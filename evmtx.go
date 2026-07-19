package outscript

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"

	"github.com/BottleFmt/gobottle"
	"github.com/KarpelesLab/rlp"
	"github.com/KarpelesLab/secp256k1"
	"github.com/KarpelesLab/typutil"
	"golang.org/x/crypto/sha3"
)

// LegacyTx
// DynamicFeeTx represents an EIP-1559 transaction
// AccessListTx is the data of EIP-2930 access list transactions; access lists
// (the [address, [storageKeys...]] tuples) are encoded/decoded for EIP-2930,
// EIP-1559 and EIP-7702 transactions.
//
// Legacy = rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
// EIP-2930 = 0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, signatureYParity, signatureR, signatureS])
// EIP-1559 = 0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list, signature_y_parity, signature_r, signature_s])
// EIP-4844 = 0x03 || [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list, max_fee_per_blob_gas, blob_versioned_hashes, y_parity, r, s]
// EIP-7702 = 0x04 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, value, data, access_list, authorization_list, signature_y_parity, signature_r, signature_s])
//            where authorization_list = [[chain_id, address, nonce, y_parity, r, s], ...] and each tuple is signed over keccak256(0x05 || rlp([chain_id, address, nonce]))
// however, EIP-2930 is so rare we can probably forget about it

// EvmTxType represents the type of EVM transaction encoding.
type EvmTxType int

const (
	EvmTxLegacy  EvmTxType = iota // Legacy (pre-EIP-2718) transaction
	EvmTxEIP2930                  // EIP-2930 access list transaction
	EvmTxEIP1559                  // EIP-1559 dynamic fee transaction
	EvmTxEIP4844                  // EIP-4844 blob transaction
	EvmTxEIP7702                  // EIP-7702 set-code (authorization list) transaction
)

// EvmTx represents an Ethereum Virtual Machine transaction. It supports legacy,
// EIP-2930, EIP-1559, EIP-4844, and EIP-7702 transaction types, and can be signed,
// serialized, parsed, and converted to/from JSON.
type EvmTx struct {
	Nonce      uint64
	GasTipCap  *big.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap  *big.Int // a.k.a. maxFeePerGas, correspond to GasFee if tx type is legacy or eip2930
	Gas        uint64   // gas of tx, can be obtained with eth_estimateGas, 21000 if Data is empty
	To         string
	Value      *big.Int
	Data       []byte
	ChainId    uint64              // in legacy tx, chainId is encoded in v before signature
	Type       EvmTxType           // type of transaction: legacy, eip2930 or eip1559
	AccessList []*EvmAccessTuple   // EIP-2930 access list (EIP-2930, EIP-1559, EIP-7702)
	AuthList   []*EvmAuthorization // EIP-7702 authorization list (type EvmTxEIP7702)
	Signed     bool
	Y, R, S    *big.Int
}

// evmTxJson is used when encoding/decoding evmTx into json
type evmTxJson struct {
	From      string `json:"from,omitempty"` // not used when reading but useful for debug
	Gas       string `json:"gas"`
	GasPrice  string `json:"gasPrice,omitempty"`
	GasTipCap string `json:"maxPriorityFeePerGas,omitempty"`
	GasFeeCap string `json:"maxFeePerGas,omitempty"`
	Hash      string `json:"hash,omitempty"`
	Input     string `json:"input"`
	Nonce     string `json:"nonce"`
	To        string `json:"to,omitempty"`
	Value     string `json:"value"`
	ChainId   string `json:"chainId"`
	V         string `json:"v"`
	R         string `json:"r"`
	S         string `json:"s"`

	AccessList        []*evmAccessTupleJson   `json:"accessList,omitempty"`
	AuthorizationList []*evmAuthorizationJson `json:"authorizationList,omitempty"`
}

// RlpFields returns the Rlp fields for the given transaction, less the signature fields
func (tx *EvmTx) RlpFields() []any {
	switch tx.Type {
	case EvmTxLegacy:
		return []any{
			tx.Nonce,
			tx.GasFeeCap,
			tx.Gas,
			tx.To,
			tx.Value,
			tx.Data,
		}
	case EvmTxEIP2930:
		return []any{
			tx.ChainId,
			tx.Nonce,
			tx.GasFeeCap,
			tx.Gas,
			tx.To,
			tx.Value,
			tx.Data,
			tx.accessListRlp(),
		}
	case EvmTxEIP1559:
		return []any{
			tx.ChainId,
			tx.Nonce,
			tx.GasTipCap,
			tx.GasFeeCap,
			tx.Gas,
			tx.To,
			tx.Value,
			tx.Data,
			tx.accessListRlp(),
		}
	case EvmTxEIP7702:
		return []any{
			tx.ChainId,
			tx.Nonce,
			tx.GasTipCap,
			tx.GasFeeCap,
			tx.Gas,
			tx.To,
			tx.Value,
			tx.Data,
			tx.accessListRlp(),
			tx.authorizationListRlp(),
		}
	default:
		return nil
	}
}

func (tx *EvmTx) typeValue() byte {
	switch tx.Type {
	case EvmTxLegacy:
		return 0
	case EvmTxEIP2930:
		return 1
	case EvmTxEIP1559:
		return 2
	case EvmTxEIP4844:
		return 3
	case EvmTxEIP7702:
		return 4
	default:
		return 0xff // :(
	}
}

// MarshalBinary transforms the transaction into its binary representation
func (tx *EvmTx) MarshalBinary() ([]byte, error) {
	if !tx.Signed {
		return tx.SignBytes()
	}

	switch tx.Type {
	case EvmTxLegacy:
		f := tx.RlpFields()
		f = append(f, tx.Y, tx.R, tx.S)
		return rlp.EncodeValue(f)
	default:
		f := tx.RlpFields()
		f = append(f, tx.Y, tx.R, tx.S)
		buf, err := rlp.EncodeValue(f)
		if err != nil {
			return nil, err
		}
		return append([]byte{tx.typeValue()}, buf...), nil
	}
}

// SignBytes returns the bytes used to sign the transaction
func (tx *EvmTx) SignBytes() ([]byte, error) {
	switch tx.Type {
	case EvmTxLegacy:
		f := tx.RlpFields()
		if tx.ChainId != 0 {
			// if ChainId == 0, we assume no EIP-155
			f = append(f, tx.ChainId, 0, 0)
		}
		return rlp.EncodeValue(f)
	default:
		buf, err := rlp.EncodeValue(tx.RlpFields())
		if err != nil {
			return nil, err
		}
		return append([]byte{tx.typeValue()}, buf...), nil
	}
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler
func (tx *EvmTx) UnmarshalBinary(buf []byte) error {
	return tx.ParseTransaction(buf)
}

// decodeUint64Checked safely decodes an RLP uint64 field, returning an error if
// the field is longer than 8 bytes (rlp.DecodeUint64 would otherwise panic).
func decodeUint64Checked(buf []byte) (uint64, error) {
	if len(buf) > 8 {
		return 0, fmt.Errorf("invalid uint64 field: length %d exceeds 8 bytes", len(buf))
	}
	return rlp.DecodeUint64(buf), nil
}

// asBytes extracts a []byte from an RLP-decoded value, returning an error on
// type mismatch instead of panicking.
func asBytes(v any) ([]byte, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("expected rlp string (bytes), got %T", v)
	}
	return b, nil
}

// asList extracts a []any (RLP list) from an RLP-decoded value, returning an
// error on type mismatch instead of panicking.
func asList(v any) ([]any, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected rlp list, got %T", v)
	}
	return l, nil
}

// ParseTransaction will parse an incoming transaction and return an error in case of failure.
// In case of error, the state of tx is undefined.
func (tx *EvmTx) ParseTransaction(buf []byte) error {
	if len(buf) < 1 {
		return io.ErrUnexpectedEOF
	}
	if buf[0] >= 0x80 {
		// legacy transaction as per https://eips.ethereum.org/EIPS/eip-2718
		dec, err := rlp.Decode(buf)
		if err != nil {
			return err
		}
		if len(dec) != 1 {
			return errors.New("invalid rlp data for legacy transaction")
		}
		txData, err := typutil.As[[][]byte](dec[0])
		if err != nil {
			return fmt.Errorf("failed to decode rlp data: %w", err)
		}
		ln := len(txData)
		if ln != 6 && ln != 9 {
			return fmt.Errorf("lgacy transaction must have 6 or 9 fields, got %d", ln)
		}
		tx.Type = EvmTxLegacy
		if tx.Nonce, err = decodeUint64Checked(txData[0]); err != nil {
			return err
		}
		tx.GasFeeCap = new(big.Int).SetBytes(txData[1])
		if tx.Gas, err = decodeUint64Checked(txData[2]); err != nil {
			return err
		}
		tx.To = "0x" + hex.EncodeToString(txData[3])
		tx.Value = new(big.Int).SetBytes(txData[4])
		tx.Data = txData[5]
		if ln == 9 {
			// signed
			tx.Signed = true
			tx.Y = new(big.Int).SetBytes(txData[6]) // 27|28, or ChainId * 2 + 35 + (v & 1) if EIP-155
			tx.R = new(big.Int).SetBytes(txData[7])
			tx.S = new(big.Int).SetBytes(txData[8])
		} else {
			tx.Signed = false
		}
		return nil
	}
	switch buf[0] {
	case 1: // EvmTxEIP2930
		dec, err := rlp.Decode(buf[1:])
		if err != nil {
			return err
		}
		if len(dec) != 1 {
			return errors.New("invalid rlp data for legacy transaction")
		}
		txData, err := asList(dec[0])
		if err != nil {
			return err
		}
		ln := len(txData)
		if ln != 8 && ln != 11 {
			return fmt.Errorf("EIP-2930 transaction must have 8 or 11 fields, got %d", ln)
		}
		fields := make([][]byte, 7)
		for i := 0; i < 7; i++ {
			if fields[i], err = asBytes(txData[i]); err != nil {
				return err
			}
		}
		tx.Type = EvmTxEIP2930
		if tx.ChainId, err = decodeUint64Checked(fields[0]); err != nil {
			return err
		}
		if tx.Nonce, err = decodeUint64Checked(fields[1]); err != nil {
			return err
		}
		tx.GasFeeCap = new(big.Int).SetBytes(fields[2])
		if tx.Gas, err = decodeUint64Checked(fields[3]); err != nil {
			return err
		}
		tx.To = "0x" + hex.EncodeToString(fields[4])
		tx.Value = new(big.Int).SetBytes(fields[5])
		tx.Data = fields[6]
		if tx.AccessList, err = parseAccessList(txData[7]); err != nil {
			return err
		}
		if ln == 11 {
			tx.Signed = true
			y, err := asBytes(txData[8])
			if err != nil {
				return err
			}
			r, err := asBytes(txData[9])
			if err != nil {
				return err
			}
			s, err := asBytes(txData[10])
			if err != nil {
				return err
			}
			tx.Y = new(big.Int).SetBytes(y)
			tx.R = new(big.Int).SetBytes(r)
			tx.S = new(big.Int).SetBytes(s)
		} else {
			tx.Signed = false
		}
		return nil
	case 2: // EvmTxEIP1559
		dec, err := rlp.Decode(buf[1:])
		if err != nil {
			return err
		}
		if len(dec) != 1 {
			return errors.New("invalid rlp data for legacy transaction")
		}
		txData, err := asList(dec[0])
		if err != nil {
			return err
		}
		ln := len(txData)
		if ln != 9 && ln != 12 {
			return fmt.Errorf("EIP-1559 transaction must have 9 or 12 fields, got %d", ln)
		}
		fields := make([][]byte, 8)
		for i := 0; i < 8; i++ {
			if fields[i], err = asBytes(txData[i]); err != nil {
				return err
			}
		}
		tx.Type = EvmTxEIP1559
		if tx.ChainId, err = decodeUint64Checked(fields[0]); err != nil {
			return err
		}
		if tx.Nonce, err = decodeUint64Checked(fields[1]); err != nil {
			return err
		}
		tx.GasTipCap = new(big.Int).SetBytes(fields[2])
		tx.GasFeeCap = new(big.Int).SetBytes(fields[3])
		if tx.Gas, err = decodeUint64Checked(fields[4]); err != nil {
			return err
		}
		tx.To = "0x" + hex.EncodeToString(fields[5])
		tx.Value = new(big.Int).SetBytes(fields[6])
		tx.Data = fields[7]
		if tx.AccessList, err = parseAccessList(txData[8]); err != nil {
			return err
		}
		if ln == 12 {
			tx.Signed = true
			y, err := asBytes(txData[9])
			if err != nil {
				return err
			}
			r, err := asBytes(txData[10])
			if err != nil {
				return err
			}
			s, err := asBytes(txData[11])
			if err != nil {
				return err
			}
			tx.Y = new(big.Int).SetBytes(y)
			tx.R = new(big.Int).SetBytes(r)
			tx.S = new(big.Int).SetBytes(s)
		} else {
			tx.Signed = false
		}
		return nil
	case 4: // EvmTxEIP7702
		dec, err := rlp.Decode(buf[1:])
		if err != nil {
			return err
		}
		if len(dec) != 1 {
			return errors.New("invalid rlp data for EIP-7702 transaction")
		}
		txData, err := asList(dec[0])
		if err != nil {
			return err
		}
		ln := len(txData)
		if ln != 10 && ln != 13 {
			return fmt.Errorf("EIP-7702 transaction must have 10 or 13 fields, got %d", ln)
		}
		fields := make([][]byte, 8)
		for i := 0; i < 8; i++ {
			if fields[i], err = asBytes(txData[i]); err != nil {
				return err
			}
		}
		tx.Type = EvmTxEIP7702
		if tx.ChainId, err = decodeUint64Checked(fields[0]); err != nil {
			return err
		}
		if tx.Nonce, err = decodeUint64Checked(fields[1]); err != nil {
			return err
		}
		tx.GasTipCap = new(big.Int).SetBytes(fields[2])
		tx.GasFeeCap = new(big.Int).SetBytes(fields[3])
		if tx.Gas, err = decodeUint64Checked(fields[4]); err != nil {
			return err
		}
		tx.To = "0x" + hex.EncodeToString(fields[5])
		tx.Value = new(big.Int).SetBytes(fields[6])
		tx.Data = fields[7]
		if tx.AccessList, err = parseAccessList(txData[8]); err != nil {
			return err
		}
		if tx.AuthList, err = parseAuthorizationList(txData[9]); err != nil {
			return err
		}
		if ln == 13 {
			tx.Signed = true
			y, err := asBytes(txData[10])
			if err != nil {
				return err
			}
			r, err := asBytes(txData[11])
			if err != nil {
				return err
			}
			s, err := asBytes(txData[12])
			if err != nil {
				return err
			}
			tx.Y = new(big.Int).SetBytes(y)
			tx.R = new(big.Int).SetBytes(r)
			tx.S = new(big.Int).SetBytes(s)
		} else {
			tx.Signed = false
		}
		return nil
	}

	return errors.New("not supported")
}

// Signature returns the parsed secp256k1 signature from the signed transaction.
func (tx *EvmTx) Signature() (*secp256k1.Signature, error) {
	if !tx.Signed {
		return nil, errors.New("cannot obtain signature of an unsigned transaction")
	}
	r := new(secp256k1.ModNScalar)
	if overflow := r.SetByteSlice(tx.R.Bytes()); overflow {
		return nil, errors.New("cannot read signature: invalid value for R >= group order")
	}
	s := new(secp256k1.ModNScalar)
	if overflow := s.SetByteSlice(tx.S.Bytes()); overflow {
		return nil, errors.New("cannot read signature: invalid value for S >= group order")
	}

	v := tx.Y.Uint64()
	if tx.Type == EvmTxLegacy {
		if v >= 35 {
			// EIP-155: v = ChainId * 2 + 35 + (v & 1)
			bit := 1 - (v & 1)
			v -= 35 + bit
			tx.ChainId = v / 2
			v = bit
		} else {
			// pre-EIP-155 legacy tx: v is the recovery id directly.
			// Standard values are 27/28 (and some implementations may use
			// the raw 0/1 recovery id). Normalize to a [0,3] recovery code
			// so we never feed an out-of-range value to secp256k1 (which
			// would panic).
			tx.ChainId = 0
			switch v {
			case 27, 28:
				v -= 27
			case 0, 1:
				// already a recovery id
			default:
				return nil, fmt.Errorf("invalid pre-EIP-155 signature v value: %d", v)
			}
		}
	}
	if v > 3 {
		return nil, fmt.Errorf("invalid signature recovery id: %d", v)
	}
	return secp256k1.NewSignatureWithRecoveryCode(r, s, byte(v)), nil
}

// SenderPubkey recovers the sender's public key from the transaction signature.
func (tx *EvmTx) SenderPubkey() (*secp256k1.PublicKey, error) {
	if !tx.Signed {
		return nil, errors.New("cannot obtain signature of an unsigned transaction")
	}
	sig, err := tx.Signature()
	if err != nil {
		return nil, err
	}
	// RecoverCompact expects a signature inform V,R,S
	buf, err := tx.SignBytes()
	if err != nil {
		return nil, err
	}
	pub, err := sig.RecoverPublicKey(gobottle.Hash(buf, sha3.NewLegacyKeccak256))
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// SenderAddress recovers and returns the EIP-55 checksummed sender address from the transaction signature.
func (tx *EvmTx) SenderAddress() (string, error) {
	pubkey, err := tx.SenderPubkey()
	if err != nil {
		return "", err
	}
	addr, err := New(pubkey).Generate("eth")
	if err != nil {
		return "", err
	}
	return eip55(addr), nil
}

// Sign signs the transaction using the given key with default signer options.
func (tx *EvmTx) Sign(key crypto.Signer) error {
	return tx.SignWithOptions(key, crypto.Hash(0))
}

// SignWithOptions signs the transaction using the given key and signer options.
func (tx *EvmTx) SignWithOptions(key crypto.Signer, opts crypto.SignerOpts) error {
	buf, err := tx.SignBytes()
	if err != nil {
		return err
	}
	h := gobottle.Hash(buf, sha3.NewLegacyKeccak256)
	sig, err := key.Sign(rand.Reader, h, opts)
	if err != nil {
		return err
	}
	// expect sig to be in DER format
	sigO, err := secp256k1.ParseDERSignature(sig)
	if err != nil {
		return err
	}
	// find recovery bit
	pub, ok := key.Public().(*secp256k1.PublicKey)
	if !ok {
		return fmt.Errorf("signing key public part must be a secp256k1 public key, got %T", key.Public())
	}
	if !sigO.BruteforceRecoveryCode(h, pub) {
		return errors.New("failed to determine signature recovery code")
	}
	// apply signature
	tx.Signed = true
	var v byte
	tx.R, tx.S, v = sigO.Export()
	if tx.Type == EvmTxLegacy {
		if tx.ChainId == 0 {
			// super-legacy
			tx.Y = big.NewInt(27 + int64(v))
		} else {
			// EIP-155: v = ChainId * 2 + 35 + (v & 1)
			tx.Y = big.NewInt(int64(tx.ChainId)*2 + 35 + int64(v))
		}
	} else {
		tx.Y = big.NewInt(int64(v))
	}
	return nil
}

// Hash returns the Keccak-256 hash of the signed transaction's binary encoding.
func (tx *EvmTx) Hash() ([]byte, error) {
	data, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return gobottle.Hash(data, sha3.NewLegacyKeccak256), nil
}

// MarshalJSON encodes the transaction as a JSON object with hex-encoded numeric fields.
func (tx *EvmTx) MarshalJSON() ([]byte, error) {
	obj := &evmTxJson{
		Gas:     "0x" + strconv.FormatUint(tx.Gas, 16),
		Input:   "0x" + hex.EncodeToString(tx.Data),
		Nonce:   "0x" + strconv.FormatUint(tx.Nonce, 16),
		To:      tx.To,
		Value:   "0x" + tx.Value.Text(16),
		ChainId: "0x" + strconv.FormatUint(tx.ChainId, 16),
	}

	if tx.Type == EvmTxLegacy {
		obj.GasPrice = "0x" + tx.GasFeeCap.Text(16)
	} else {
		obj.GasFeeCap = "0x" + tx.GasFeeCap.Text(16)
		obj.GasTipCap = "0x" + tx.GasTipCap.Text(16)
	}

	if len(tx.AccessList) > 0 {
		obj.AccessList = make([]*evmAccessTupleJson, len(tx.AccessList))
		for i, t := range tx.AccessList {
			obj.AccessList[i] = t.toJson()
		}
	}

	if len(tx.AuthList) > 0 {
		obj.AuthorizationList = make([]*evmAuthorizationJson, len(tx.AuthList))
		for i, a := range tx.AuthList {
			obj.AuthorizationList[i] = a.toJson()
		}
	}

	if tx.Signed {
		obj.From, _ = tx.SenderAddress()
		obj.V = "0x" + tx.Y.Text(16)
		obj.R = "0x" + tx.R.Text(16)
		obj.S = "0x" + tx.S.Text(16)
		//obj.Hash = gobottle.Hash(tx.????, sha3.NewLegacyKeccak256)
	}
	return json.Marshal(obj)
}

// UnmarshalJSON decodes a JSON representation into an EvmTx.
func (tx *EvmTx) UnmarshalJSON(b []byte) error {
	var obj *evmTxJson
	var ok bool
	err := json.Unmarshal(b, &obj)
	if err != nil {
		return err
	}
	if obj.Gas != "" {
		tx.Gas, err = strconv.ParseUint(obj.Gas, 0, 64)
		if err != nil {
			return err
		}
	}
	if obj.GasFeeCap != "" && obj.GasTipCap != "" {
		// EIP-1559
		tx.GasFeeCap, ok = new(big.Int).SetString(obj.GasFeeCap, 0)
		if !ok {
			return errors.New("invalid value in gasPrice")
		}
		tx.GasTipCap, ok = new(big.Int).SetString(obj.GasTipCap, 0)
		if !ok {
			return errors.New("invalid value in gasPrice")
		}
		tx.Type = EvmTxEIP1559
	} else if obj.GasPrice != "" {
		tx.GasFeeCap, ok = new(big.Int).SetString(obj.GasPrice, 0)
		if !ok {
			return errors.New("invalid value in gasPrice")
		}
	}
	if obj.Input != "" {
		tx.Data, err = parseEthBufferHex(obj.Input)
		if err != nil {
			return err
		}
	}
	if obj.Nonce != "" {
		tx.Nonce, err = strconv.ParseUint(obj.Nonce, 0, 64)
		if err != nil {
			return err
		}
	}
	if obj.To != "" {
		tx.To = obj.To
	}
	if obj.Value != "" {
		tx.Value, ok = new(big.Int).SetString(obj.Value, 0)
		if !ok {
			return errors.New("invalid value in value")
		}
	}
	if obj.ChainId != "" {
		tx.ChainId, err = strconv.ParseUint(obj.ChainId, 0, 64)
		if err != nil {
			return err
		}
	}
	if obj.V != "" {
		tx.Y, ok = new(big.Int).SetString(obj.V, 0)
		if !ok {
			return errors.New("invalid value in v")
		}
	}
	if obj.R != "" {
		tx.R, ok = new(big.Int).SetString(obj.R, 0)
		if !ok {
			return errors.New("invalid value in r")
		}
	}
	if obj.S != "" {
		tx.S, ok = new(big.Int).SetString(obj.S, 0)
		if !ok {
			return errors.New("invalid value in s")
		}
	}
	if len(obj.AccessList) > 0 {
		tx.AccessList = make([]*EvmAccessTuple, len(obj.AccessList))
		for i, ja := range obj.AccessList {
			tx.AccessList[i] = ja.toAccessTuple()
		}
	}
	if len(obj.AuthorizationList) > 0 {
		tx.AuthList = make([]*EvmAuthorization, len(obj.AuthorizationList))
		for i, ja := range obj.AuthorizationList {
			if tx.AuthList[i], err = ja.toAuthorization(); err != nil {
				return err
			}
		}
		tx.Type = EvmTxEIP7702
	}
	if tx.Y != nil && tx.R != nil && tx.S != nil {
		tx.Signed = true
	}
	return nil
}

func parseEthBufferHex(buf string) ([]byte, error) {
	if len(buf) < 2 {
		return nil, errors.New("eth buffer must start with 0x")
	}
	return hex.DecodeString(buf[2:])
}

// Call sets the transaction's Data field to the ABI-encoded method call for the given
// method signature and parameters.
func (tx *EvmTx) Call(method string, params ...any) error {
	res, err := EvmCall(method, params...)
	if err != nil {
		return err
	}
	tx.Data = res
	return nil
}
