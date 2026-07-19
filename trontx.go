package outscript

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/KarpelesLab/secp256k1"
)

// TronContractType identifies a Tron smart-contract/system-contract type. The
// values match protocol.Transaction.Contract.ContractType in the Tron protobuf
// definitions.
type TronContractType int32

const (
	TronTransferContract      TronContractType = 1  // native TRX transfer
	TronTransferAssetContract TronContractType = 2  // TRC10 asset transfer
	TronTriggerSmartContract  TronContractType = 31 // smart-contract call (e.g. TRC20)
)

// typeURL returns the protobuf Any type_url used to wrap a contract of this type,
// or "" if the type is not supported for encoding.
func (t TronContractType) typeURL() string {
	switch t {
	case TronTransferContract:
		return "type.googleapis.com/protocol.TransferContract"
	case TronTransferAssetContract:
		return "type.googleapis.com/protocol.TransferAssetContract"
	case TronTriggerSmartContract:
		return "type.googleapis.com/protocol.TriggerSmartContract"
	default:
		return ""
	}
}

// TronContract is a single contract carried by a Tron transaction. Parameter is
// the serialized contract-specific protobuf message (the Any.value), typically
// built with one of the NewTron*Contract constructors.
type TronContract struct {
	Type      TronContractType
	Parameter []byte
}

// TronTx represents a Tron transaction. The reference-block fields, expiration
// and timestamp are usually filled from a recent block obtained from a node; the
// contracts describe the operations to perform.
type TronTx struct {
	RefBlockBytes []byte // 2 bytes: bytes [6:8] of the reference block height
	RefBlockHash  []byte // 8 bytes: bytes [8:16] of the reference block id (hash)
	Expiration    int64  // expiration time in milliseconds since epoch
	Timestamp     int64  // creation time in milliseconds since epoch
	FeeLimit      int64  // maximum energy fee in sun (smart-contract calls)
	Contracts     []*TronContract
	Signatures    [][]byte // 65-byte recoverable signatures (r||s||v)
}

// --- minimal protobuf wire-format writers ---

// pbVarint encodes v as a protobuf base-128 varint.
func pbVarint(v uint64) []byte {
	var buf []byte
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

// pbTag encodes a protobuf field tag (field number + wire type).
func pbTag(field, wire int) []byte {
	return pbVarint(uint64(field)<<3 | uint64(wire))
}

// pbVarintField encodes a varint (wire type 0) field.
func pbVarintField(field int, v uint64) []byte {
	return append(pbTag(field, 0), pbVarint(v)...)
}

// pbBytesField encodes a length-delimited (wire type 2) field: bytes, string or
// embedded message.
func pbBytesField(field int, b []byte) []byte {
	out := pbTag(field, 2)
	out = append(out, pbVarint(uint64(len(b)))...)
	return append(out, b...)
}

// checkTronAddress verifies raw is a 21-byte 0x41-prefixed Tron address.
func checkTronAddress(raw []byte, what string) error {
	if len(raw) != 21 {
		return fmt.Errorf("tron %s address must be 21 bytes, got %d", what, len(raw))
	}
	if raw[0] != tronAddressPrefix {
		return fmt.Errorf("tron %s address must start with 0x41, got 0x%02x", what, raw[0])
	}
	return nil
}

// NewTronTransferContract builds a native TRX TransferContract. owner and to are
// 21-byte raw Tron addresses (0x41 prefix + 20-byte hash); amount is in sun.
func NewTronTransferContract(owner, to []byte, amount int64) (*TronContract, error) {
	if err := checkTronAddress(owner, "owner"); err != nil {
		return nil, err
	}
	if err := checkTronAddress(to, "destination"); err != nil {
		return nil, err
	}
	if amount < 0 {
		return nil, fmt.Errorf("tron transfer amount must not be negative: %d", amount)
	}
	// proto3 omits zero-valued scalar fields for canonical (txID-matching) output
	value := slices.Concat(pbBytesField(1, owner), pbBytesField(2, to))
	if amount != 0 {
		value = append(value, pbVarintField(3, uint64(amount))...)
	}
	return &TronContract{Type: TronTransferContract, Parameter: value}, nil
}

// NewTronTriggerSmartContract builds a TriggerSmartContract call. owner and
// contract are 21-byte raw Tron addresses; callValue is the amount of TRX (in
// sun) to send along with the call; data is the ABI-encoded call payload.
func NewTronTriggerSmartContract(owner, contract []byte, callValue int64, data []byte) (*TronContract, error) {
	if err := checkTronAddress(owner, "owner"); err != nil {
		return nil, err
	}
	if err := checkTronAddress(contract, "contract"); err != nil {
		return nil, err
	}
	if callValue < 0 {
		return nil, fmt.Errorf("tron call value must not be negative: %d", callValue)
	}
	value := slices.Concat(pbBytesField(1, owner), pbBytesField(2, contract))
	if callValue != 0 {
		value = append(value, pbVarintField(3, uint64(callValue))...)
	}
	if len(data) > 0 {
		value = append(value, pbBytesField(4, data)...)
	}
	return &TronContract{Type: TronTriggerSmartContract, Parameter: value}, nil
}

// AddTransfer appends a native TRX transfer to the transaction, taking the from
// and to addresses in "T..." Base58Check form.
func (tx *TronTx) AddTransfer(from, to string, amount int64) error {
	f, err := DecodeTronAddress(from)
	if err != nil {
		return err
	}
	t, err := DecodeTronAddress(to)
	if err != nil {
		return err
	}
	c, err := NewTronTransferContract(f, t, amount)
	if err != nil {
		return err
	}
	tx.Contracts = append(tx.Contracts, c)
	return nil
}

// AddTriggerSmartContract appends a smart-contract call to the transaction,
// taking the from and contract addresses in "T..." Base58Check form.
func (tx *TronTx) AddTriggerSmartContract(from, contract string, callValue int64, data []byte) error {
	f, err := DecodeTronAddress(from)
	if err != nil {
		return err
	}
	c, err := DecodeTronAddress(contract)
	if err != nil {
		return err
	}
	sc, err := NewTronTriggerSmartContract(f, c, callValue, data)
	if err != nil {
		return err
	}
	tx.Contracts = append(tx.Contracts, sc)
	return nil
}

// AddTRC20Transfer appends a TRC20 token transfer (e.g. USDT) to the
// transaction. It builds the transfer(address,uint256) call for the token
// contract and sends it through a TriggerSmartContract. from, contract and to
// are "T..." Base58Check addresses; amount is the token amount in the token's
// base units. Set FeeLimit on the transaction to cover the energy cost.
func (tx *TronTx) AddTRC20Transfer(from, contract, to string, amount *big.Int) error {
	if amount == nil {
		return errors.New("tron TRC20 transfer amount must not be nil")
	}
	if amount.Sign() < 0 {
		return fmt.Errorf("tron TRC20 transfer amount must not be negative: %s", amount)
	}
	toRaw, err := DecodeTronAddress(to)
	if err != nil {
		return err
	}
	// TRC20 calls take the 20-byte address form (Tron address without the 0x41
	// prefix); toRaw[1:] is exactly that.
	data, err := EvmCall("transfer(address,uint256)", toRaw[1:], amount)
	if err != nil {
		return err
	}
	return tx.AddTriggerSmartContract(from, contract, 0, data)
}

// marshal serializes the contract as a Transaction.Contract protobuf message.
func (c *TronContract) marshal() ([]byte, error) {
	url := c.Type.typeURL()
	if url == "" {
		return nil, fmt.Errorf("unsupported tron contract type %d", c.Type)
	}
	// google.protobuf.Any { type_url = 1, value = 2 }
	any := slices.Concat(pbBytesField(1, []byte(url)), pbBytesField(2, c.Parameter))
	// Contract { type = 1, parameter = 2 }
	out := pbVarintField(1, uint64(c.Type))
	out = append(out, pbBytesField(2, any)...)
	return out, nil
}

// RawData serializes the transaction's raw_data protobuf message (the bytes over
// which the transaction id is computed and which are signed).
func (tx *TronTx) RawData() ([]byte, error) {
	if len(tx.Contracts) == 0 {
		return nil, errors.New("tron transaction has no contracts")
	}
	// Transaction.raw fields, emitted in ascending field-number order so the
	// bytes match what java-tron produces (and therefore the network txID).
	var out []byte
	if len(tx.RefBlockBytes) > 0 {
		out = append(out, pbBytesField(1, tx.RefBlockBytes)...)
	}
	if len(tx.RefBlockHash) > 0 {
		out = append(out, pbBytesField(4, tx.RefBlockHash)...)
	}
	if tx.Expiration != 0 {
		out = append(out, pbVarintField(8, uint64(tx.Expiration))...)
	}
	for _, c := range tx.Contracts {
		cb, err := c.marshal()
		if err != nil {
			return nil, err
		}
		out = append(out, pbBytesField(11, cb)...)
	}
	if tx.Timestamp != 0 {
		out = append(out, pbVarintField(14, uint64(tx.Timestamp))...)
	}
	if tx.FeeLimit != 0 {
		out = append(out, pbVarintField(18, uint64(tx.FeeLimit))...)
	}
	return out, nil
}

// TxID returns the transaction id: the SHA-256 hash of the serialized raw_data.
func (tx *TronTx) TxID() ([]byte, error) {
	raw, err := tx.RawData()
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(raw)
	return h[:], nil
}

// Sign signs the transaction with the given key using default signer options,
// appending a signature to the transaction.
func (tx *TronTx) Sign(key crypto.Signer) error {
	return tx.SignWithOptions(key, crypto.Hash(0))
}

// SignWithOptions signs the transaction with the given key and signer options,
// appending a 65-byte recoverable signature (r||s||v) to the transaction.
func (tx *TronTx) SignWithOptions(key crypto.Signer, opts crypto.SignerOpts) error {
	txid, err := tx.TxID()
	if err != nil {
		return err
	}
	sig, err := key.Sign(rand.Reader, txid, opts)
	if err != nil {
		return err
	}
	// expect sig to be in DER format
	sigO, err := secp256k1.ParseDERSignature(sig)
	if err != nil {
		return err
	}
	pub, ok := key.Public().(*secp256k1.PublicKey)
	if !ok {
		return fmt.Errorf("signing key public part must be a secp256k1 public key, got %T", key.Public())
	}
	if !sigO.BruteforceRecoveryCode(txid, pub) {
		return errors.New("failed to determine signature recovery code")
	}
	r, s, v := sigO.Export()
	out := make([]byte, 65)
	r.FillBytes(out[0:32])
	s.FillBytes(out[32:64])
	out[64] = v
	tx.Signatures = append(tx.Signatures, out)
	return nil
}

// MarshalBinary serializes the full Transaction protobuf message (raw_data plus
// signatures), suitable for broadcast.
func (tx *TronTx) MarshalBinary() ([]byte, error) {
	raw, err := tx.RawData()
	if err != nil {
		return nil, err
	}
	// Transaction { raw_data = 1, signature = 2 (repeated) }
	out := pbBytesField(1, raw)
	for _, sig := range tx.Signatures {
		out = append(out, pbBytesField(2, sig)...)
	}
	return out, nil
}

// recoverTronPubkey recovers the secp256k1 public key that produced a 65-byte
// Tron signature (r||s||v) over the given transaction id.
func recoverTronPubkey(txid, sig []byte) (*secp256k1.PublicKey, error) {
	if len(sig) != 65 {
		return nil, fmt.Errorf("tron signature must be 65 bytes, got %d", len(sig))
	}
	r := new(secp256k1.ModNScalar)
	if overflow := r.SetByteSlice(sig[0:32]); overflow {
		return nil, errors.New("invalid signature: R >= group order")
	}
	s := new(secp256k1.ModNScalar)
	if overflow := s.SetByteSlice(sig[32:64]); overflow {
		return nil, errors.New("invalid signature: S >= group order")
	}
	v := sig[64]
	if v > 3 {
		return nil, fmt.Errorf("invalid signature recovery id: %d", v)
	}
	return secp256k1.NewSignatureWithRecoveryCode(r, s, v).RecoverPublicKey(txid)
}

// SignerAddresses recovers the "T..." Tron address of each signature attached to
// the transaction, in order.
func (tx *TronTx) SignerAddresses() ([]string, error) {
	txid, err := tx.TxID()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(tx.Signatures))
	for _, sig := range tx.Signatures {
		pub, err := recoverTronPubkey(txid, sig)
		if err != nil {
			return nil, err
		}
		addr, err := New(pub).Address("tron")
		if err != nil {
			return nil, err
		}
		out = append(out, addr)
	}
	return out, nil
}
