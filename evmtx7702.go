package outscript

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/BottleFmt/gobottle"
	"github.com/KarpelesLab/rlp"
	"github.com/KarpelesLab/secp256k1"
	"golang.org/x/crypto/sha3"
)

// eip7702MagicPrefix is the MAGIC byte prepended before the RLP-encoded
// authorization tuple when computing the digest that an authorization is signed
// over, as defined by EIP-7702.
const eip7702MagicPrefix = 0x05

// EvmAuthorization is an EIP-7702 authorization tuple. It authorizes delegating
// the signing account's (the "authority") code to Address. Once signed, it is
// carried in the AuthList of an EvmTxEIP7702 transaction.
//
// The authority signs keccak256(0x05 || rlp([chainId, address, nonce])). A
// ChainId of 0 makes the authorization valid on any chain.
type EvmAuthorization struct {
	ChainId uint64
	Address string // "0x"-prefixed 20-byte delegation target
	Nonce   uint64
	Signed  bool
	Y, R, S *big.Int
}

// evmAuthorizationJson is used when encoding/decoding an EvmAuthorization to/from
// JSON, matching the eth JSON-RPC authorization list representation.
type evmAuthorizationJson struct {
	ChainId string `json:"chainId"`
	Address string `json:"address"`
	Nonce   string `json:"nonce"`
	YParity string `json:"yParity,omitempty"`
	R       string `json:"r,omitempty"`
	S       string `json:"s,omitempty"`
}

// rlpTuple returns the six-element RLP representation of the authorization,
// including its signature, as embedded in a transaction's authorization list.
func (a *EvmAuthorization) rlpTuple() []any {
	return []any{a.ChainId, a.Address, a.Nonce, a.Y, a.R, a.S}
}

// SignBytes returns the bytes the authority signs: the MAGIC prefix followed by
// the RLP encoding of [chainId, address, nonce].
func (a *EvmAuthorization) SignBytes() ([]byte, error) {
	buf, err := rlp.EncodeValue([]any{a.ChainId, a.Address, a.Nonce})
	if err != nil {
		return nil, err
	}
	return append([]byte{eip7702MagicPrefix}, buf...), nil
}

// Sign signs the authorization using the given key with default signer options.
func (a *EvmAuthorization) Sign(key crypto.Signer) error {
	return a.SignWithOptions(key, crypto.Hash(0))
}

// SignWithOptions signs the authorization using the given key and signer options.
func (a *EvmAuthorization) SignWithOptions(key crypto.Signer, opts crypto.SignerOpts) error {
	buf, err := a.SignBytes()
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
	pub, ok := key.Public().(*secp256k1.PublicKey)
	if !ok {
		return fmt.Errorf("signing key public part must be a secp256k1 public key, got %T", key.Public())
	}
	if !sigO.BruteforceRecoveryCode(h, pub) {
		return errors.New("failed to determine signature recovery code")
	}
	var v byte
	a.R, a.S, v = sigO.Export()
	a.Y = big.NewInt(int64(v))
	a.Signed = true
	return nil
}

// Signature returns the parsed secp256k1 signature from the signed authorization.
func (a *EvmAuthorization) Signature() (*secp256k1.Signature, error) {
	if !a.Signed {
		return nil, errors.New("cannot obtain signature of an unsigned authorization")
	}
	r := new(secp256k1.ModNScalar)
	if overflow := r.SetByteSlice(a.R.Bytes()); overflow {
		return nil, errors.New("cannot read signature: invalid value for R >= group order")
	}
	s := new(secp256k1.ModNScalar)
	if overflow := s.SetByteSlice(a.S.Bytes()); overflow {
		return nil, errors.New("cannot read signature: invalid value for S >= group order")
	}
	// EIP-7702 authorizations use a plain y_parity recovery id (no EIP-155).
	v := a.Y.Uint64()
	if v > 3 {
		return nil, fmt.Errorf("invalid authorization signature recovery id: %d", v)
	}
	return secp256k1.NewSignatureWithRecoveryCode(r, s, byte(v)), nil
}

// AuthorityPubkey recovers the authority's public key from the authorization
// signature.
func (a *EvmAuthorization) AuthorityPubkey() (*secp256k1.PublicKey, error) {
	sig, err := a.Signature()
	if err != nil {
		return nil, err
	}
	buf, err := a.SignBytes()
	if err != nil {
		return nil, err
	}
	return sig.RecoverPublicKey(gobottle.Hash(buf, sha3.NewLegacyKeccak256))
}

// Authority recovers and returns the EIP-55 checksummed address that signed the
// authorization.
func (a *EvmAuthorization) Authority() (string, error) {
	pub, err := a.AuthorityPubkey()
	if err != nil {
		return "", err
	}
	addr, err := New(pub).Generate("eth")
	if err != nil {
		return "", err
	}
	return eip55(addr), nil
}

// toJson converts the authorization into its JSON representation.
func (a *EvmAuthorization) toJson() *evmAuthorizationJson {
	j := &evmAuthorizationJson{
		ChainId: "0x" + strconv.FormatUint(a.ChainId, 16),
		Address: a.Address,
		Nonce:   "0x" + strconv.FormatUint(a.Nonce, 16),
	}
	if a.Signed {
		j.YParity = "0x" + a.Y.Text(16)
		j.R = "0x" + a.R.Text(16)
		j.S = "0x" + a.S.Text(16)
	}
	return j
}

// toAuthorization converts the JSON representation into an EvmAuthorization.
func (j *evmAuthorizationJson) toAuthorization() (*EvmAuthorization, error) {
	a := &EvmAuthorization{Address: j.Address}
	var err error
	if j.ChainId != "" {
		if a.ChainId, err = strconv.ParseUint(j.ChainId, 0, 64); err != nil {
			return nil, err
		}
	}
	if j.Nonce != "" {
		if a.Nonce, err = strconv.ParseUint(j.Nonce, 0, 64); err != nil {
			return nil, err
		}
	}
	if j.YParity != "" && j.R != "" && j.S != "" {
		var ok bool
		if a.Y, ok = new(big.Int).SetString(j.YParity, 0); !ok {
			return nil, errors.New("invalid yParity in authorization")
		}
		if a.R, ok = new(big.Int).SetString(j.R, 0); !ok {
			return nil, errors.New("invalid r in authorization")
		}
		if a.S, ok = new(big.Int).SetString(j.S, 0); !ok {
			return nil, errors.New("invalid s in authorization")
		}
		a.Signed = true
	}
	return a, nil
}

// authorizationListRlp returns the transaction's authorization list as an RLP
// list of tuples.
func (tx *EvmTx) authorizationListRlp() []any {
	out := make([]any, len(tx.AuthList))
	for i, a := range tx.AuthList {
		out[i] = a.rlpTuple()
	}
	return out
}

// parseAuthorizationList decodes the RLP authorization_list of an EIP-7702
// transaction into a slice of EvmAuthorization.
func parseAuthorizationList(v any) ([]*EvmAuthorization, error) {
	items, err := asList(v)
	if err != nil {
		return nil, err
	}
	out := make([]*EvmAuthorization, 0, len(items))
	for _, item := range items {
		tuple, err := asList(item)
		if err != nil {
			return nil, err
		}
		if len(tuple) != 6 {
			return nil, fmt.Errorf("EIP-7702 authorization must have 6 fields, got %d", len(tuple))
		}
		fields := make([][]byte, 6)
		for i := 0; i < 6; i++ {
			if fields[i], err = asBytes(tuple[i]); err != nil {
				return nil, err
			}
		}
		auth := &EvmAuthorization{Signed: true}
		if auth.ChainId, err = decodeUint64Checked(fields[0]); err != nil {
			return nil, err
		}
		auth.Address = "0x" + hex.EncodeToString(fields[1])
		if auth.Nonce, err = decodeUint64Checked(fields[2]); err != nil {
			return nil, err
		}
		auth.Y = new(big.Int).SetBytes(fields[3])
		auth.R = new(big.Int).SetBytes(fields[4])
		auth.S = new(big.Int).SetBytes(fields[5])
		out = append(out, auth)
	}
	return out, nil
}
