package outscript

import (
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"

	"github.com/KarpelesLab/edwards25519"
)

// CardanoSigner produces an Ed25519 signature over a 32-byte message (the
// transaction body hash) and exposes the public key it signs with. It lets a
// [CardanoTx] be signed by standard Ed25519 keys, BIP32-Ed25519 extended keys
// (see [CardanoExtendedKey]), or external signers such as HSMs.
type CardanoSigner interface {
	// CardanoPublicKey returns the 32-byte Ed25519 public key.
	CardanoPublicKey() []byte
	// SignCardano returns a 64-byte Ed25519 signature over message.
	SignCardano(message []byte) ([]byte, error)
}

// cardanoStdSigner adapts a standard crypto/ed25519 key to [CardanoSigner].
type cardanoStdSigner struct {
	key ed25519.PrivateKey
}

func (s cardanoStdSigner) CardanoPublicKey() []byte {
	return append([]byte(nil), s.key.Public().(ed25519.PublicKey)...)
}

func (s cardanoStdSigner) SignCardano(message []byte) ([]byte, error) {
	return ed25519.Sign(s.key, message), nil
}

// CardanoExtendedKey is a BIP32-Ed25519 (CIP-1852) extended Ed25519 signing key,
// the form used by Cardano HD wallets. A standard Ed25519 key is a 32-byte seed
// that is expanded with SHA-512 (and clamped) at signing time; an extended key
// instead stores the already-expanded 64-byte secret directly — a 32-byte scalar
// followed by a 32-byte nonce — so it cannot be used with crypto/ed25519. The
// scalar is not re-clamped here, which is what allows it to represent keys
// produced by BIP32-Ed25519 child derivation.
//
// The signatures it produces are ordinary Ed25519 signatures, verifiable with
// crypto/ed25519 against [CardanoExtendedKey.CardanoPublicKey].
type CardanoExtendedKey struct {
	scalar    [32]byte // kL: the (clamped or derived) signing scalar
	nonce     [32]byte // kR: the signing nonce / prefix
	pub       [32]byte // cached public key A = (kL mod L)·B
	chainCode [32]byte // 32-byte chain code (only set when derivable)
	hasChain  bool     // whether chainCode is present (required for derivation)
}

// NewCardanoExtendedKey builds an extended key from a Cardano xprv. The input is
// either the 64-byte expanded secret (a 32-byte scalar followed by a 32-byte
// nonce) for signing only, or the full 96-byte xprv (secret followed by a 32-byte
// chain code), which additionally enables BIP32-Ed25519 child derivation. This is
// the form exported by tooling such as cardano-address or
// cardano-serialization-lib.
func NewCardanoExtendedKey(xprv []byte) (*CardanoExtendedKey, error) {
	if len(xprv) != 64 && len(xprv) != 96 {
		return nil, fmt.Errorf("cardano xprv must be 64 or 96 bytes, got %d", len(xprv))
	}
	ek := &CardanoExtendedKey{}
	copy(ek.scalar[:], xprv[:32])
	copy(ek.nonce[:], xprv[32:64])
	if len(xprv) == 96 {
		copy(ek.chainCode[:], xprv[64:96])
		ek.hasChain = true
	}
	ek.pub = cardanoScalarBasePub(&ek.scalar)
	return ek, nil
}

// ChainCode returns the 32-byte chain code, or nil if this key was created
// without one (and therefore cannot derive children).
func (ek *CardanoExtendedKey) ChainCode() []byte {
	if !ek.hasChain {
		return nil
	}
	return append([]byte(nil), ek.chainCode[:]...)
}

// CardanoPublicKey returns the 32-byte Ed25519 public key for this extended key.
func (ek *CardanoExtendedKey) CardanoPublicKey() []byte {
	return append([]byte(nil), ek.pub[:]...)
}

// Bytes returns the xprv: the 64-byte expanded secret (scalar followed by nonce),
// plus the 32-byte chain code when present (96 bytes total).
func (ek *CardanoExtendedKey) Bytes() []byte {
	out := make([]byte, 0, 96)
	out = append(out, ek.scalar[:]...)
	out = append(out, ek.nonce[:]...)
	if ek.hasChain {
		out = append(out, ek.chainCode[:]...)
	}
	return out
}

// SignCardano signs message (the 32-byte transaction body hash) and returns a
// standard 64-byte Ed25519 signature. The signing follows RFC 8032 PureEdDSA but
// uses the stored scalar and nonce instead of expanding a seed:
//
//	a    = scalar mod L
//	r    = SHA-512(nonce || message) mod L
//	R    = r·B
//	hram = SHA-512(R || A || message) mod L
//	S    = (hram·a + r) mod L
//	sig  = R || S
func (ek *CardanoExtendedKey) SignCardano(message []byte) ([]byte, error) {
	a := cardanoReduceScalar(&ek.scalar)

	hr := sha512.New()
	hr.Write(ek.nonce[:])
	hr.Write(message)
	var r64 [64]byte
	hr.Sum(r64[:0])
	var r [32]byte
	edwards25519.ScReduce(&r, &r64)

	var Rge edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&Rge, &r)
	var R [32]byte
	Rge.ToBytes(&R)

	hk := sha512.New()
	hk.Write(R[:])
	hk.Write(ek.pub[:])
	hk.Write(message)
	var k64 [64]byte
	hk.Sum(k64[:0])
	var hram [32]byte
	edwards25519.ScReduce(&hram, &k64)

	var s [32]byte
	edwards25519.ScMulAdd(&s, &hram, &a, &r)

	sig := make([]byte, 64)
	copy(sig[:32], R[:])
	copy(sig[32:], s[:])
	return sig, nil
}

// cardanoReduceScalar interprets a 32-byte little-endian scalar and reduces it
// modulo the group order L. The scalar is not clamped, so derived extended keys
// (whose scalar is not in freshly-clamped form) are handled correctly.
func cardanoReduceScalar(in *[32]byte) [32]byte {
	var wide [64]byte
	copy(wide[:32], in[:])
	var out [32]byte
	edwards25519.ScReduce(&out, &wide)
	return out
}

// cardanoScalarBasePub returns the compressed public key A = (scalar mod L)·B.
func cardanoScalarBasePub(scalar *[32]byte) [32]byte {
	a := cardanoReduceScalar(scalar)
	var A edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&A, &a)
	var pub [32]byte
	A.ToBytes(&pub)
	return pub
}
