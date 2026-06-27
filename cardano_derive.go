package outscript

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/KarpelesLab/edwards25519"
	"golang.org/x/crypto/pbkdf2"
)

// CardanoHardened is the offset that marks a BIP32 derivation index as hardened.
// A hardened child can only be derived from a private key.
const CardanoHardened uint32 = 0x80000000

// CardanoHarden returns the hardened form of a derivation index (index | 2^31).
func CardanoHarden(index uint32) uint32 {
	return index | CardanoHardened
}

// CardanoIcarusMasterKey derives a root extended key from BIP-39 entropy using
// the Icarus master-key scheme (CIP-3): the 96-byte xprv is
// PBKDF2(HMAC-SHA512, password, entropy, 4096 iterations), with the resulting
// scalar bit-tweaked. password is the optional spending passphrase (use nil for
// none); entropy is the decoded BIP-39 entropy, not the mnemonic seed.
func CardanoIcarusMasterKey(entropy, password []byte) (*CardanoExtendedKey, error) {
	if len(entropy) == 0 {
		return nil, errors.New("cardano: empty entropy")
	}
	xprv := pbkdf2.Key(password, entropy, 4096, 96, sha512.New)
	// normalize the scalar (CIP-3 force-3rd clamp): clear the low 3 bits and the
	// two highest bits, set bit 254.
	xprv[0] &= 0b1111_1000
	xprv[31] &= 0b0001_1111
	xprv[31] |= 0b0100_0000
	return NewCardanoExtendedKey(xprv)
}

// DeriveChild derives the BIP32-Ed25519 (scheme V2) child of this key at index.
// Indices >= [CardanoHardened] derive a hardened child. The key must carry a
// chain code (i.e. have been created from a 96-byte xprv or via
// [CardanoIcarusMasterKey]).
func (ek *CardanoExtendedKey) DeriveChild(index uint32) (*CardanoExtendedKey, error) {
	if !ek.hasChain {
		return nil, errors.New("cardano: extended key has no chain code; cannot derive")
	}
	seri := cardanoLE32(index)
	zmac := hmac.New(sha512.New, ek.chainCode[:])
	imac := hmac.New(sha512.New, ek.chainCode[:])
	if index >= CardanoHardened {
		// hardened: HMAC over 0x00/0x01 || kL || kR || ser32(i)
		zmac.Write([]byte{0x00})
		zmac.Write(ek.scalar[:])
		zmac.Write(ek.nonce[:])
		zmac.Write(seri)
		imac.Write([]byte{0x01})
		imac.Write(ek.scalar[:])
		imac.Write(ek.nonce[:])
		imac.Write(seri)
	} else {
		// soft: HMAC over 0x02/0x03 || A || ser32(i)
		zmac.Write([]byte{0x02})
		zmac.Write(ek.pub[:])
		zmac.Write(seri)
		imac.Write([]byte{0x03})
		imac.Write(ek.pub[:])
		imac.Write(seri)
	}
	zout := zmac.Sum(nil)
	iout := imac.Sum(nil)

	var zl, zr [32]byte
	copy(zl[:], zout[:32])
	copy(zr[:], zout[32:64])

	child := &CardanoExtendedKey{hasChain: true}
	child.scalar = cardanoAdd28Mul8(&ek.scalar, &zl) // kL_child = kL + 8·trunc28(zl)
	child.nonce = cardanoAdd256(&ek.nonce, &zr)      // kR_child = kR + zr (mod 2^256)
	copy(child.chainCode[:], iout[32:64])
	child.pub = cardanoScalarBasePub(&child.scalar)
	return child, nil
}

// DerivePath derives a chain of children in sequence, e.g. the CIP-1852 payment
// key path CardanoHarden(1852), CardanoHarden(1815), CardanoHarden(0), 0, 0.
func (ek *CardanoExtendedKey) DerivePath(indices ...uint32) (*CardanoExtendedKey, error) {
	cur := ek
	for i, idx := range indices {
		next, err := cur.DeriveChild(idx)
		if err != nil {
			return nil, fmt.Errorf("cardano: deriving index %d (step %d): %w", idx, i, err)
		}
		cur = next
	}
	return cur, nil
}

// CardanoExtendedPubKey is a BIP32-Ed25519 extended public key (a 32-byte public
// key plus a 32-byte chain code). It supports watch-only derivation of soft
// (non-hardened) children without access to the private key.
type CardanoExtendedPubKey struct {
	pub       [32]byte
	chainCode [32]byte
}

// ExtendedPublicKey returns the extended public key (public key + chain code) for
// this private extended key, suitable for watch-only soft derivation. It returns
// nil if the key has no chain code.
func (ek *CardanoExtendedKey) ExtendedPublicKey() *CardanoExtendedPubKey {
	if !ek.hasChain {
		return nil
	}
	xp := &CardanoExtendedPubKey{}
	xp.pub = ek.pub
	xp.chainCode = ek.chainCode
	return xp
}

// NewCardanoExtendedPubKey builds an extended public key from a 32-byte public key
// and 32-byte chain code.
func NewCardanoExtendedPubKey(pub, chainCode []byte) (*CardanoExtendedPubKey, error) {
	if len(pub) != 32 {
		return nil, fmt.Errorf("cardano public key must be 32 bytes, got %d", len(pub))
	}
	if len(chainCode) != 32 {
		return nil, fmt.Errorf("cardano chain code must be 32 bytes, got %d", len(chainCode))
	}
	xp := &CardanoExtendedPubKey{}
	copy(xp.pub[:], pub)
	copy(xp.chainCode[:], chainCode)
	return xp, nil
}

// PublicKey returns the 32-byte Ed25519 public key.
func (xp *CardanoExtendedPubKey) PublicKey() []byte {
	return append([]byte(nil), xp.pub[:]...)
}

// ChainCode returns the 32-byte chain code.
func (xp *CardanoExtendedPubKey) ChainCode() []byte {
	return append([]byte(nil), xp.chainCode[:]...)
}

// DeriveChild derives a soft (non-hardened) child extended public key. Hardened
// derivation is impossible without the private key and returns an error.
func (xp *CardanoExtendedPubKey) DeriveChild(index uint32) (*CardanoExtendedPubKey, error) {
	if index >= CardanoHardened {
		return nil, errors.New("cardano: cannot derive a hardened child from a public key")
	}
	seri := cardanoLE32(index)
	zmac := hmac.New(sha512.New, xp.chainCode[:])
	imac := hmac.New(sha512.New, xp.chainCode[:])
	zmac.Write([]byte{0x02})
	zmac.Write(xp.pub[:])
	zmac.Write(seri)
	imac.Write([]byte{0x03})
	imac.Write(xp.pub[:])
	imac.Write(seri)
	zout := zmac.Sum(nil)
	iout := imac.Sum(nil)

	var zl [32]byte
	copy(zl[:], zout[:32])
	// child public point = A + (8·trunc28(zl))·B
	var zero [32]byte
	tweak := cardanoAdd28Mul8(&zero, &zl)
	childPub, err := cardanoPointAddBase(&xp.pub, &tweak)
	if err != nil {
		return nil, err
	}
	child := &CardanoExtendedPubKey{pub: childPub}
	copy(child.chainCode[:], iout[32:64])
	return child, nil
}

// DerivePath derives a chain of soft children in sequence.
func (xp *CardanoExtendedPubKey) DerivePath(indices ...uint32) (*CardanoExtendedPubKey, error) {
	cur := xp
	for i, idx := range indices {
		next, err := cur.DeriveChild(idx)
		if err != nil {
			return nil, fmt.Errorf("cardano: deriving index %d (step %d): %w", idx, i, err)
		}
		cur = next
	}
	return cur, nil
}

// cardanoLE32 serializes a derivation index as little-endian (BIP32-Ed25519 V2).
func cardanoLE32(i uint32) []byte {
	return []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}
}

// cardanoAdd28Mul8 computes x + 8·y over the low 28 bytes of y, propagating the
// carry through bytes 28..31 of x. This is the V2 scalar tweak for child keys.
func cardanoAdd28Mul8(x, y *[32]byte) [32]byte {
	var out [32]byte
	var carry uint16
	for i := 0; i < 28; i++ {
		r := uint16(x[i]) + (uint16(y[i]) << 3) + carry
		out[i] = byte(r)
		carry = r >> 8
	}
	for i := 28; i < 32; i++ {
		r := uint16(x[i]) + carry
		out[i] = byte(r)
		carry = r >> 8
	}
	return out
}

// cardanoAdd256 computes x + y modulo 2^256 (32-byte little-endian addition).
func cardanoAdd256(x, y *[32]byte) [32]byte {
	var out [32]byte
	var carry uint16
	for i := 0; i < 32; i++ {
		r := uint16(x[i]) + uint16(y[i]) + carry
		out[i] = byte(r)
		carry = r >> 8
	}
	return out
}

// cardanoPointAddBase returns the compressed encoding of A + scalar·B, where A is
// the point decoded from pub. Used for watch-only public child derivation.
func cardanoPointAddBase(pub, scalar *[32]byte) ([32]byte, error) {
	var a edwards25519.ExtendedGroupElement
	if !a.FromBytes(pub) {
		return [32]byte{}, errors.New("cardano: invalid parent public key point")
	}
	red := cardanoReduceScalar(scalar)
	var tweak edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&tweak, &red)
	var sum edwards25519.ExtendedGroupElement
	sum.Add(&a, &tweak)
	var out [32]byte
	sum.ToBytes(&out)
	return out, nil
}
