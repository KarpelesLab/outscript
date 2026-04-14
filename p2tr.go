package outscript

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/KarpelesLab/secp256k1"
)

// bip340TaggedHash returns SHA256(SHA256(tag) || SHA256(tag) || data...), as
// defined in BIP-340.
func bip340TaggedHash(tag string, data ...[]byte) []byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// taprootLiftX parses a 32-byte x-only public key and returns the point with
// an even Y coordinate, per BIP-340 lift_x.
func taprootLiftX(xOnly []byte) (*secp256k1.JacobianPoint, error) {
	if len(xOnly) != 32 {
		return nil, fmt.Errorf("taproot: x-only pubkey must be 32 bytes, got %d", len(xOnly))
	}
	var x secp256k1.FieldVal
	if overflow := x.SetByteSlice(xOnly); overflow {
		return nil, errors.New("taproot: x-only pubkey x >= field prime")
	}
	var y secp256k1.FieldVal
	if !secp256k1.DecompressY(&x, false, &y) {
		return nil, errors.New("taproot: x coordinate is not on the curve")
	}
	y.Normalize()
	var p secp256k1.JacobianPoint
	p.X.Set(&x)
	p.Y.Set(&y)
	p.Z.SetInt(1)
	return &p, nil
}

// taprootXOnlyFromPubKey extracts the 32-byte x-only public key from a
// 33-byte compressed secp256k1 pubkey.
func taprootXOnlyFromPubKey(pubComp []byte) ([]byte, error) {
	if len(pubComp) != 33 {
		return nil, fmt.Errorf("taproot: expected 33-byte compressed pubkey, got %d", len(pubComp))
	}
	return append([]byte(nil), pubComp[1:]...), nil
}

// taprootTweakPubKey applies the BIP-341 taproot tweak to an internal public
// key, with an empty merkle root (key-path only). It returns the 32-byte
// tweaked x-only output key and parity (0 if tweaked Q has even Y, 1 if odd).
func taprootTweakPubKey(internalXOnly []byte) (tweakedXOnly []byte, parity int, tweak [32]byte, err error) {
	P, err := taprootLiftX(internalXOnly)
	if err != nil {
		return nil, 0, tweak, err
	}
	// t = tagged_hash("TapTweak", x(P)) since merkle_root is empty
	tBytes := bip340TaggedHash("TapTweak", internalXOnly)
	var t secp256k1.ModNScalar
	if overflow := t.SetByteSlice(tBytes); overflow {
		return nil, 0, tweak, errors.New("taproot: tweak >= curve order")
	}
	copy(tweak[:], tBytes)
	// Q = P + t*G
	var tG, Q secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&t, &tG)
	secp256k1.AddNonConst(P, &tG, &Q)
	Q.ToAffine()
	out := make([]byte, 32)
	Q.X.PutBytesUnchecked(out)
	par := 0
	if Q.Y.IsOdd() {
		par = 1
	}
	return out, par, tweak, nil
}

// TaprootTweak applies the BIP-341 key-path-only taproot tweak to a 32-byte
// x-only internal public key (empty merkle root). It returns the 32-byte
// tweaked x-only output key and the parity of the tweaked point (0 if the
// resulting Q has an even Y coordinate, 1 if odd).
//
// TSS / MuSig / FROST callers use this to derive the aggregate output key
// they need to commit to on-chain; signing itself is then done via a
// [TaprootSigner] that already knows the tweak.
func TaprootTweak(internalXOnly []byte) (tweakedXOnly []byte, parity int, err error) {
	out, par, _, err := taprootTweakPubKey(internalXOnly)
	return out, par, err
}

// ITaprootTweak is an [Insertable] that takes a 33-byte compressed secp256k1
// pubkey and emits the 32-byte BIP-341 key-path-only tweaked x-only output key.
type ITaprootTweak struct {
	v Insertable
}

// Bytes produces the 32-byte tweaked x-only output pubkey.
func (i ITaprootTweak) Bytes(s *Script) ([]byte, error) {
	buf, err := i.v.Bytes(s)
	if err != nil {
		return nil, err
	}
	xOnly, err := taprootXOnlyFromPubKey(buf)
	if err != nil {
		return nil, err
	}
	out, _, _, err := taprootTweakPubKey(xOnly)
	return out, err
}

// String returns a human-readable representation.
func (i ITaprootTweak) String() string {
	return fmt.Sprintf("TaprootTweak(%s)", i.v)
}

// bip340Sign produces a 64-byte BIP-340 Schnorr signature over msg (must be
// 32 bytes) using the given raw private key scalar. auxRand is 32 bytes of
// auxiliary randomness per BIP-340; callers that want deterministic behavior
// should pass a zero-filled slice.
func bip340Sign(priv *secp256k1.ModNScalar, msg, auxRand []byte) ([]byte, error) {
	if len(msg) != 32 {
		return nil, fmt.Errorf("bip340: message must be 32 bytes, got %d", len(msg))
	}
	if len(auxRand) != 32 {
		return nil, fmt.Errorf("bip340: aux_rand must be 32 bytes, got %d", len(auxRand))
	}
	if priv.IsZero() {
		return nil, errors.New("bip340: private key is zero")
	}

	// P = d0*G; if P.y is odd, d = n - d0; otherwise d = d0.
	var P secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(priv, &P)
	P.ToAffine()
	var d secp256k1.ModNScalar
	d.Set(priv)
	if P.Y.IsOdd() {
		d.Negate()
	}

	var pxBytes [32]byte
	P.X.PutBytes(&pxBytes)

	// t = d XOR tagged_hash("BIP0340/aux", aux_rand)
	auxHash := bip340TaggedHash("BIP0340/aux", auxRand)
	var dBytes [32]byte
	d.PutBytes(&dBytes)
	var tBytes [32]byte
	for i := 0; i < 32; i++ {
		tBytes[i] = dBytes[i] ^ auxHash[i]
	}

	// rand = tagged_hash("BIP0340/nonce", t || P.x || msg)
	randBytes := bip340TaggedHash("BIP0340/nonce", tBytes[:], pxBytes[:], msg)
	var k secp256k1.ModNScalar
	k.SetByteSlice(randBytes)
	if k.IsZero() {
		return nil, errors.New("bip340: derived nonce is zero")
	}

	// R = k*G; if R.y is odd, k = n - k.
	var R secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&k, &R)
	R.ToAffine()
	if R.Y.IsOdd() {
		k.Negate()
	}
	var rxBytes [32]byte
	R.X.PutBytes(&rxBytes)

	// e = int(tagged_hash("BIP0340/challenge", R.x || P.x || msg)) mod n
	eBytes := bip340TaggedHash("BIP0340/challenge", rxBytes[:], pxBytes[:], msg)
	var e secp256k1.ModNScalar
	e.SetByteSlice(eBytes)

	// s = k + e*d mod n
	var ed secp256k1.ModNScalar
	ed.Mul2(&e, &d)
	var s secp256k1.ModNScalar
	s.Add2(&k, &ed)
	var sBytes [32]byte
	s.PutBytes(&sBytes)

	sig := make([]byte, 64)
	copy(sig[:32], rxBytes[:])
	copy(sig[32:], sBytes[:])
	return sig, nil
}

// TaprootSigner is implemented by signers that can produce a 64-byte BIP-340
// Schnorr signature directly over a 32-byte sighash digest. The signer is
// responsible for applying the BIP-341 taproot tweak (and any y-parity
// adjustments) to its key material before signing — the outscript package
// does not attempt to tweak an opaque signer.
//
// This is the integration point for TSS / MuSig2 / FROST signers and for
// hardware-backed or mock ("fake") signers that do not expose a raw private
// scalar. Use [TaprootTweak] and [BtcTx.TaprootSighash] to compute the
// tweaked output key and the sighash outside the library.
type TaprootSigner interface {
	SignTaproot(sighash []byte) ([]byte, error)
}

// taprootPrivKey returns the underlying secp256k1 private scalar of a
// crypto.Signer. Callers that can't expose a raw scalar (TSS, HSM, etc.)
// should implement [TaprootSigner] on their Key instead.
func taprootPrivKey(signer crypto.Signer) (*secp256k1.PrivateKey, error) {
	if pk, ok := signer.(*secp256k1.PrivateKey); ok {
		return pk, nil
	}
	return nil, fmt.Errorf("p2tr signing requires *secp256k1.PrivateKey or a TaprootSigner, got %T", signer)
}
