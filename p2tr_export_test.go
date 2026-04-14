package outscript

import (
	"errors"

	"github.com/KarpelesLab/secp256k1"
)

// Test-only exports for package-internal helpers.

// BIP340SignForTest exposes bip340Sign without any BIP-341 taproot tweak so
// that top-level BIP-340 vectors can be exercised.
func BIP340SignForTest(priv *secp256k1.PrivateKey, msg, auxRand []byte) ([]byte, error) {
	return bip340Sign(&priv.Key, msg, auxRand)
}

// TaprootTweakForTest exposes taprootTweakPubKey.
func TaprootTweakForTest(internalXOnly []byte) (tweakedXOnly []byte, parity int, err error) {
	out, par, _, err := taprootTweakPubKey(internalXOnly)
	return out, par, err
}

// TaprootSighashForTest computes the BIP-341 SIGHASH_DEFAULT key-path sighash
// for input idx of tx, given the full slice of signing keys (each with
// PrevScript and Amount populated for its input).
func TaprootSighashForTest(tx *BtcTx, keys []*BtcTxSign, idx int) ([]byte, error) {
	parts, err := tx.taprootSighashParts(keys)
	if err != nil {
		return nil, err
	}
	return tx.taprootKeySpendSighash(idx, 0x00, parts)
}

// BIP340VerifyForTest verifies a 64-byte BIP-340 Schnorr signature over msg
// against a 32-byte x-only public key.
func BIP340VerifyForTest(xOnly, msg, sig []byte) (bool, error) {
	if len(xOnly) != 32 {
		return false, errors.New("xOnly must be 32 bytes")
	}
	if len(sig) != 64 {
		return false, errors.New("sig must be 64 bytes")
	}
	P, err := taprootLiftX(xOnly)
	if err != nil {
		return false, err
	}
	var r secp256k1.FieldVal
	if overflow := r.SetByteSlice(sig[:32]); overflow {
		return false, nil
	}
	r.Normalize()
	var s secp256k1.ModNScalar
	if overflow := s.SetByteSlice(sig[32:]); overflow {
		return false, nil
	}

	rxBytes := make([]byte, 32)
	r.PutBytesUnchecked(rxBytes)
	eBytes := bip340TaggedHash("BIP0340/challenge", rxBytes, xOnly, msg)
	var e secp256k1.ModNScalar
	e.SetByteSlice(eBytes)

	// R = s*G - e*P
	e.Negate()
	var sG, eP, R secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&s, &sG)
	secp256k1.ScalarMultNonConst(&e, P, &eP)
	secp256k1.AddNonConst(&sG, &eP, &R)
	if (R.X.IsZero() && R.Y.IsZero()) || R.Z.IsZero() {
		return false, nil
	}
	R.ToAffine()
	if R.Y.IsOdd() {
		return false, nil
	}
	return R.X.Equals(&r), nil
}
