package outscript_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/outscript"
)

// expandSeed mimics the standard Ed25519 secret-key expansion (RFC 8032): the
// 32-byte seed is hashed with SHA-512, the lower half is clamped into the scalar,
// and the upper half is the nonce. The 64-byte result is the extended secret a
// CardanoExtendedKey stores directly.
func expandSeed(seed []byte) []byte {
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 63
	h[31] |= 64
	return h[:]
}

// TestCardanoExtendedKeyMatchesStdlib proves the extended-key signer implements
// genuine Ed25519: for a key expanded from a seed the standard way, both its
// public key and its signatures are byte-identical to crypto/ed25519.
func TestCardanoExtendedKeyMatchesStdlib(t *testing.T) {
	for i := 0; i < 8; i++ {
		seed := bytes.Repeat([]byte{byte(i + 1)}, ed25519.SeedSize)
		std := ed25519.NewKeyFromSeed(seed)
		stdPub := std.Public().(ed25519.PublicKey)

		ek, err := outscript.NewCardanoExtendedKey(expandSeed(seed))
		if err != nil {
			t.Fatalf("seed %d: NewCardanoExtendedKey: %s", i, err)
		}

		if !bytes.Equal(ek.CardanoPublicKey(), stdPub) {
			t.Fatalf("seed %d: public key mismatch:\n ext %s\n std %s",
				i, hex.EncodeToString(ek.CardanoPublicKey()), hex.EncodeToString(stdPub))
		}

		for _, msg := range [][]byte{nil, []byte("cardano"), bytes.Repeat([]byte{0xAB}, 32)} {
			got, err := ek.SignCardano(msg)
			if err != nil {
				t.Fatalf("seed %d: SignCardano: %s", i, err)
			}
			want := ed25519.Sign(std, msg)
			if !bytes.Equal(got, want) {
				t.Errorf("seed %d msg %x: signature mismatch:\n ext %s\n std %s",
					i, msg, hex.EncodeToString(got), hex.EncodeToString(want))
			}
			if !ed25519.Verify(stdPub, msg, got) {
				t.Errorf("seed %d: extended signature does not verify", i)
			}
		}
	}
}

// TestCardanoExtendedKeyDerivedScalar checks that a scalar which is NOT in
// freshly-clamped form (as happens after BIP32-Ed25519 child derivation, where
// kL = 8·Z + parent) still produces a valid Ed25519 signature. crypto/ed25519
// cannot represent such a key, which is the whole reason the extended signer
// exists.
func TestCardanoExtendedKeyDerivedScalar(t *testing.T) {
	secret := expandSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	// Simulate a derivation step: add 8·Z to the low part of the scalar, keeping
	// the low 3 bits clear and staying within 2^255.
	carry := 0
	for i := 0; i < 28; i++ {
		v := int(secret[i]) + ((8 * 0x1234) >> (uint(i%4) * 8) & 0xff) + carry
		secret[i] = byte(v & 0xff)
		carry = v >> 8
	}
	secret[0] &= 248 // keep low 3 bits clear (multiple of 8)
	secret[31] &= 63 // keep below 2^254 for the test
	secret[31] |= 64

	ek, err := outscript.NewCardanoExtendedKey(secret)
	if err != nil {
		t.Fatalf("NewCardanoExtendedKey: %s", err)
	}
	pub := ek.CardanoPublicKey()
	msg := []byte("derived-key transaction body hash")
	sig, err := ek.SignCardano(msg)
	if err != nil {
		t.Fatalf("SignCardano: %s", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		t.Errorf("derived-key signature does not verify against its own public key")
	}
}

func TestCardanoExtendedKeyBadLength(t *testing.T) {
	if _, err := outscript.NewCardanoExtendedKey(make([]byte, 63)); err == nil {
		t.Errorf("expected error for 63-byte secret")
	}
}

// TestCardanoTxSignWithExtendedKey exercises the full transaction path with an
// extended-key signer.
func TestCardanoTxSignWithExtendedKey(t *testing.T) {
	tx := sampleCardanoTx(t)

	ek, err := outscript.NewCardanoExtendedKey(expandSeed(bytes.Repeat([]byte{0x55}, ed25519.SeedSize)))
	if err != nil {
		t.Fatalf("NewCardanoExtendedKey: %s", err)
	}

	digest, _ := tx.SignBytes()
	if err := tx.SignWith(ek); err != nil {
		t.Fatalf("SignWith: %s", err)
	}
	if len(tx.Witnesses) != 1 {
		t.Fatalf("expected 1 witness, got %d", len(tx.Witnesses))
	}
	w := tx.Witnesses[0]
	if !bytes.Equal(w.VKey, ek.CardanoPublicKey()) {
		t.Errorf("witness vkey mismatch")
	}
	if !ed25519.Verify(ed25519.PublicKey(w.VKey), digest, w.Signature) {
		t.Errorf("extended-key witness signature does not verify against body digest")
	}

	// must still marshal/round-trip cleanly
	enc, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %s", err)
	}
	var decoded outscript.CardanoTx
	if err := decoded.UnmarshalBinary(enc); err != nil {
		t.Fatalf("UnmarshalBinary: %s", err)
	}
	if len(decoded.Witnesses) != 1 || !bytes.Equal(decoded.Witnesses[0].Signature, w.Signature) {
		t.Errorf("witness lost in round-trip")
	}
}
