package outscript_test

import (
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/outscript"
	"github.com/KarpelesLab/secp256k1"
)

// BIP-340 test vectors (subset with aux_rand = 0 so our deterministic-aux
// implementation matches). Taken from
// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
var bip340SignVectors = []struct {
	secKey   string
	pubKey   string // x-only
	aux      string
	msg      string
	expected string
}{
	{
		// index 0
		secKey:   "0000000000000000000000000000000000000000000000000000000000000003",
		pubKey:   "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		aux:      "0000000000000000000000000000000000000000000000000000000000000000",
		msg:      "0000000000000000000000000000000000000000000000000000000000000000",
		expected: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
	},
}

func TestBIP340SignVectors(t *testing.T) {
	for i, v := range bip340SignVectors {
		secBytes, _ := hex.DecodeString(v.secKey)
		priv := secp256k1.PrivKeyFromBytes(secBytes)
		// Sanity: pubkey matches expected x-only key.
		pub := priv.PubKey().SerializeCompressed()
		got := hex.EncodeToString(pub[1:])
		if got != toLower(v.pubKey) {
			t.Errorf("vector %d: pubkey mismatch: got %s want %s", i, got, v.pubKey)
		}

		sig, err := outscript.BIP340SignForTest(priv, mustHex(t, v.msg), mustHex(t, v.aux))
		if err != nil {
			t.Errorf("vector %d: sign err: %v", i, err)
			continue
		}
		gotSig := hex.EncodeToString(sig)
		if gotSig != toLower(v.expected) {
			t.Errorf("vector %d: sig mismatch:\n got  %s\n want %s", i, gotSig, v.expected)
		}
	}
}

// BIP-341 taproot tweak vector from the spec (test vector 0 under
// "scriptPubKey tests", key-path only with empty merkle root).
// Given internal key, tweaked x-only output key should match.
func TestBIP341TaprootTweak(t *testing.T) {
	// From the BIP-341 test vectors JSON (commit-final spec values):
	//   internal_key (x-only): d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d
	//   tweak (empty merkle root) output:
	//       x-only: 53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343
	internalX, _ := hex.DecodeString("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d")
	wantX := "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"

	gotX, _, err := outscript.TaprootTweakForTest(internalX)
	if err != nil {
		t.Fatalf("tweak err: %v", err)
	}
	if hex.EncodeToString(gotX) != wantX {
		t.Errorf("tweaked key mismatch:\n got  %x\n want %s", gotX, wantX)
	}
}

// TestP2TRGenerate verifies that Script.Generate("p2tr") yields the correct
// scriptPubKey for a known pubkey/address pair.
func TestP2TRGenerate(t *testing.T) {
	// Derive pubkey from a fixed privkey and compare its generated p2tr
	// script against the taproot script derived via independent tweak.
	privBytes, _ := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101")
	priv := secp256k1.PrivKeyFromBytes(privBytes)

	s := outscript.New(priv.PubKey())
	script, err := s.Generate("p2tr")
	if err != nil {
		t.Fatalf("generate p2tr: %v", err)
	}
	if len(script) != 34 {
		t.Fatalf("p2tr script len = %d, want 34", len(script))
	}
	if script[0] != 0x51 || script[1] != 0x20 {
		t.Fatalf("p2tr script must start with 0x5120, got %x", script[:2])
	}

	// Double-check via direct tweak of the x-only internal key.
	pub := priv.PubKey().SerializeCompressed()
	wantX, _, err := outscript.TaprootTweakForTest(pub[1:])
	if err != nil {
		t.Fatalf("tweak: %v", err)
	}
	if hex.EncodeToString(script[2:]) != hex.EncodeToString(wantX) {
		t.Errorf("p2tr output key mismatch:\n got  %x\n want %x", script[2:], wantX)
	}
}

func TestP2TRAddress(t *testing.T) {
	privBytes, _ := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101")
	priv := secp256k1.PrivKeyFromBytes(privBytes)
	s := outscript.New(priv.PubKey())
	addr, err := s.Address("p2tr", "bitcoin")
	if err != nil {
		t.Fatalf("p2tr address: %v", err)
	}
	if addr[:4] != "bc1p" {
		t.Errorf("p2tr address should start with bc1p, got %s", addr)
	}
	// Round-trip: parse it back and ensure script matches.
	out, err := outscript.ParseBitcoinBasedAddress("bitcoin", addr)
	if err != nil {
		t.Fatalf("parse back: %v", err)
	}
	gen, _ := s.Generate("p2tr")
	if hex.EncodeToString(out.Bytes()) != hex.EncodeToString(gen) {
		t.Errorf("round-trip mismatch:\n addr script %x\n gen script  %x", out.Bytes(), gen)
	}
}

func TestP2TRSignProducesValidSig(t *testing.T) {
	// End-to-end: build a 1-in/1-out tx spending a p2tr output, sign with
	// the p2tr scheme, and verify the resulting 64-byte Schnorr signature
	// against the tweaked output key.
	privBytes, _ := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101")
	priv := secp256k1.PrivKeyFromBytes(privBytes)
	s := outscript.New(priv.PubKey())
	scriptPubKey, err := s.Generate("p2tr")
	if err != nil {
		t.Fatalf("gen: %v", err)
	}

	tx := &outscript.BtcTx{
		Version: 2,
		In: []*outscript.BtcTxInput{{
			Vout:     0,
			Sequence: 0xffffffff,
		}},
		Out: []*outscript.BtcTxOutput{{
			Amount: outscript.BtcAmount(90000),
			Script: scriptPubKey,
		}},
	}

	err = tx.Sign(&outscript.BtcTxSign{
		Key:        priv,
		Scheme:     "p2tr",
		Amount:     outscript.BtcAmount(100000),
		PrevScript: scriptPubKey,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if got := len(tx.In[0].Witnesses); got != 1 {
		t.Fatalf("witness count = %d, want 1", got)
	}
	if got := len(tx.In[0].Witnesses[0]); got != 64 {
		t.Fatalf("sig len = %d, want 64", got)
	}

	// Re-derive the BIP-341 sighash and verify the 64-byte Schnorr signature
	// against the tweaked x-only output key.
	keys := []*outscript.BtcTxSign{{
		Amount:     outscript.BtcAmount(100000),
		PrevScript: scriptPubKey,
	}}
	digest, err := outscript.TaprootSighashForTest(tx, keys, 0)
	if err != nil {
		t.Fatalf("sighash: %v", err)
	}
	ok, err := outscript.BIP340VerifyForTest(scriptPubKey[2:], digest, tx.In[0].Witnesses[0])
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Errorf("schnorr verification failed on generated p2tr signature")
	}
}

// --- helpers ---

func toLower(s string) string {
	b := make([]byte, len(s))
	for i, c := range s {
		if c >= 'A' && c <= 'F' {
			c += 'a' - 'A'
		}
		b[i] = byte(c)
	}
	return string(b)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %s", s)
	}
	return b
}
