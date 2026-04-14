package outscript_test

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
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

	gotX, _, err := outscript.TaprootTweak(internalX)
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
	wantX, _, err := outscript.TaprootTweak(pub[1:])
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
	digest, err := tx.TaprootSighash(keys, 0)
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

// taprootSignerStub implements both crypto.Signer (for the Key field type)
// and outscript.TaprootSigner. It pretends to be an external signer (TSS,
// HSM, mock) that already knows its own tweaked key — the library must NOT
// apply a second tweak when this path is taken. We prove that by signing
// with the already-tweaked scalar and verifying against the tweaked x-only
// output key.
type taprootSignerStub struct {
	tweaked *secp256k1.ModNScalar
	pub     *secp256k1.PublicKey
}

func (s *taprootSignerStub) Public() crypto.PublicKey { return s.pub }
func (s *taprootSignerStub) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("unused: TaprootSigner path should be taken")
}

func (s *taprootSignerStub) SignTaproot(sighash []byte) ([]byte, error) {
	var aux [32]byte
	return outscript.BIP340SignForTest(
		secp256k1.NewPrivateKey(s.tweaked),
		sighash, aux[:],
	)
}

func TestP2TRSignWithTaprootSigner(t *testing.T) {
	// Build an internal key, apply the BIP-341 tweak manually, and hand the
	// tweaked scalar to a TaprootSigner implementation. The library should
	// skip its own scalar-tweak path and just ask the signer for the sig.
	privBytes, _ := hex.DecodeString("0202020202020202020202020202020202020202020202020202020202020202")
	priv := secp256k1.PrivKeyFromBytes(privBytes)
	pub := priv.PubKey().SerializeCompressed()

	tweakedX, parity, err := outscript.TaprootTweak(pub[1:])
	if err != nil {
		t.Fatalf("tweak: %v", err)
	}

	// Reproduce the same scalar math p2trSign would have done internally,
	// to simulate what a TSS layer is expected to hold.
	var d secp256k1.ModNScalar
	d.Set(&priv.Key)
	if pub[0] == 0x03 {
		d.Negate()
	}
	// t = hashTapTweak(P.x)
	taggedTweak := sha256Tagged("TapTweak", pub[1:])
	var tScalar secp256k1.ModNScalar
	tScalar.SetByteSlice(taggedTweak)
	d.Add(&tScalar)
	if parity == 1 {
		d.Negate()
	}

	// Tweaked public key (for the stub's Public() — not actually used by
	// the library on the TaprootSigner path, but good hygiene).
	tweakedPub, _ := secp256k1.ParsePubKey(append([]byte{0x02}, tweakedX...))

	signer := &taprootSignerStub{tweaked: &d, pub: tweakedPub}

	scriptPubKey := append([]byte{0x51, 0x20}, tweakedX...)
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
		Key:        signer,
		Scheme:     "p2tr",
		Amount:     outscript.BtcAmount(100000),
		PrevScript: scriptPubKey,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(tx.In[0].Witnesses) != 1 || len(tx.In[0].Witnesses[0]) != 64 {
		t.Fatalf("witness shape wrong: %v", tx.In[0].Witnesses)
	}

	keys := []*outscript.BtcTxSign{{
		Amount:     outscript.BtcAmount(100000),
		PrevScript: scriptPubKey,
	}}
	digest, err := tx.TaprootSighash(keys, 0)
	if err != nil {
		t.Fatalf("sighash: %v", err)
	}
	ok, err := outscript.BIP340VerifyForTest(tweakedX, digest, tx.In[0].Witnesses[0])
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Error("TaprootSigner path produced an invalid signature")
	}
}

// sha256Tagged recomputes BIP-340's TaggedHash in the test to keep the stub
// self-contained (the library exposes TaprootTweak but not the tagged-hash
// helper directly).
func sha256Tagged(tag string, data ...[]byte) []byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

func TestP2TRPrefill(t *testing.T) {
	// Prefill("p2tr") must produce the exact witness shape that a real
	// signature yields: one 64-byte item. We then check that ComputeSize
	// matches the size after a real Sign.
	privBytes, _ := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101")
	priv := secp256k1.PrivKeyFromBytes(privBytes)
	s := outscript.New(priv.PubKey())
	scriptPubKey, _ := s.Generate("p2tr")

	build := func() *outscript.BtcTx {
		return &outscript.BtcTx{
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
	}

	txEst := build()
	if err := txEst.In[0].Prefill("p2tr"); err != nil {
		t.Fatalf("Prefill(p2tr): %v", err)
	}
	if n := len(txEst.In[0].Witnesses); n != 1 {
		t.Fatalf("prefill witness count = %d, want 1", n)
	}
	if n := len(txEst.In[0].Witnesses[0]); n != 64 {
		t.Fatalf("prefill sig len = %d, want 64", n)
	}
	estimated := txEst.ComputeSize()

	txSig := build()
	err := txSig.Sign(&outscript.BtcTxSign{
		Key:        priv,
		Scheme:     "p2tr",
		Amount:     outscript.BtcAmount(100000),
		PrevScript: scriptPubKey,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	actual := txSig.ComputeSize()

	if estimated != actual {
		t.Errorf("p2tr ComputeSize mismatch: prefill=%d signed=%d", estimated, actual)
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
