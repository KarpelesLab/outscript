package outscript_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/KarpelesLab/outscript"
	"github.com/KarpelesLab/secp256k1"
)

// TestExtractAndVerifyP2WPKH signs a tx with p2wpkh, then re-extracts r/s and
// recomputes the sighash via the new helpers and verifies the signature.
func TestExtractAndVerifyP2WPKH(t *testing.T) {
	// Same key/tx setup as TestBtxTxP2WPKH (BIP-143 test vector).
	key1 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")))

	txHex := strings.Join([]string{
		"01000000", // version
		"02",       // num txIn
		"fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f", "00000000", "00", "eeffffff",
		"ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a", "01000000", "00", "ffffffff",
		"02",
		"202cb20600000000", "1976a914", "8280b37df378db99f66f85c95a783a76ac7a6d59", "88ac",
		"9093510d00000000", "1976a914", "3bde42dbee7e4dbe6a21b2d50ce2f0167faa8159", "88ac",
		"11000000",
	}, "")

	tx := &outscript.BtcTx{}
	if _, err := tx.ReadFrom(bytes.NewReader(must(hex.DecodeString(txHex)))); err != nil {
		t.Fatalf("read: %s", err)
	}

	key0 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866")))
	if err := tx.Sign(
		&outscript.BtcTxSign{Key: key0, Scheme: "p2pk"},
		&outscript.BtcTxSign{Key: key1, Scheme: "p2wpkh", Amount: 600000000},
	); err != nil {
		t.Fatalf("sign: %s", err)
	}

	// Input 1 is p2wpkh; extract the signature and verify against our sighash.
	sigs, err := outscript.ExtractBtcInputSig(tx.In[1].Script, tx.In[1].Witnesses)
	if err != nil {
		t.Fatalf("extract: %s", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 sig, got %d", len(sigs))
	}
	sig := sigs[0]
	if sig.Scheme != "p2wpkh" {
		t.Errorf("scheme: got %q, want p2wpkh", sig.Scheme)
	}
	if sig.SigHashFlag != 1 {
		t.Errorf("sighash flag: got %d, want 1", sig.SigHashFlag)
	}

	digest, err := tx.InputSighash(1, sig, nil, 600000000)
	if err != nil {
		t.Fatalf("sighash: %s", err)
	}

	// Reconstruct an ECDSA signature object from r/s and verify it.
	derSig := tx.In[1].Witnesses[0]
	parsed, err := secp256k1.ParseDERSignature(derSig[:len(derSig)-1])
	if err != nil {
		t.Fatalf("parse der: %s", err)
	}
	if !parsed.Verify(digest, key1.PubKey()) {
		t.Errorf("signature failed to verify against recomputed sighash")
	}
}

// TestExtractAndVerifyP2PKH builds a single-input p2pkh tx, signs it, then
// extracts r/s, recomputes the sighash, and verifies.
func TestExtractAndVerifyP2PKH(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866")))

	prevScript, err := outscript.New(key.PubKey()).Generate("p2pkh")
	if err != nil {
		t.Fatalf("p2pkh script: %s", err)
	}

	txHex := strings.Join([]string{
		"01000000", // version
		"01",       // num txIn
		"0000000000000000000000000000000000000000000000000000000000000001", "00000000", "00", "ffffffff",
		"01",               // num txOut
		"a086010000000000", // value 100000
		"1976a914",         // OP_DUP OP_HASH160 <20>
		"00112233445566778899aabbccddeeff00112233",
		"88ac",
		"00000000",
	}, "")

	tx := &outscript.BtcTx{}
	if _, err := tx.ReadFrom(bytes.NewReader(must(hex.DecodeString(txHex)))); err != nil {
		t.Fatalf("read: %s", err)
	}

	if err := tx.Sign(&outscript.BtcTxSign{Key: key, Scheme: "p2pkh"}); err != nil {
		t.Fatalf("sign: %s", err)
	}

	sigs, err := outscript.ExtractBtcInputSig(tx.In[0].Script, tx.In[0].Witnesses)
	if err != nil {
		t.Fatalf("extract: %s", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 sig, got %d", len(sigs))
	}
	sig := sigs[0]
	if sig.Scheme != "p2pkh" {
		t.Errorf("scheme: got %q, want p2pkh", sig.Scheme)
	}

	digest, err := tx.InputSighash(0, sig, prevScript, 0)
	if err != nil {
		t.Fatalf("sighash: %s", err)
	}

	pushed, _ := outscript.ParsePushBytes(tx.In[0].Script)
	parsed, err := secp256k1.ParseDERSignature(pushed[:len(pushed)-1])
	if err != nil {
		t.Fatalf("parse der: %s", err)
	}
	if !parsed.Verify(digest, key.PubKey()) {
		t.Errorf("signature failed to verify against recomputed p2pkh sighash")
	}
}

// TestExtractInputSigUnsupported confirms non-recognized inputs return nil.
func TestExtractInputSigUnsupported(t *testing.T) {
	sigs, err := outscript.ExtractBtcInputSig(nil, [][]byte{{0x00, 0x01, 0x02}})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if sigs != nil {
		t.Errorf("expected nil for taproot-style input, got %+v", sigs)
	}
}

// TestExtractAndVerifyP2TRKeyPath signs a P2TR key-path tx via outscript.Sign,
// re-extracts the Schnorr sig via ExtractBtcInputSig, recomputes the BIP-341
// sighash with TaprootInputSighash, and verifies the signature.
func TestExtractAndVerifyP2TRKeyPath(t *testing.T) {
	privBytes := must(hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101"))
	priv := secp256k1.PrivKeyFromBytes(privBytes)
	scriptPubKey, err := outscript.New(priv.PubKey()).Generate("p2tr")
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

	if err := tx.Sign(&outscript.BtcTxSign{
		Key:        priv,
		Scheme:     "p2tr",
		Amount:     outscript.BtcAmount(100000),
		PrevScript: scriptPubKey,
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	sigs, err := outscript.ExtractBtcInputSig(tx.In[0].Script, tx.In[0].Witnesses)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(sigs) != 1 || sigs[0].Scheme != "p2tr-keypath" {
		t.Fatalf("expected 1 p2tr-keypath sig, got %+v", sigs)
	}
	sig := sigs[0]
	if sig.SigHashFlag != 0 {
		t.Errorf("sighash flag: got %d, want 0 (default)", sig.SigHashFlag)
	}

	// PubKey is not set by Extract for key-path; the caller fills it from the
	// prev_out scriptPubKey: OP_1 PUSH32 <xpk>.
	sig.PubKey = scriptPubKey[2:]

	digest, err := tx.TaprootInputSighash(0, sig,
		[][]byte{scriptPubKey},
		[]outscript.BtcAmount{100000},
	)
	if err != nil {
		t.Fatalf("sighash: %v", err)
	}

	// The 64-byte witness sig must verify against the tweaked output key.
	ok, err := outscript.BIP340VerifyForTest(scriptPubKey[2:], digest, tx.In[0].Witnesses[0])
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Error("recomputed sighash does not match the signature")
	}
}

// TestExtractAndVerifyP2TRScriptPath manually constructs a script-path witness
// (outscript has no script-path signer), then round-trips it: extract, recompute
// sighash, verify the schnorr sig over the recomputed sighash.
func TestExtractAndVerifyP2TRScriptPath(t *testing.T) {
	privBytes := must(hex.DecodeString("0303030303030303030303030303030303030303030303030303030303030303"))
	priv := secp256k1.PrivKeyFromBytes(privBytes)
	pubComp, _ := outscript.New(priv.PubKey()).Generate("pubkey:comp")
	xpk := pubComp[1:] // x-only pubkey (32 bytes)

	// Tapleaf script: PUSH32 <xpk> OP_CHECKSIG
	leafScript := slices.Concat([]byte{0x20}, xpk, []byte{0xac})

	// A throwaway prev_out scriptPubKey ("OP_1 <push32 32-zero bytes>") — the
	// content doesn't have to be a real taproot output for this test because
	// BIP-341 only uses it via the shaScriptPubs commitment.
	prevScript := slices.Concat([]byte{0x51, 0x20}, make([]byte, 32))

	tx := &outscript.BtcTx{
		Version: 2,
		In: []*outscript.BtcTxInput{{
			Vout:     0,
			Sequence: 0xffffffff,
		}},
		Out: []*outscript.BtcTxOutput{{
			Amount: outscript.BtcAmount(90000),
			Script: prevScript,
		}},
	}

	// Compute the script-path sighash; we use a stub BtcInputSig that carries
	// only the leaf script — the SigHashFlag must be 0 (SIGHASH_DEFAULT).
	stub := &outscript.BtcInputSig{
		Scheme:      "p2tr-scriptpath",
		SigHashFlag: 0,
		LeafScript:  leafScript,
	}
	digest, err := tx.TaprootInputSighash(0, stub,
		[][]byte{prevScript},
		[]outscript.BtcAmount{100000},
	)
	if err != nil {
		t.Fatalf("sighash: %v", err)
	}

	// BIP-340 sign the digest with the internal key (no taproot tweak — the
	// signer of a script-path uses the raw x-only key from the leaf).
	var aux [32]byte
	sig, err := outscript.BIP340SignForTest(priv, digest, aux[:])
	if err != nil {
		t.Fatalf("schnorr sign: %v", err)
	}

	// Build a fabricated control block: 33 bytes, leaf version 0xc0, parity 0,
	// and a 32-byte zero internal pubkey. (Not a valid commitment, but the
	// sighash computation doesn't validate it.)
	controlBlock := slices.Concat([]byte{0xc0}, make([]byte, 32))

	witness := [][]byte{sig, leafScript, controlBlock}

	// Extract and verify.
	sigs, err := outscript.ExtractBtcInputSig(nil, witness)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(sigs) != 1 || sigs[0].Scheme != "p2tr-scriptpath" {
		t.Fatalf("expected 1 p2tr-scriptpath sig, got %+v", sigs)
	}
	got := sigs[0]
	if !bytes.Equal(got.PubKey, xpk) {
		t.Errorf("PubKey mismatch: got %x, want %x", got.PubKey, xpk)
	}
	if !bytes.Equal(got.LeafScript, leafScript) {
		t.Errorf("LeafScript mismatch")
	}

	digest2, err := tx.TaprootInputSighash(0, got,
		[][]byte{prevScript},
		[]outscript.BtcAmount{100000},
	)
	if err != nil {
		t.Fatalf("re-sighash: %v", err)
	}
	if !bytes.Equal(digest, digest2) {
		t.Errorf("recomputed digest differs:\n  got  %x\n  want %x", digest2, digest)
	}

	ok, err := outscript.BIP340VerifyForTest(xpk, digest2, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Error("script-path schnorr verify failed")
	}
}

// TestExtractAndVerifyP2SHMultisig constructs a 2-of-2 P2SH-multisig spend
// manually (outscript has no multisig signer), then re-extracts and verifies.
func TestExtractAndVerifyP2SHMultisig(t *testing.T) {
	key0 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866")))
	key1 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")))

	pk0, _ := outscript.New(key0.PubKey()).Generate("pubkey:comp")
	pk1, _ := outscript.New(key1.PubKey()).Generate("pubkey:comp")

	// Redeem script: OP_2 <push pk0> <push pk1> OP_2 OP_CHECKMULTISIG
	redeem := slices.Concat(
		[]byte{0x52}, // OP_2
		outscript.PushBytes(pk0),
		outscript.PushBytes(pk1),
		[]byte{0x52, 0xae}, // OP_2 OP_CHECKMULTISIG
	)

	// Build a tx with one input. The scriptSig is empty for now — we'll fill
	// it after computing the sighash.
	txHex := strings.Join([]string{
		"01000000",
		"01",
		"0000000000000000000000000000000000000000000000000000000000000001", "00000000", "00", "ffffffff",
		"01",
		"a086010000000000",
		"1976a914",
		"00112233445566778899aabbccddeeff00112233",
		"88ac",
		"00000000",
	}, "")

	tx := &outscript.BtcTx{}
	if _, err := tx.ReadFrom(bytes.NewReader(must(hex.DecodeString(txHex)))); err != nil {
		t.Fatalf("read: %s", err)
	}

	// Compute the legacy sighash with redeem script substituted at input 0.
	stub := &outscript.BtcInputSig{
		Scheme:       "p2sh-multisig",
		SigHashFlag:  1,
		RedeemScript: redeem,
	}
	digest, err := tx.InputSighash(0, stub, nil, 0)
	if err != nil {
		t.Fatalf("sighash: %s", err)
	}

	// Sign with both keys.
	sigDER0, err := key0.Sign(nil, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("sign0: %s", err)
	}
	sigDER0 = append(sigDER0, 0x01) // SIGHASH_ALL
	sigDER1, err := key1.Sign(nil, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("sign1: %s", err)
	}
	sigDER1 = append(sigDER1, 0x01)

	// scriptSig: OP_0 <push sig0> <push sig1> <push redeem>
	tx.In[0].Script = slices.Concat(
		[]byte{0x00},
		outscript.PushBytes(sigDER0),
		outscript.PushBytes(sigDER1),
		outscript.PushBytes(redeem),
	)

	// Extract and verify.
	sigs, err := outscript.ExtractBtcInputSig(tx.In[0].Script, nil)
	if err != nil {
		t.Fatalf("extract: %s", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("expected 2 sigs, got %d", len(sigs))
	}
	for i, s := range sigs {
		if s.Scheme != "p2sh-multisig" {
			t.Errorf("sig %d scheme: got %q", i, s.Scheme)
		}
		if !bytes.Equal(s.RedeemScript, redeem) {
			t.Errorf("sig %d redeem script mismatch", i)
		}
		if len(s.Pubkeys) != 2 {
			t.Errorf("sig %d pubkeys: got %d, want 2", i, len(s.Pubkeys))
		}
	}

	got, err := tx.InputSighash(0, sigs[0], nil, 0)
	if err != nil {
		t.Fatalf("re-sighash: %s", err)
	}
	if !bytes.Equal(got, digest) {
		t.Errorf("recomputed sighash differs:\n  got  %x\n  want %x", got, digest)
	}

	// Each sig should verify against the corresponding pubkey from the redeem script.
	parsed0, err := secp256k1.ParseDERSignature(sigDER0[:len(sigDER0)-1])
	if err != nil {
		t.Fatalf("parse der 0: %s", err)
	}
	if !parsed0.Verify(digest, key0.PubKey()) {
		t.Errorf("sig0 does not verify against recomputed digest")
	}
	parsed1, err := secp256k1.ParseDERSignature(sigDER1[:len(sigDER1)-1])
	if err != nil {
		t.Fatalf("parse der 1: %s", err)
	}
	if !parsed1.Verify(digest, key1.PubKey()) {
		t.Errorf("sig1 does not verify against recomputed digest")
	}

	// ResolveMultisigPubKey should pick each signer's pubkey out of the redeem
	// script by trial verification.
	pub0, err := sigs[0].ResolveMultisigPubKey(digest)
	if err != nil {
		t.Fatalf("resolve sig0: %s", err)
	}
	if !bytes.Equal(pub0, pk0) {
		t.Errorf("sig0 resolved to %x, want %x", pub0, pk0)
	}
	pub1, err := sigs[1].ResolveMultisigPubKey(digest)
	if err != nil {
		t.Fatalf("resolve sig1: %s", err)
	}
	if !bytes.Equal(pub1, pk1) {
		t.Errorf("sig1 resolved to %x, want %x", pub1, pk1)
	}
}
