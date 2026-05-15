package outscript_test

import (
	"bytes"
	"encoding/hex"
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
	sig, err := outscript.ExtractBtcInputSig(tx.In[1].Script, tx.In[1].Witnesses)
	if err != nil {
		t.Fatalf("extract: %s", err)
	}
	if sig == nil {
		t.Fatal("extract returned nil for p2wpkh input")
	}
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

	// One input spending a P2PKH output, one P2PKH output.
	txHex := strings.Join([]string{
		"01000000", // version
		"01",       // num txIn
		"0000000000000000000000000000000000000000000000000000000000000001", "00000000", "00", "ffffffff",
		"01",                 // num txOut
		"a086010000000000",   // value 100000
		"1976a914",           // OP_DUP OP_HASH160 <20>
		"00112233445566778899aabbccddeeff00112233",
		"88ac",
		"00000000", // locktime
	}, "")

	tx := &outscript.BtcTx{}
	if _, err := tx.ReadFrom(bytes.NewReader(must(hex.DecodeString(txHex)))); err != nil {
		t.Fatalf("read: %s", err)
	}

	if err := tx.Sign(&outscript.BtcTxSign{Key: key, Scheme: "p2pkh"}); err != nil {
		t.Fatalf("sign: %s", err)
	}

	sig, err := outscript.ExtractBtcInputSig(tx.In[0].Script, tx.In[0].Witnesses)
	if err != nil {
		t.Fatalf("extract: %s", err)
	}
	if sig == nil {
		t.Fatal("extract returned nil for p2pkh input")
	}
	if sig.Scheme != "p2pkh" {
		t.Errorf("scheme: got %q, want p2pkh", sig.Scheme)
	}

	digest, err := tx.InputSighash(0, sig, prevScript, 0)
	if err != nil {
		t.Fatalf("sighash: %s", err)
	}

	// Recover the DER bytes (scriptSig is push(sig) push(pubkey)).
	pushed, _ := outscript.ParsePushBytes(tx.In[0].Script)
	parsed, err := secp256k1.ParseDERSignature(pushed[:len(pushed)-1])
	if err != nil {
		t.Fatalf("parse der: %s", err)
	}
	if !parsed.Verify(digest, key.PubKey()) {
		t.Errorf("signature failed to verify against recomputed p2pkh sighash")
	}
}

// TestExtractInputSigUnsupported confirms non-p2pkh/p2wpkh inputs return (nil, nil).
func TestExtractInputSigUnsupported(t *testing.T) {
	// taproot-style: 1-element witness
	sig, err := outscript.ExtractBtcInputSig(nil, [][]byte{{0x00, 0x01, 0x02}})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if sig != nil {
		t.Errorf("expected nil for taproot-style input, got %+v", sig)
	}
}
