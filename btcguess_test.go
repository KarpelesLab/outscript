package outscript_test

import (
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestGuessOut(t *testing.T) {
	// 76a9149e8985f82bc4e0f753d0492aa8d11cc39925774088ac
	a, b := outscript.GuessPubKeyAndHashByOutScript(must(hex.DecodeString("76a9149e8985f82bc4e0f753d0492aa8d11cc39925774088ac")))

	if a != nil || hex.EncodeToString(b) != "9e8985f82bc4e0f753d0492aa8d11cc399257740" {
		t.Errorf("invalid result for GuessPubKeyAndHashByOutScript")
	}
}

func TestGuessInScriptInvalidPubKey(t *testing.T) {
	// A two-push input script whose second push is NOT a valid secp256k1 pubkey
	// must not be misclassified as P2PKH.
	// push1 = 3 bytes (0x010203), push2 = 3 bytes (0x040506) -> push2 has invalid shape.
	script := must(hex.DecodeString("03010203" + "03040506"))
	pub, hash := outscript.GuessPubKeyAndHashByInScript(script)
	if pub != nil || hash != nil {
		t.Errorf("expected nil,nil for invalid pubkey shape, got %x,%x", pub, hash)
	}

	// Sanity check: a valid 33-byte compressed pubkey is still accepted.
	validPub := "02" + "0000000000000000000000000000000000000000000000000000000000000001"
	good := must(hex.DecodeString("03010203" + "21" + validPub))
	pub2, hash2 := outscript.GuessPubKeyAndHashByInScript(good)
	if pub2 == nil || hash2 == nil {
		t.Errorf("expected a valid pubkey to be accepted")
	}
}
