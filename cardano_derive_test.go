package outscript_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/outscript"
)

func decodeHexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %s", err)
	}
	return b
}

// Authoritative V2 derivation vectors from typed-io/rust-ed25519-bip32 (the crate
// used by cardano-serialization-lib): parent key D1, its hardened child at index
// 0x80000000 (D1_H0), and D1_H0's signature over "Hello World".
const (
	d1         = "f8a29231ee38d6c5bf715d5bac21c750577aa3798b22d79d65bf97d6fadea15adcd1ee1abdf78bd4be64731a12deb94d3671784112eb6f364b871851fd1c9a247384db9ad6003bbd08b3b1ddc0d07a597293ff85e961bf252b331262eddfad0d"
	d1H0       = "60d399da83ef80d8d4f8d223239efdc2b8fef387e1b5219137ffb4e8fbdea15adc9366b7d003af37c11396de9a83734e30e05e851efa32745c9cd7b42712c890608763770eddf77248ab652984b21b849760d1da74a6f5bd633ce41adceef07a"
	d1H0SigHex = "90194d57cde4fdadd01eb7cf161780c277e129fc7135b97779a3268837e4cd2e9444b9bb91c0e84d23bba870df3c4bda91a110ef735638fa7a34ea2046d4be04"
)

// TestCardanoDeriveHardenedVector checks private hardened (V2) derivation against
// the authoritative D1 -> D1_H0 vector at index 0x80000000.
func TestCardanoDeriveHardenedVector(t *testing.T) {
	parent, err := outscript.NewCardanoExtendedKey(decodeHexT(t, d1))
	if err != nil {
		t.Fatalf("NewCardanoExtendedKey: %s", err)
	}
	child, err := parent.DeriveChild(0x80000000)
	if err != nil {
		t.Fatalf("DeriveChild: %s", err)
	}
	if got, want := hex.EncodeToString(child.Bytes()), d1H0; got != want {
		t.Errorf("derived child mismatch:\n got %s\nwant %s", got, want)
	}
}

// TestCardanoDerivedKeySignsVector checks that signing with the derived key D1_H0
// reproduces its authoritative signature over "Hello World".
func TestCardanoDerivedKeySignsVector(t *testing.T) {
	ek, err := outscript.NewCardanoExtendedKey(decodeHexT(t, d1H0)[:64])
	if err != nil {
		t.Fatalf("NewCardanoExtendedKey: %s", err)
	}
	sig, err := ek.SignCardano([]byte("Hello World"))
	if err != nil {
		t.Fatalf("SignCardano: %s", err)
	}
	if got := hex.EncodeToString(sig); got != d1H0SigHex {
		t.Errorf("signature mismatch:\n got %s\nwant %s", got, d1H0SigHex)
	}
}

// TestCardanoIcarusEndToEnd validates the whole chain — Icarus master key, three
// hardened + two soft derivations, public key, blake2b-224, and address encoding
// — against cardano-serialization-lib's own test vectors for the recovery phrase
// "test walk nut penalty hip pave soap entry language right filter choice".
func TestCardanoIcarusEndToEnd(t *testing.T) {
	entropy := decodeHexT(t, "df9ed25ed146bf43336a5d7cf7395994")
	master, err := outscript.CardanoIcarusMasterKey(entropy, nil)
	if err != nil {
		t.Fatalf("CardanoIcarusMasterKey: %s", err)
	}

	H := outscript.CardanoHarden
	spend, err := master.DerivePath(H(1852), H(1815), H(0), 0, 0)
	if err != nil {
		t.Fatalf("derive spend: %s", err)
	}
	stake, err := master.DerivePath(H(1852), H(1815), H(0), 2, 0)
	if err != nil {
		t.Fatalf("derive stake: %s", err)
	}

	spendHash := outscript.CardanoKeyHash(ed25519.PublicKey(spend.CardanoPublicKey()))
	stakeHash := outscript.CardanoKeyHash(ed25519.PublicKey(stake.CardanoPublicKey()))

	// the spend key is the same one used in the CIP-19 address tests
	if got := hex.EncodeToString(spendHash); got != "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e" {
		t.Fatalf("spend key hash mismatch: %s", got)
	}

	check := func(name, got, want string) {
		if got != want {
			t.Errorf("%s:\n got %s\nwant %s", name, got, want)
		}
	}
	entMain, _ := outscript.CardanoEnterpriseAddress(spendHash, "cardano")
	check("enterprise mainnet", entMain, "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8")
	entTest, _ := outscript.CardanoEnterpriseAddress(spendHash, "cardano-testnet")
	check("enterprise testnet", entTest, "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz")
	baseMain, _ := outscript.CardanoBaseAddress(spendHash, stakeHash, "cardano")
	check("base mainnet", baseMain, "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwqfjkjv7")
	baseTest, _ := outscript.CardanoBaseAddress(spendHash, stakeHash, "cardano-testnet")
	check("base testnet", baseTest, "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp")
}

// TestCardanoPublicDerivationMatchesPrivate validates the watch-only (public-key)
// soft derivation path — which uses the new edwards25519.Add — by checking it
// arrives at the same public key as the private derivation, which is itself
// ground-truthed by the end-to-end vector above.
func TestCardanoPublicDerivationMatchesPrivate(t *testing.T) {
	entropy := decodeHexT(t, "df9ed25ed146bf43336a5d7cf7395994")
	master, err := outscript.CardanoIcarusMasterKey(entropy, nil)
	if err != nil {
		t.Fatalf("CardanoIcarusMasterKey: %s", err)
	}
	H := outscript.CardanoHarden

	// account/role level (m/1852'/1815'/0'/0), still private so we hold an xpub
	role, err := master.DerivePath(H(1852), H(1815), H(0), 0)
	if err != nil {
		t.Fatalf("derive role: %s", err)
	}
	xpub := role.ExtendedPublicKey()
	if xpub == nil {
		t.Fatal("ExtendedPublicKey returned nil")
	}

	for _, idx := range []uint32{0, 1, 5, 100} {
		priv, err := role.DeriveChild(idx)
		if err != nil {
			t.Fatalf("private DeriveChild(%d): %s", idx, err)
		}
		pub, err := xpub.DeriveChild(idx)
		if err != nil {
			t.Fatalf("public DeriveChild(%d): %s", idx, err)
		}
		if !bytes.Equal(priv.CardanoPublicKey(), pub.PublicKey()) {
			t.Errorf("index %d: public-path pubkey != private-path pubkey:\n pub  %s\n priv %s",
				idx, hex.EncodeToString(pub.PublicKey()), hex.EncodeToString(priv.CardanoPublicKey()))
		}
	}

	// hardened public derivation must be rejected
	if _, err := xpub.DeriveChild(H(0)); err == nil {
		t.Error("expected error deriving hardened child from public key")
	}
}
