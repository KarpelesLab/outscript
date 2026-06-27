package outscript_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/bech32m"
	"github.com/KarpelesLab/outscript"
)

// decodeBech32Key decodes a CIP-5 bech32 key (e.g. addr_vk1…, stake_vk1…) to its
// raw 32-byte Ed25519 public key.
func decodeBech32Key(t *testing.T, s string) ed25519.PublicKey {
	t.Helper()
	_, data, _, err := bech32m.Decode(s)
	if err != nil {
		t.Fatalf("failed to decode %s: %s", s, err)
	}
	// data is in 5-bit groups; regroup to 8-bit. Reuse a tiny local convertbits.
	buf, err := convertBits5to8(data)
	if err != nil {
		t.Fatalf("convertbits failed for %s: %s", s, err)
	}
	if len(buf) != 32 {
		t.Fatalf("expected 32-byte key from %s, got %d", s, len(buf))
	}
	return ed25519.PublicKey(buf)
}

func convertBits5to8(data []byte) ([]byte, error) {
	var acc uint32
	var bits uint
	out := make([]byte, 0, len(data)*5/8)
	for _, v := range data {
		acc = (acc << 5) | uint32(v&0x1f)
		bits += 5
		for bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits)&0xff)
		}
	}
	return out, nil
}

// CIP-19 reference keys.
const (
	cip19AddrVK  = "addr_vk1w0l2sr2zgfm26ztc6nl9xy8ghsk5sh6ldwemlpmp9xylzy4dtf7st80zhd"
	cip19StakeVK = "stake_vk1px4j0r2fk7ux5p23shz8f3y5y2qam7s954rgf3lg5merqcj6aetsft99wu"
)

func TestCardanoCIP19Vectors(t *testing.T) {
	paymentKey := decodeBech32Key(t, cip19AddrVK)
	stakeKey := decodeBech32Key(t, cip19StakeVK)

	paymentHash := outscript.CardanoKeyHash(paymentKey)
	stakeHash := outscript.CardanoKeyHash(stakeKey)

	t.Logf("payment key hash: %s", hex.EncodeToString(paymentHash))
	t.Logf("stake key hash:   %s", hex.EncodeToString(stakeHash))

	type tc struct {
		name string
		got  func() (string, error)
		want string
	}
	cases := []tc{
		// Mainnet
		{"base mainnet", func() (string, error) { return outscript.CardanoBaseAddress(paymentHash, stakeHash, "cardano") },
			"addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"},
		{"enterprise mainnet", func() (string, error) { return outscript.CardanoEnterpriseAddress(paymentHash, "cardano") },
			"addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"},
		{"reward mainnet", func() (string, error) { return outscript.CardanoRewardAddress(stakeHash, "cardano") },
			"stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"},
		// Testnet
		{"base testnet", func() (string, error) { return outscript.CardanoBaseAddress(paymentHash, stakeHash, "cardano-testnet") },
			"addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae"},
		{"reward testnet", func() (string, error) { return outscript.CardanoRewardAddress(stakeHash, "cardano-testnet") },
			"stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn"},
	}
	for _, c := range cases {
		got, err := c.got()
		if err != nil {
			t.Errorf("%s: error: %s", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
}

func TestCardanoFromPubKey(t *testing.T) {
	paymentKey := decodeBech32Key(t, cip19AddrVK)
	s := outscript.New(paymentKey)

	// default (mainnet) enterprise address via the format
	got, err := s.Address("cardano")
	if err != nil {
		t.Fatalf("Address(cardano): %s", err)
	}
	want := "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"
	if got != want {
		t.Errorf("enterprise mainnet:\n got %s\nwant %s", got, want)
	}

	// testnet enterprise: validate via parse round-trip (same payment hash, net nibble 0)
	gotTest, err := s.Address("cardano", "cardano-testnet")
	if err != nil {
		t.Fatalf("Address(cardano, testnet): %s", err)
	}
	out, err := outscript.ParseCardanoAddress(gotTest)
	if err != nil {
		t.Fatalf("parse testnet enterprise %s: %s", gotTest, err)
	}
	if h := hex.EncodeToString(out.Hash()); h != "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e" {
		t.Errorf("testnet enterprise payment hash mismatch: %s", h)
	}
}

func TestCardanoParseRoundTrip(t *testing.T) {
	addrs := []string{
		"addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x",
		"addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8",
		"stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw",
		"addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae",
		"stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn",
	}
	for _, a := range addrs {
		out, err := outscript.ParseCardanoAddress(a)
		if err != nil {
			t.Errorf("parse %s: %s", a, err)
			continue
		}
		got, err := out.Address()
		if err != nil {
			t.Errorf("re-encode %s: %s", a, err)
			continue
		}
		if got != a {
			t.Errorf("round-trip mismatch:\n got %s\nwant %s", got, a)
		}
	}
}
