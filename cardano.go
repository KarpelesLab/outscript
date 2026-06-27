package outscript

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"slices"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// Cardano (Shelley-era) addresses encode a 1-byte header followed by one or two
// 28-byte credentials. The header's high 4 bits select the address type and the
// low 4 bits carry the network id (0 = testnet, 1 = mainnet). Credentials for
// key-based addresses are the blake2b-224 hash of the raw 32-byte Ed25519 public
// key. The whole payload is then Bech32-encoded (BIP-173, not Bech32m).
//
// See CIP-19 (https://cips.cardano.org/cip/CIP-19) for the binary format.
const (
	// address type nibbles (high 4 bits of the header byte)
	cardanoTypeBase       = 0x0 // payment key hash + stake key hash
	cardanoTypeEnterprise = 0x6 // payment key hash only
	cardanoTypeReward     = 0xe // stake key hash only (reward/account address)

	// network ids (low 4 bits of the header byte)
	cardanoNetTestnet = 0x0
	cardanoNetMainnet = 0x1
)

// newCardanoHash returns a blake2b-224 hash, the function used to derive Cardano
// key credentials from public keys.
func newCardanoHash() hash.Hash {
	h, err := blake2b.New(28, nil)
	if err != nil {
		// blake2b.New only errors on an invalid size or key; 28 with no key is always valid.
		panic(err)
	}
	return h
}

// CardanoKeyHash returns the 28-byte blake2b-224 credential for an Ed25519 public
// key, as used in Cardano payment and stake credentials.
func CardanoKeyHash(pubkey ed25519.PublicKey) []byte {
	h := newCardanoHash()
	h.Write(pubkey)
	return h.Sum(nil)
}

// cardanoNetwork maps a network flag to its network id nibble.
func cardanoNetwork(network string) (byte, error) {
	switch network {
	case "", "cardano", "cardano-mainnet", "mainnet":
		return cardanoNetMainnet, nil
	case "cardano-testnet", "testnet":
		return cardanoNetTestnet, nil
	default:
		return 0, fmt.Errorf("unsupported cardano network %q", network)
	}
}

// cardanoHRP returns the Bech32 human-readable prefix for a given address type
// nibble and network id.
func cardanoHRP(typ, net byte) string {
	var hrp string
	switch typ {
	case cardanoTypeReward:
		hrp = "stake"
	default:
		hrp = "addr"
	}
	if net == cardanoNetTestnet {
		hrp += "_test"
	}
	return hrp
}

// cardanoEncodeAddress Bech32-encodes a full address payload (header byte followed
// by its credentials). The header byte determines the human-readable prefix.
func cardanoEncodeAddress(payload []byte) (string, error) {
	if len(payload) == 0 {
		return "", errors.New("empty cardano address payload")
	}
	hrp := cardanoHRP(payload[0]>>4, payload[0]&0x0f)
	data, err := cardanoConvertBits(payload, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32Encode(hrp, data), nil
}

// CardanoEnterpriseAddress builds a type-6 enterprise address (payment credential
// only) from a 28-byte payment key hash.
func CardanoEnterpriseAddress(paymentKeyHash []byte, network string) (string, error) {
	if len(paymentKeyHash) != 28 {
		return "", fmt.Errorf("cardano payment key hash must be 28 bytes, got %d", len(paymentKeyHash))
	}
	net, err := cardanoNetwork(network)
	if err != nil {
		return "", err
	}
	header := byte(cardanoTypeEnterprise<<4) | net
	return cardanoEncodeAddress(slices.Concat([]byte{header}, paymentKeyHash))
}

// CardanoBaseAddress builds a type-0 base address (payment credential + stake
// credential) from two 28-byte key hashes.
func CardanoBaseAddress(paymentKeyHash, stakeKeyHash []byte, network string) (string, error) {
	if len(paymentKeyHash) != 28 {
		return "", fmt.Errorf("cardano payment key hash must be 28 bytes, got %d", len(paymentKeyHash))
	}
	if len(stakeKeyHash) != 28 {
		return "", fmt.Errorf("cardano stake key hash must be 28 bytes, got %d", len(stakeKeyHash))
	}
	net, err := cardanoNetwork(network)
	if err != nil {
		return "", err
	}
	header := byte(cardanoTypeBase<<4) | net
	return cardanoEncodeAddress(slices.Concat([]byte{header}, paymentKeyHash, stakeKeyHash))
}

// CardanoRewardAddress builds a type-14 reward (stake/account) address from a
// 28-byte stake key hash.
func CardanoRewardAddress(stakeKeyHash []byte, network string) (string, error) {
	if len(stakeKeyHash) != 28 {
		return "", fmt.Errorf("cardano stake key hash must be 28 bytes, got %d", len(stakeKeyHash))
	}
	net, err := cardanoNetwork(network)
	if err != nil {
		return "", err
	}
	header := byte(cardanoTypeReward<<4) | net
	return cardanoEncodeAddress(slices.Concat([]byte{header}, stakeKeyHash))
}

// ParseCardanoAddress parses a Bech32-encoded Cardano Shelley address (addr…,
// addr_test…, stake…, stake_test…) and returns the corresponding [Out]. The raw
// payload (header byte followed by credentials) is preserved so the address can
// be re-encoded via [Out.Address].
func ParseCardanoAddress(address string) (*Out, error) {
	hrp, data, err := bech32Decode(address)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cardano address: %w", err)
	}
	switch hrp {
	case "addr", "addr_test", "stake", "stake_test":
		// ok
	default:
		return nil, fmt.Errorf("unsupported cardano address prefix %q", hrp)
	}
	payload, err := cardanoConvertBits(data, 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cardano address payload: %w", err)
	}
	if len(payload) == 0 {
		return nil, errors.New("empty cardano address payload")
	}

	header := payload[0]
	typ := header >> 4
	net := header & 0x0f
	if net != cardanoNetMainnet && net != cardanoNetTestnet {
		return nil, fmt.Errorf("unsupported cardano network id %d", net)
	}

	var wantLen int
	switch typ {
	case cardanoTypeBase:
		wantLen = 1 + 28 + 28
	case cardanoTypeEnterprise, cardanoTypeReward:
		wantLen = 1 + 28
	default:
		return nil, fmt.Errorf("unsupported cardano address type %d", typ)
	}
	if len(payload) != wantLen {
		return nil, fmt.Errorf("invalid cardano address length %d for type %d", len(payload), typ)
	}

	flag := "cardano"
	if net == cardanoNetTestnet {
		flag = "cardano-testnet"
	}
	return &Out{Name: "cardano", Script: hex.EncodeToString(payload), raw: payload, Flags: []string{flag}}, nil
}

// cardanoConvertBits regroups data between bit widths (8↔5) for Bech32 encoding,
// following the reference convertbits routine from BIP-173.
func cardanoConvertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	var acc uint32
	var bits uint
	out := make([]byte, 0, len(data)*int(fromBits)/int(toBits)+1)
	maxv := byte((1 << toBits) - 1)
	maxAcc := uint32(1<<(fromBits+toBits-1)) - 1
	for _, value := range data {
		if (uint32(value) >> fromBits) != 0 {
			return nil, fmt.Errorf("invalid data value %d for %d-bit groups", value, fromBits)
		}
		acc = ((acc << fromBits) | uint32(value)) & maxAcc
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte(acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(toBits-bits))&maxv)
		}
	} else if bits >= fromBits || (byte(acc<<(toBits-bits))&maxv) != 0 {
		return nil, errors.New("invalid padding in bit conversion")
	}
	return out, nil
}

// cardanoAddressFromOut renders a Cardano address for a parsed or generated
// [Out] whose raw payload is "header byte + credentials". The network flag
// overrides the header's network nibble so the same Out can produce mainnet or
// testnet forms.
func cardanoAddressFromOut(raw []byte, network string) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("empty cardano out")
	}
	net, err := cardanoNetwork(network)
	if err != nil {
		return "", err
	}
	payload := slices.Clone(raw)
	payload[0] = (payload[0] & 0xf0) | net
	return cardanoEncodeAddress(payload)
}

// Bech32 (BIP-173) implementation. Unlike the shared bech32m package, this has no
// 90-character limit, which Cardano addresses (per CIP-19) routinely exceed.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&0x1f)
	}
	return out
}

func bech32CreateChecksum(hrp string, data []byte) []byte {
	values := slices.Concat(bech32HrpExpand(hrp), data, []byte{0, 0, 0, 0, 0, 0})
	polymod := bech32Polymod(values) ^ 1
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[i] = byte(polymod>>uint(5*(5-i))) & 0x1f
	}
	return out
}

func bech32Encode(hrp string, data []byte) string {
	checksum := bech32CreateChecksum(hrp, data)
	var sb strings.Builder
	sb.Grow(len(hrp) + 1 + len(data) + 6)
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, b := range slices.Concat(data, checksum) {
		sb.WriteByte(bech32Charset[b])
	}
	return sb.String()
}

func bech32Decode(s string) (string, []byte, error) {
	lower, upper := strings.ToLower(s), strings.ToUpper(s)
	if s != lower && s != upper {
		return "", nil, errors.New("bech32 string must not be mixed-case")
	}
	s = lower
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, errors.New("invalid bech32 separator position")
	}
	hrp := s[:pos]
	data := make([]byte, 0, len(s)-pos-1)
	for i := pos + 1; i < len(s); i++ {
		idx := strings.IndexByte(bech32Charset, s[i])
		if idx < 0 {
			return "", nil, fmt.Errorf("invalid bech32 character %q", s[i])
		}
		data = append(data, byte(idx))
	}
	if bech32Polymod(slices.Concat(bech32HrpExpand(hrp), data)) != 1 {
		return "", nil, errors.New("invalid bech32 checksum")
	}
	return hrp, data[:len(data)-6], nil
}
