package outscript

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/BottleFmt/gobottle"
	"github.com/KarpelesLab/base58"
)

// tronAddressPrefix is the version byte prepended to the 20-byte account hash of
// a Tron mainnet address before Base58Check encoding. It makes every Tron
// address start with the letter "T".
const tronAddressPrefix = 0x41

// EncodeTronAddress Base58Check-encodes a 21-byte raw Tron address (the 0x41
// prefix followed by the 20-byte account hash) into its "T..." string form.
func EncodeTronAddress(raw []byte) string {
	h := gobottle.Hash(raw, sha256.New, sha256.New)
	return base58.Bitcoin.Encode(slices.Concat(raw, h[:4]))
}

// DecodeTronAddress decodes a Base58Check "T..." Tron address into its 21-byte
// raw form (0x41 prefix followed by the 20-byte account hash), verifying the
// checksum, length and prefix.
func DecodeTronAddress(address string) ([]byte, error) {
	buf, err := base58.Bitcoin.Decode(address)
	if err != nil {
		return nil, fmt.Errorf("failed to decode tron address: %w", err)
	}
	// 21-byte payload + 4-byte checksum
	if len(buf) != 25 {
		return nil, fmt.Errorf("invalid tron address length %d, expected 25", len(buf))
	}
	payload := buf[:21]
	chk := buf[21:]
	h := gobottle.Hash(payload, sha256.New, sha256.New)
	if subtle.ConstantTimeCompare(h[:4], chk) != 1 {
		return nil, errors.New("bad checksum on tron address")
	}
	if payload[0] != tronAddressPrefix {
		return nil, fmt.Errorf("invalid tron address prefix 0x%02x, expected 0x41", payload[0])
	}
	return payload, nil
}

// ParseTronAddress parses a Base58Check "T..." Tron address and returns the
// matching Out.
func ParseTronAddress(address string) (*Out, error) {
	raw, err := DecodeTronAddress(address)
	if err != nil {
		return nil, err
	}
	return &Out{Name: "tron", Script: hex.EncodeToString(raw), raw: raw, Flags: []string{"tron"}}, nil
}
