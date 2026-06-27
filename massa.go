package outscript

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"slices"
	"strings"

	"github.com/BottleFmt/gobottle"
	"github.com/KarpelesLab/base58"
	"lukechampine.com/blake3"
)

func newMassaHash() hash.Hash {
	return blake3.New(32, nil)
}

// ParseMassaAddress parses a Massa network address (starting with "AU" for user accounts
// or "AS" for smart contracts) and returns the corresponding [Out].
func ParseMassaAddress(address string) (*Out, error) {
	if !strings.HasPrefix(address, "AU") && !strings.HasPrefix(address, "AS") {
		return nil, errors.New("massa address must start with AU or AS")
	}

	var typ byte
	switch address[1] {
	case 'U':
		typ = 0
	case 'S':
		typ = 1
	}

	// decode base58 code
	buf, err := base58.Bitcoin.Decode(address[2:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode massa address: %w", err)
	}
	// require at least the 4 checksum bytes before slicing
	if len(buf) < 4 {
		return nil, errors.New("massa address too short")
	}
	// check hash
	chk := buf[len(buf)-4:]
	buf = buf[:len(buf)-4]
	h := gobottle.Hash(buf, sha256.New, sha256.New)
	if subtle.ConstantTimeCompare(h[:4], chk) != 1 {
		return nil, errors.New("bad checksum on massa address")
	}

	// prepend typ
	buf = slices.Concat([]byte{typ}, buf)

	return &Out{Name: "massa", Script: hex.EncodeToString(buf), raw: buf, Flags: []string{"massa"}}, nil
}
