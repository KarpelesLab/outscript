package outscript

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

// BtcAmount represents a Bitcoin amount in satoshis (1 BTC = 100,000,000 satoshis).
// It marshals to JSON as a decimal string with 8 decimal places and supports
// unmarshaling from decimal strings, integers, and hex-encoded values.
type BtcAmount uint64

// MarshalJSON encodes the amount as a JSON number with 8 decimal places (e.g. "1.00000000").
func (b BtcAmount) MarshalJSON() ([]byte, error) {
	// return amount as a float, always 8 decimals
	s := strconv.FormatUint(uint64(b), 10)
	ln := len(s)
	if ln <= 8 {
		// add zeroes
		s = strings.Repeat("0", 9-ln) + s
		ln = 9
	}
	// we now know that len(s) >= 9, cut it so we add a zero
	s = s[:ln-8] + "." + s[ln-8:]
	return []byte(s), nil
}

// UnmarshalJSON decodes a JSON number or quoted string into a BtcAmount.
func (ba *BtcAmount) UnmarshalJSON(b []byte) error {
	// locate dot position
	if string(b) == "null" {
		return nil
	}
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' {
		b = b[1 : len(b)-1]
	}

	return ba.UnmarshalText(b)
}

// UnmarshalText decodes a text representation into a BtcAmount.
// It accepts decimal strings (e.g. "1.5"), integer strings (e.g. "100000000"),
// and hex-prefixed strings (e.g. "0x5f5e100").
func (ba *BtcAmount) UnmarshalText(b []byte) error {
	s := string(b)

	if strings.HasPrefix(s, "0x") {
		// if hex value, handle it has integer
		v, err := strconv.ParseUint(s[2:], 16, 64)
		if err != nil {
			return err
		}
		*ba = BtcAmount(v)
		return nil
	}

	pos := strings.IndexByte(s, '.')
	if pos == -1 {
		// no dot means this is an int, multiply it by 100000000
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return err
		}
		if v > math.MaxUint64/1_0000_0000 {
			return errors.New("amount too large")
		}
		v = v * 1_0000_0000
		*ba = BtcAmount(v)
		return nil
	}
	// we have a ., it should be at len(s)-8 ideally, but let's be flexible
	// we will not allow more than 8 decimals however
	ln := len(s)
	decCount := ln - pos - 1
	if decCount > 8 {
		return errors.New("cannot parse amount with more than 8 decimals")
	}
	s = s[:pos] + s[pos+1:] // without the dot
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	for decCount < 8 {
		// multiply by 10 until decCount==8
		decCount += 1
		if v > math.MaxUint64/10 {
			return errors.New("amount too large")
		}
		v *= 10
	}
	*ba = BtcAmount(v)
	return nil
}
