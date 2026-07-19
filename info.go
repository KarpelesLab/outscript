package outscript

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"slices"

	"github.com/BottleFmt/gobottle"
	"golang.org/x/crypto/ripemd160"
)

// Out represents a generated output script with its format name, hex-encoded script,
// and optional flags indicating the target network(s).
type Out struct {
	Name   string   `json:"name"`            // p2sh, etc
	Script string   `json:"script"`          // out script
	Flags  []string `json:"flags,omitempty"` // flags
	raw    []byte
}

// Bytes returns the raw output script bytes.
func (o *Out) Bytes() []byte {
	return o.raw
}

// String returns a human-readable representation of the Out in "name:script" format.
func (o *Out) String() string {
	return o.Name + ":" + o.Script
}

// Hash will extract the hash part of the Out, or return nil if there is no known hash
func (o *Out) Hash() []byte {
	switch o.Name {
	case "p2wpkh", "p2tr":
		res, _ := ParsePushBytes(o.raw[1:])
		return res
	case "p2pkh", "p2pukh":
		res, _ := ParsePushBytes(o.raw[2:])
		return res
	case "p2pk", "p2puk":
		pub, _ := ParsePushBytes(o.raw)
		return gobottle.Hash(pub, sha256.New, ripemd160.New)
	case "p2sh":
		// 0xa9 <pushbytes> 0x87
		res, _ := ParsePushBytes(o.raw[1:])
		return res
	case "eth":
		return o.raw
	case "tron":
		// raw is 0x41 || 20-byte account hash; return the account hash
		if len(o.raw) == 21 {
			return o.raw[1:]
		}
		return nil
	case "massa":
		return o.raw
	case "solana":
		return o.raw
	case "cardano":
		// raw is "header byte + credential(s)"; return the payment/stake credential
		if len(o.raw) >= 29 {
			return o.raw[1:29]
		}
		return nil
	default:
		return nil
	}
}

func makeOut(name string, script []byte, flags ...string) *Out {
	return &Out{
		Name:   name,
		Script: hex.EncodeToString(script),
		Flags:  flags,
		raw:    script,
	}
}

// GuessOut will return a out matching the provided script, and attempt to
// guess the correct type. pubkeyhint can be nil and this function will still
// be useful, but it won't be able to differenciate between compressed and
// uncompressed keys if the script contains a hashed key
func GuessOut(script []byte, pubkeyhint crypto.PublicKey) *Out {
	if len(script) == 0 {
		return makeOut("empty", script, "invalid")
	}
	switch {
	case script[0] == 0:
		// Segwit
		switch len(script) {
		case 22:
			return makeOut("p2wpkh", script)
		case 34:
			return makeOut("p2wsh", script)
		default:
			return makeOut("invalid", script)
		}
	case script[0] == 0x51: // OP_1 (p2tr)
		if len(script) == 34 {
			return makeOut("p2tr", script)
		}
		return makeOut("invalid", script)
	case script[0] == 0x6a: // OP_RETURN
		return makeOut("op_return", script)
	case script[len(script)-1] == 0xac: // OP_CHECKSIG
		if len(script) == 25 && bytes.HasPrefix(script, []byte{0x76, 0xa9, 0x14}) && bytes.HasSuffix(script, []byte{0x88, 0xac}) {
			// pay-to-keyhash
			if pubkeyhint == nil {
				return makeOut("p2pkh", script)
			}
			s := New(pubkeyhint)
			for _, e := range []string{"p2pkh", "p2pukh"} {
				buf, err := s.Generate(e)
				if err != nil {
					continue
				}
				if bytes.Equal(buf, script) {
					return makeOut(e, script)
				}
			}
			// could not identify the script
			return makeOut("p2pkh", script)
		}
		v, _ := ParsePushBytes(script)
		if v != nil && bytes.Equal(append(PushBytes(v), 0xac), script) {
			switch len(v) {
			case 33:
				return makeOut("p2pk", script)
			case 65:
				return makeOut("p2puk", script)
			}
		}
	case script[len(script)-1] == 0x87: // OP_EQUAL (likely P2SH)
		v, _ := ParsePushBytes(script[1:])
		if v != nil && bytes.Equal(slices.Concat([]byte{0xa9}, PushBytes(v), []byte{0x87}), script) {
			// p2sh
			if pubkeyhint == nil {
				return makeOut("p2sh", script)
			}
			s := New(pubkeyhint)
			for _, e := range []string{"p2sh:p2pk", "p2sh:p2pkh", "p2sh:p2puk", "p2sh:p2pukh", "p2sh:p2wpkh"} {
				buf, err := s.Generate(e)
				if err != nil {
					continue
				}
				if bytes.Equal(buf, script) {
					return makeOut(e, script)
				}
			}
			// could not identify the script
			return makeOut("p2sh", script)
		}
	}

	// unrecognized
	return makeOut("invalid", script)
}

// GetOuts returns the potential outputs that can be opened in theory with the given pubkey. p2w* values are "pay to segwit" and
// can only be used on segwit-enabled chains.
func GetOuts(pubkey crypto.PublicKey) []*Out {
	v := New(pubkey)

	// https://learnmeabitcoin.com/technical/script/

	var outScripts []*Out
	for name := range Formats {
		out, err := v.Out(name)
		if err != nil {
			continue
		}
		outScripts = append(outScripts, out)
	}

	return outScripts
}
