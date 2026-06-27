package outscript

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/BottleFmt/gobottle"
	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/bech32m"
)

// ParseEvmAddress parses an address to return an Out, supporting EVM-based
// networks.
func ParseEvmAddress(address string) (*Out, error) {
	if len(address) != 42 || !strings.HasPrefix(address, "0x") {
		return nil, errors.New("EVM addresses must be 42 characters long and start with 0x")
	}

	// that's an easy one
	data, err := hex.DecodeString(address[2:])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ethereum address: %w", err)
	}
	// if the address has any uppercase character, check the checksum. If all lowercase no checksum check is performed
	if address != strings.ToLower(address) {
		if address != eip55(data) {
			return nil, fmt.Errorf("bad checksum on ethereum address")
		}
	}
	// all good
	return &Out{Name: "eth", Script: hex.EncodeToString(data), raw: data, Flags: []string{"evm"}}, nil
}

// ParseBitcoinAddress parses an address in bitcoin format and returns the matching script,
// accepting also other networks addresses (in which cash a flag will be set)
//
// Deprecated: use ParseBitcoinBasedAddress instead
func ParseBitcoinAddress(address string) (*Out, error) {
	return ParseBitcoinBasedAddress("auto", address)
}

// ParseBitcoinBasedAddress parses an address in bitcoin format and returns the matching script,
// for the specified network. The special value "auto" for network will attempt to detect the network.
func ParseBitcoinBasedAddress(network, address string) (*Out, error) {
	// case 1: bech32 address
	if strings.HasPrefix(address, "bitcoincash:") {
		if network != "bitcoin-cash" && network != "auto" {
			return nil, fmt.Errorf("bitcoincash address provided while expecting a %s address", network)
		}
		typ, buf, err := bech32m.CashAddrDecode("bitcoincash:", address)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bitcoin cash address: %s", err)
		}
		switch typ {
		case 0:
			// P2PKH
			script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf), []byte{0x88, 0xac})
			out := makeOut("p2pkh", script, "bitcoin-cash")
			return out, nil
		case 1:
			// P2SH
			script := slices.Concat([]byte{0xa9}, PushBytes(buf), []byte{0x87})
			out := makeOut("p2sh", script, "bitcoin-cash")
			return out, nil
		default:
			return nil, fmt.Errorf("unsupported bitcoincash address type %d", typ)
		}
	}
	// attempt to decode as segwit addr
	pos := strings.LastIndexByte(address, '1')
	if pos > 0 {
		hrp := address[:pos]
		typ, buf, err := bech32m.SegwitAddrDecode(hrp, address)
		if err == nil {
			// this is a segwit addr!
			net := "bitcoin"
			switch hrp {
			case "ltc":
				net = "litecoin"
			case "nc":
				net = "namecoin"
			case "bc":
				net = "bitcoin"
			case "tb":
				net = "bitcoin-testnet"
			case "mona":
				net = "monacoin"
			case "ep":
				net = "electraproto"
			default:
				return nil, fmt.Errorf("unsupported hrp value %s", hrp)
			}
			if net != network && network != "auto" {
				return nil, fmt.Errorf("got a %s address where we expected a %s address", net, network)
			}
			if typ == 1 && (net == "bitcoin" || net == "bitcoin-testnet") && len(buf) == 32 {
				// this is taproot
				script := slices.Concat([]byte{0x51}, PushBytes(buf)) // OP_1 <taproot>
				return makeOut("p2tr", script, net), nil
			}
			if typ != 0 {
				return nil, fmt.Errorf("unsupported segwit type %d", typ)
			}
			switch len(buf) {
			case 20:
				// P2WPKH
				script := slices.Concat([]byte{0x00}, PushBytes(buf))
				return makeOut("p2wpkh", script, net), nil
			case 32:
				// p2wsh
				script := slices.Concat([]byte{0x00}, PushBytes(buf))
				return makeOut("p2wsh", script, net), nil
			default:
				return nil, fmt.Errorf("invalid segwit address length %d", len(buf))
			}
		}
	}

	// decode as base58
	buf, err := base58.Bitcoin.Decode(address)
	if err == nil {
		// check hash
		chk := buf[len(buf)-4:]
		buf = buf[:len(buf)-4]
		h := gobottle.Hash(buf, sha256.New, sha256.New)
		if subtle.ConstantTimeCompare(h[:4], chk) != 1 {
			err = errors.New("bad checksum")
		}
	}
	if err == nil {
		// https://en.bitcoin.it/wiki/List_of_address_prefixes
		// 1Fw9zL4vzCaf8yCqz1kinoU6N71hcmJyvD 0x00
		// 36WzxPKBV4ScwUKLPgmMZkphf7Np4rqjyo 0x05
		// LYSJKD6D9robFvCVTq3ZqgCNoCYgPFmyLs 0x30 litecoin p2pkh
		// MANDhrctLRAygo3dFckfWvEaWeQiti143C 0x32 litecoin p2sh OR monacoin
		switch network {
		case "auto":
			// attempt autodetection
			switch buf[0] {
			case 0x00: // btc standard p2pkh, possibly bitcoin-cash
				script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf[1:]), []byte{0x88, 0xac})
				out := makeOut("p2pkh", script, "bitcoin", "bitcoin-cash")
				return out, nil
			case 0x05: // btc p2sh
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, "bitcoin", "bitcoin-cash")
				return out, nil
			case 0x0d: // namecoin p2sh
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, "namecoin")
				return out, nil
			case 0x10: // dash p2sh
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, "dash")
				return out, nil
			case 0x16: // dogecoin p2sh
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, "dogecoin")
				return out, nil
			case 0x1e: // dogecoin p2pkh
				script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf[1:]), []byte{0x88, 0xac})
				out := makeOut("p2pkh", script, "dogecoin")
				return out, nil
			case 0x30: // litecoin p2pkh
				script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf[1:]), []byte{0x88, 0xac})
				out := makeOut("p2pkh", script, "litecoin")
				return out, nil
			case 0x32: // litecoin p2sh, but could also be monacoin p2pkh (we'll take litecoin by default since it's most likely)
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, "litecoin")
				return out, nil
			case 0x34: // namecoin p2pkh
				script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf[1:]), []byte{0x88, 0xac})
				out := makeOut("p2pkh", script, "namecoin")
				return out, nil
			case 0x37: // monacoin p2sh, but could also be electraproto p2pk
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, "monacoin")
				return out, nil
			case 0x4c: // dash p2pkh
				script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf[1:]), []byte{0x88, 0xac})
				out := makeOut("p2pkh", script, "dash")
				return out, nil
			case 0x6f: // bitcoin testnet p2pkh
				script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf[1:]), []byte{0x88, 0xac})
				out := makeOut("p2pkh", script, "bitcoin-testnet")
				return out, nil
			case 0x89: // electraproto p2sh
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, "electraproto")
				return out, nil
			case 0xc4: // bitcoin testnet p2sh
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, "bitcoin-testnet")
				return out, nil
			default:
				return nil, fmt.Errorf("unsupported base58 address version=%x", buf[0])
			}
		case "bitcoin", "bitcoin-cash":
			switch buf[0] {
			case 0x00: // btc standard p2pkh, possibly bitcoin-cash
				script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf[1:]), []byte{0x88, 0xac})
				out := makeOut("p2pkh", script, network)
				return out, nil
			case 0x05: // btc/bch p2sh
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, network)
				return out, nil
			default:
				return nil, fmt.Errorf("unsupported %s base58 address version=%x", network, buf[0])
			}
		case "bitcoin-testnet":
			switch buf[0] {
			case 0x6f: // bitcoin testnet p2pkh
				script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf[1:]), []byte{0x88, 0xac})
				out := makeOut("p2pkh", script, network)
				return out, nil
			case 0xc4: // bitcoin testnet p2sh
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, network)
				return out, nil
			default:
				return nil, fmt.Errorf("unsupported %s base58 address version=%x", network, buf[0])
			}
		case "litecoin":
			switch buf[0] {
			case 0x30: // litecoin p2pkh
				script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf[1:]), []byte{0x88, 0xac})
				out := makeOut("p2pkh", script, "litecoin")
				return out, nil
			case 0x32: // litecoin p2sh, but could also be monacoin p2pkh (we'll take litecoin by default since it's most likely)
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, "litecoin")
				return out, nil
			default:
				return nil, fmt.Errorf("unsupported %s base58 address version=%x", network, buf[0])
			}
		case "namecoin":
			switch buf[0] {
			case 0x34: // namecoin p2pkh
				script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf[1:]), []byte{0x88, 0xac})
				out := makeOut("p2pkh", script, "namecoin")
				return out, nil
			case 0x0d: // namecoin p2sh
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, "namecoin")
				return out, nil
			default:
				return nil, fmt.Errorf("unsupported %s base58 address version=%x", network, buf[0])
			}
		case "dogecoin":
			switch buf[0] {
			case 0x16: // dogecoin p2sh
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, "dogecoin")
				return out, nil
			case 0x1e: // dogecoin p2pkh
				script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf[1:]), []byte{0x88, 0xac})
				out := makeOut("p2pkh", script, "dogecoin")
				return out, nil
			}
		case "monacoin":
			switch buf[0] {
			case 0x32: // monacoin p2pkh
				script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf[1:]), []byte{0x88, 0xac})
				out := makeOut("p2pkh", script, "monacoin")
				return out, nil
			case 0x37: // monacoin p2sh
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, "monacoin")
				return out, nil
			}
		case "electraproto":
			switch buf[0] {
			case 0x37: // electraproto p2pkh
				script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf[1:]), []byte{0x88, 0xac})
				out := makeOut("p2pkh", script, "electraproto")
				return out, nil
			case 0x89: // electraproto p2sh
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, "electraproto")
				return out, nil
			}
		case "dash":
			switch buf[0] {
			case 0x4c: // dash p2pkh
				script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf[1:]), []byte{0x88, 0xac})
				out := makeOut("p2pkh", script, "dash")
				return out, nil
			case 0x10: // dash p2sh
				script := slices.Concat([]byte{0xa9}, PushBytes(buf[1:]), []byte{0x87})
				out := makeOut("p2sh", script, "dash")
				return out, nil
			}
		default:
			return nil, fmt.Errorf("unsupported %s network for address parsing", network)
		}
	}

	// attempt to see if this is a bitcoincash: addr missing its bitcoincash: prefix
	if network == "auto" || network == "bitcoin-cash" {
		typ, buf, err := bech32m.CashAddrDecode("bitcoincash:", "bitcoincash:"+address)
		if err == nil {
			switch typ {
			case 0:
				// P2PKH
				script := slices.Concat([]byte{0x76, 0xa9}, PushBytes(buf), []byte{0x88, 0xac})
				out := makeOut("p2pkh", script, "bitcoin-cash")
				return out, nil
			case 1:
				// P2SH
				script := slices.Concat([]byte{0xa9}, PushBytes(buf), []byte{0x87})
				out := makeOut("p2sh", script, "bitcoin-cash")
				return out, nil
			default:
				return nil, fmt.Errorf("unsupported bitcoincash address type %d", typ)
			}
		}
	}

	return nil, fmt.Errorf("unsupported address %s", address)
}

func (out *Out) baseName() string {
	name := out.Name
	pos := strings.IndexByte(name, ':')
	if pos >= 0 {
		return name[:pos]
	}
	return name
}

func encodeBase58addr(vers byte, buf []byte) string {
	buf = slices.Concat([]byte{vers}, buf)
	h := gobottle.Hash(buf, sha256.New, sha256.New)
	buf = slices.Concat(buf, h[:4])
	return base58.Bitcoin.Encode(buf)
}

// Address returns an address matching the provided out. Flags will be used for hints if multiple addresses are possible.
func (out *Out) Address(flags ...string) (string, error) {
	flags = append(flags, out.Flags...)
	net := ""
	if len(flags) > 0 {
		net = flags[0]
	}

	switch out.baseName() {
	case "solana":
		return base58.Bitcoin.Encode(out.raw), nil
	case "cardano":
		return cardanoAddressFromOut(out.raw, net)
	case "eth", "evm":
		return eip55(out.raw), nil
	case "massa_pubkey":
		buf := out.raw
		h := gobottle.Hash(buf, sha256.New, sha256.New)
		buf = slices.Concat(buf, h[:4])
		return "P" + base58.Bitcoin.Encode(buf), nil
	case "massa":
		// massa network key: blake3 encoding → A[US]+
		buf := out.raw
		typ := buf[0] // if 0, start with AU, if 1, start with AS
		buf = buf[1:]
		h := gobottle.Hash(buf, sha256.New, sha256.New)
		buf = slices.Concat(buf, h[:4])

		switch typ {
		case 0:
			return "AU" + base58.Bitcoin.Encode(buf), nil
		case 1:
			return "AS" + base58.Bitcoin.Encode(buf), nil
		default:
			return "", fmt.Errorf("unsupported value for massa address type: %d", typ)
		}
	case "p2pkh", "p2pukh":
		// 0x76 0xa9 <pushdata> 0x88 0xac
		buf := out.raw
		buf = buf[2 : len(buf)-2]
		buf, _ = ParsePushBytes(buf)
		if buf == nil {
			return "", errors.New("invalid script for address type")
		}
		switch net {
		case "bitcoin-cash", "bitcoincash":
			// bitcoin-cash format
			return bech32m.CashAddrEncode("bitcoincash:", 0, buf)
		case "litecoin":
			return encodeBase58addr(0x30, buf), nil
		case "namecoin":
			return encodeBase58addr(0x34, buf), nil
		case "dogecoin":
			return encodeBase58addr(0x1e, buf), nil
		case "monacoin":
			return encodeBase58addr(0x32, buf), nil
		case "electraproto":
			return encodeBase58addr(0x37, buf), nil
		case "dash":
			return encodeBase58addr(0x4c, buf), nil
		case "bitcoin-testnet":
			return encodeBase58addr(0x6f, buf), nil
		case "bitcoin":
			fallthrough
		default:
			// "good old" format
			return encodeBase58addr(0, buf), nil
		}
	case "p2sh":
		// 0xa9 <pushdata> 0x87
		buf := out.raw
		buf = buf[1 : len(buf)-1]
		buf, _ = ParsePushBytes(buf)
		if buf == nil {
			return "", errors.New("invalid script for address type")
		}
		switch net {
		case "bitcoin-cash", "bitcoincash":
			// bitcoin-cash format
			return bech32m.CashAddrEncode("bitcoincash:", 1, buf)
		case "litecoin":
			return encodeBase58addr(0x32, buf), nil
		case "namecoin":
			return encodeBase58addr(0x0d, buf), nil
		case "dogecoin":
			return encodeBase58addr(0x16, buf), nil
		case "monacoin":
			return encodeBase58addr(0x37, buf), nil
		case "electraproto":
			return encodeBase58addr(0x89, buf), nil
		case "dash":
			return encodeBase58addr(0x10, buf), nil
		case "bitcoin-testnet":
			return encodeBase58addr(0xc4, buf), nil
		case "bitcoin":
			fallthrough
		default:
			// "good old" format
			return encodeBase58addr(0x05, buf), nil
		}
	case "p2wpkh", "p2wsh":
		// 0x00 <pushdata 20bytes>
		buf, _ := ParsePushBytes(out.raw[1:])
		switch net {
		case "litecoin":
			return bech32m.SegwitAddrEncode("ltc", 0, buf)
		case "namecoin":
			return bech32m.SegwitAddrEncode("nc", 0, buf)
		case "bitcoin":
			return bech32m.SegwitAddrEncode("bc", 0, buf)
		case "bitcoin-testnet":
			return bech32m.SegwitAddrEncode("tb", 0, buf)
		case "monacoin":
			return bech32m.SegwitAddrEncode("mona", 0, buf)
		case "electraproto":
			return bech32m.SegwitAddrEncode("ep", 0, buf)
		}
	case "p2tr":
		// 0x51 <pushdata 32bytes>
		buf, _ := ParsePushBytes(out.raw[1:])
		switch net {
		case "bitcoin":
			return bech32m.SegwitAddrEncode("bc", 1, buf)
		case "bitcoin-testnet":
			return bech32m.SegwitAddrEncode("tb", 1, buf)
		}
	}

	return "", fmt.Errorf("could not transform outscript of format %s", out.Name)
}
