// Package outscript generates potential output scripts for a given public key.
//
// It supports Bitcoin and Bitcoin-like cryptocurrency output script formats (P2PKH, P2SH, P2WPKH,
// P2WSH, P2PK, P2TR, etc.), EVM-based networks (Ethereum and compatible chains), and other
// blockchains such as Litecoin, Dogecoin, Namecoin, Monacoin, Electraproto, Dash, Bitcoin Cash,
// Massa, Solana, and Cardano.
//
// The package also provides transaction building and signing for Bitcoin-style (with segwit
// witness data), EVM, Solana, and Cardano transactions, as well as block reward calculations
// for various cryptocurrency networks.
package outscript

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"slices"
)

// Script holds a public key and caches generated output scripts for various formats.
type Script struct {
	pubkey crypto.PublicKey
	cache  map[string][]byte
}

// New returns a new [Script] object for the given public key, which can be used to generate output scripts
func New(pubkey crypto.PublicKey) *Script {
	v := &Script{
		pubkey: pubkey,
		cache:  make(map[string][]byte),
	}

	return v
}

// getPubKeyBytes returns the public key in the requested format (one of pubkey, pubkey:comp or pubkey:uncomp).
// pubkey:comp and pubkey:uncomp require a secp256k1 key
func (s *Script) getPubKeyBytes(typ string) ([]byte, error) {
	switch typ {
	case "pubkey:pkix":
		return x509.MarshalPKIXPublicKey(s.pubkey)
	case "pubkey:ed25519":
		// get raw ed25519 key
		if o, ok := s.pubkey.(ed25519.PublicKey); ok {
			return []byte(o), nil
		}
		return nil, fmt.Errorf("pubkey of type %T does not support %s export", s.pubkey, typ)
	case "pubkey:comp":
		switch o := s.pubkey.(type) {
		case interface{ SerializeCompressed() []byte }:
			return o.SerializeCompressed(), nil
		default:
			return nil, fmt.Errorf("pubkey of type %T does not support %s export", s.pubkey, typ)
		}
	case "pubkey:uncomp":
		switch o := s.pubkey.(type) {
		case interface{ SerializeUncompressed() []byte }:
			return o.SerializeUncompressed(), nil
		default:
			return nil, fmt.Errorf("pubkey of type %T does not support %s export", s.pubkey, typ)
		}
	default:
		return nil, fmt.Errorf("unknown public key format %s", typ)
	}
}

// Generate will return the byte value for the specified script type for the current public key
func (s *Script) Generate(name string) ([]byte, error) {
	if r, ok := s.cache[name]; ok {
		return r, nil
	}

	// some special cases to access the public key
	switch name {
	case "pubkey:pkix", "pubkey:ed25519", "pubkey:comp", "pubkey:uncomp":
		res, err := s.getPubKeyBytes(name)
		if err != nil {
			return nil, err
		}
		s.cache[name] = res
		return res, nil
	}

	f, ok := Formats[name]
	if !ok {
		return nil, fmt.Errorf("unsupported format %s", name)
	}

	var pieces [][]byte

	for _, piece := range f {
		v, err := piece.Bytes(s)
		if err != nil {
			return nil, err
		}
		pieces = append(pieces, v)
	}
	res := slices.Concat(pieces...)
	s.cache[name] = res
	return res, nil
}

// Out returns a [Out] object matching the requested script
func (s *Script) Out(name string) (*Out, error) {
	buf, err := s.Generate(name)
	if err != nil {
		return nil, err
	}

	return makeOut(name, buf), nil
}

// Address formats the key using the specified script (eg. p2sh, etc) and optional
// flags hints. You can do things like Address("eth") where no hint is needed, or
// things like Address("p2pkh", "litecoin") so the appropriate format is used.
func (s *Script) Address(script string, flags ...string) (string, error) {
	out, err := s.Out(script)
	if err != nil {
		return "", err
	}

	return out.Address(flags...)
}
