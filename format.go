package outscript

import (
	"crypto/sha256"
)

// Format is a sequence of [Insertable] values that together define how an output script
// is constructed from a public key.
type Format []Insertable

var (
	// Formats maps script format names (e.g. "p2pkh", "p2wpkh", "eth") to their
	// corresponding [Format] definitions.
	Formats = map[string]Format{
		"p2pkh":  Format{Bytes{0x76, 0xa9}, IPushBytes{IHash160(Lookup("pubkey:comp"))}, Bytes{0x88, 0xac}},
		"p2pukh": Format{Bytes{0x76, 0xa9}, IPushBytes{IHash160(Lookup("pubkey:uncomp"))}, Bytes{0x88, 0xac}},
		"p2pk":   Format{IPushBytes{Lookup("pubkey:comp")}, Bytes{0xac}},
		"p2puk":  Format{IPushBytes{Lookup("pubkey:uncomp")}, Bytes{0xac}},
		"p2wpkh": Format{Bytes{0}, IPushBytes{IHash160(Lookup("pubkey:comp"))}},
		// p2tr (BIP-341, key-path only): OP_1 <32-byte tweaked x-only output key>
		"p2tr": Format{Bytes{0x51}, IPushBytes{ITaprootTweak{Lookup("pubkey:comp")}}},
		// p2sh formats
		"p2sh:p2pkh":  Format{Bytes{0xa9}, IPushBytes{IHash160(Lookup("p2pkh"))}, Bytes{0x87}},
		"p2sh:p2pukh": Format{Bytes{0xa9}, IPushBytes{IHash160(Lookup("p2pukh"))}, Bytes{0x87}},
		"p2sh:p2pk":   Format{Bytes{0xa9}, IPushBytes{IHash160(Lookup("p2pk"))}, Bytes{0x87}},
		"p2sh:p2puk":  Format{Bytes{0xa9}, IPushBytes{IHash160(Lookup("p2puk"))}, Bytes{0x87}},
		"p2sh:p2wpkh": Format{Bytes{0xa9}, IPushBytes{IHash160(Lookup("p2wpkh"))}, Bytes{0x87}},
		// segwit formats
		"p2wsh:p2pkh":  Format{Bytes{0}, IPushBytes{IHash(Lookup("p2pkh"), sha256.New)}},
		"p2wsh:p2pukh": Format{Bytes{0}, IPushBytes{IHash(Lookup("p2pukh"), sha256.New)}},
		"p2wsh:p2pk":   Format{Bytes{0}, IPushBytes{IHash(Lookup("p2pk"), sha256.New)}},
		"p2wsh:p2puk":  Format{Bytes{0}, IPushBytes{IHash(Lookup("p2puk"), sha256.New)}},
		"p2wsh:p2wpkh": Format{Bytes{0}, IPushBytes{IHash(Lookup("p2wpkh"), sha256.New)}},
		// ethereum format
		"eth": Format{IHash(Lookup("pubkey:uncomp"), newEtherHash)},
		// massa keys are blake3 encoded
		"massa_pubkey": Format{Bytes{0}, Lookup("pubkey:ed25519")},
		"massa":        Format{Bytes{0, 0}, IHash(Lookup("massa_pubkey"), newMassaHash)}, // 0[type=address, 1 for smart contract], version=0
		// solana: raw 32-byte Ed25519 public key
		"solana": Format{Lookup("pubkey:ed25519")},
		// cardano: type-6 enterprise address payload (mainnet header 0x61) followed by
		// the blake2b-224 payment key hash. Out.Address adjusts the network nibble.
		"cardano": Format{Bytes{0x61}, IHash(Lookup("pubkey:ed25519"), newCardanoHash)},
	}

	// FormatsPerNetwork is a table listing the typically available formats for each network
	FormatsPerNetwork = map[string][]string{
		"bitcoin":      []string{"p2tr", "p2wpkh", "p2sh:p2wpkh", "p2puk", "p2pk", "p2pukh", "p2pkh"},
		"bitcoin-cash": []string{"p2puk", "p2pk", "p2pukh", "p2pkh"},
		"litecoin":     []string{"p2wpkh", "p2sh:p2wpkh", "p2puk", "p2pk", "p2pukh", "p2pkh"},
		"dogecoin":     []string{"p2puk", "p2pk", "p2pukh", "p2pkh"},
		"evm":          []string{"eth"},
		"massa":        []string{"massa"},
		"solana":       []string{"solana"},
		"cardano":      []string{"cardano"},
	}
)
