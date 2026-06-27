package outscript

import (
	"crypto/sha256"

	"github.com/BottleFmt/gobottle"
	"golang.org/x/crypto/ripemd160"
)

// GuessPubKeyAndHashByOutScript will attempt to guess the pubkey hash (address component) and possibly
// the pubkey from a output script.
func GuessPubKeyAndHashByOutScript(scriptBytes []byte) (foundPubKey []byte, foundPubKeyHash []byte) {
	// 1) P2PKH pattern: 76 a9 14 <20-byte> 88 ac
	//    i.e. OP_DUP OP_HASH160 (PUSH 20) <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
	if len(scriptBytes) == 25 &&
		scriptBytes[0] == 0x76 && // OP_DUP
		scriptBytes[1] == 0xa9 && // OP_HASH160
		scriptBytes[2] == 0x14 && // PUSH 20
		scriptBytes[23] == 0x88 && // OP_EQUALVERIFY
		scriptBytes[24] == 0xac { // OP_CHECKSIG

		foundPubKeyHash = scriptBytes[3:23]
		return nil, foundPubKeyHash
	}

	// 2) P2SH pattern: a9 14 <20 bytes> 87
	//    i.e. OP_HASH160 (PUSH 20) <20 bytes> OP_EQUAL
	if len(scriptBytes) == 23 &&
		scriptBytes[0] == 0xa9 && // OP_HASH160
		scriptBytes[1] == 0x14 && // PUSH 20
		scriptBytes[22] == 0x87 { // OP_EQUAL

		foundPubKeyHash = scriptBytes[2:22]
		return nil, foundPubKeyHash
	}

	// 3) P2PK pattern: e.g. 0x21 <33-byte-pubkey> 0xac OR 0x41 <65-byte-pubkey> 0xac
	//    (compressed/uncompressed pubkey directly in script).
	if len(scriptBytes) == 35 &&
		scriptBytes[0] == 0x21 && // PUSH 33
		scriptBytes[34] == 0xac { // OP_CHECKSIG
		pubKey := scriptBytes[1:34]
		// pubkey-hash is RIPEMD160(SHA256(pubKey))
		foundPubKey = pubKey
		foundPubKeyHash = gobottle.Hash(pubKey, sha256.New, ripemd160.New)
		return foundPubKey, foundPubKeyHash
	}
	if len(scriptBytes) == 67 &&
		scriptBytes[0] == 0x41 && // PUSH 65
		scriptBytes[66] == 0xac { // OP_CHECKSIG
		pubKey := scriptBytes[1:66]
		foundPubKey = pubKey
		foundPubKeyHash = gobottle.Hash(pubKey, sha256.New, ripemd160.New)
		return foundPubKey, foundPubKeyHash
	}

	// 4) SegWit patterns:
	//    - P2WPKH: 0x00 0x14 <20 bytes> => total length 22
	//    - P2WSH:  0x00 0x20 <32 bytes> => total length 34
	if len(scriptBytes) == 22 && scriptBytes[0] == 0x00 && scriptBytes[1] == 0x14 {
		// This is likely P2WPKH => the next 20 bytes is the witness program
		foundPubKeyHash = scriptBytes[2:22]
		return nil, foundPubKeyHash
	}
	if len(scriptBytes) == 34 && scriptBytes[0] == 0x00 && scriptBytes[1] == 0x20 {
		// This is likely P2WSH => the next 32 bytes is the witness script
		foundPubKeyHash = scriptBytes[2:34]
		return nil, foundPubKeyHash
	}

	// 5) P2TR pattern: 51 20 <32-byte x-only pubkey> => total length 34
	//    i.e. OP_1 (PUSH 32) <32 bytes>
	if len(scriptBytes) == 34 && scriptBytes[0] == 0x51 && scriptBytes[1] == 0x20 {
		foundPubKeyHash = scriptBytes[2:34]
		return nil, foundPubKeyHash
	}

	// If none of the above matched, we don't have a recognized pattern.
	return nil, nil
}

// GuessPubKeyAndHashByInScript will attempt to guess the pubkey hash (address component) and possibly
// the pubkey from an input script.
func GuessPubKeyAndHashByInScript(scriptBytes []byte) (foundPubKey []byte, foundPubKeyHash []byte) {
	push1, pos1 := ParsePushBytes(scriptBytes)
	var push2 []byte
	if push1 != nil {
		push2, _ = ParsePushBytes(scriptBytes[pos1:])
	}

	// P2PKH: push1 is usually signature, and push2 the pubkey
	if push1 != nil && push2 != nil && isPlausibleSecp256k1PubKey(push2) {
		foundPubKey = push2
		foundPubKeyHash = gobottle.Hash(foundPubKey, sha256.New, ripemd160.New)
		return foundPubKey, foundPubKeyHash
	}

	return nil, nil
}

// isPlausibleSecp256k1PubKey reports whether b has the shape of a valid secp256k1
// public key: a 33-byte compressed key prefixed with 0x02/0x03, or a 65-byte
// uncompressed key prefixed with 0x04. Empty or otherwise shaped pushes are rejected.
func isPlausibleSecp256k1PubKey(b []byte) bool {
	switch len(b) {
	case 33:
		return b[0] == 0x02 || b[0] == 0x03
	case 65:
		return b[0] == 0x04
	default:
		return false
	}
}
