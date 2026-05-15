package outscript

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/BottleFmt/gobottle"
	"golang.org/x/crypto/ripemd160"
)

// BtcInputSig holds parsed Bitcoin input signature data for a single
// signature in a recognized spend pattern.
type BtcInputSig struct {
	Scheme       string   // "p2pkh", "p2wpkh", "p2sh-multisig", "p2tr-keypath", "p2tr-scriptpath"
	R            []byte   // 32 bytes, big-endian
	S            []byte   // 32 bytes, big-endian
	SigHashFlag  uint32   // sighash flag byte; 0 = SIGHASH_DEFAULT (taproot), 1 = SIGHASH_ALL (others)
	PubKey       []byte   // signing pubkey: full compressed/uncompressed for ECDSA, x-only (32B) for taproot
	RedeemScript []byte   // populated for p2sh-multisig; required by InputSighash
	Pubkeys      [][]byte // for p2sh-multisig: all N pubkeys from the redeem script
	LeafScript   []byte   // p2tr-scriptpath: the tapleaf script
	ControlBlock []byte   // p2tr-scriptpath: the BIP-341 control block
}

// ExtractBtcInputSig parses a Bitcoin transaction input's scriptSig and witness,
// recognizing P2PKH, P2WPKH, P2SH-multisig, P2TR key-path, and P2TR script-path
// (single-sig `<xpk> OP_CHECKSIG` tapscript only). Returns nil and no error
// when the input does not match any of those (e.g. P2WSH, P2SH-P2WPKH, exotic
// tapscripts). Multisig spends return one entry per signature; the redeem
// script and full pubkey list are attached to every returned entry.
//
// For P2TR key-path the returned PubKey is unset; callers should fill it in
// from the prev_out scriptPubKey (`OP_1 <x-only pubkey>`).
func ExtractBtcInputSig(scriptSig []byte, witness [][]byte) ([]*BtcInputSig, error) {
	if len(scriptSig) == 0 && len(witness) > 0 {
		return extractWitnessOnly(witness)
	}
	if len(witness) == 0 && len(scriptSig) > 0 {
		return extractScriptSigOnly(scriptSig)
	}
	return nil, nil
}

func extractWitnessOnly(witness [][]byte) ([]*BtcInputSig, error) {
	// Annex (BIP-341): not supported. If present, bail.
	if len(witness) >= 2 && len(witness[len(witness)-1]) > 0 && witness[len(witness)-1][0] == 0x50 {
		return nil, nil
	}
	switch len(witness) {
	case 1:
		// P2TR key-path: single 64- or 65-byte Schnorr signature
		if s := parseTaprootSig(witness[0], "p2tr-keypath"); s != nil {
			return []*BtcInputSig{s}, nil
		}
		return nil, nil
	default:
		// Check for P2TR script-path: last witness element is a control block.
		cb := witness[len(witness)-1]
		if isControlBlock(cb) {
			return parseP2TRScriptPath(witness)
		}
		// Otherwise treat as P2WPKH if shape matches.
		if len(witness) == 2 {
			pub := witness[1]
			if len(pub) > 0 && (pub[0] == 0x02 || pub[0] == 0x03 || pub[0] == 0x04 || pub[0] == 0x06 || pub[0] == 0x07) {
				s, err := parseEcdsaSig(witness[0], pub, "p2wpkh")
				if err != nil {
					return nil, err
				}
				return []*BtcInputSig{s}, nil
			}
		}
	}
	return nil, nil
}

func extractScriptSigOnly(scriptSig []byte) ([]*BtcInputSig, error) {
	if scriptSig[0] == 0x00 {
		if out := parseP2SHMultisig(scriptSig); out != nil {
			return out, nil
		}
	}
	// P2PKH: scriptSig = <push sig> <push pubkey>
	sigB, n := ParsePushBytes(scriptSig)
	if sigB == nil {
		return nil, nil
	}
	pubB, m := ParsePushBytes(scriptSig[n:])
	if pubB == nil || n+m != len(scriptSig) {
		return nil, nil
	}
	s, err := parseEcdsaSig(sigB, pubB, "p2pkh")
	if err != nil {
		return nil, err
	}
	return []*BtcInputSig{s}, nil
}

// isControlBlock checks the BIP-341 control-block shape: 33 + 32*k bytes,
// first byte is leaf_version | parity_bit. BIP-342 tapscript uses leaf
// version 0xc0, so the masked first byte must equal 0xc0.
func isControlBlock(b []byte) bool {
	if len(b) < 33 || (len(b)-33)%32 != 0 {
		return false
	}
	return (b[0] & 0xfe) == 0xc0
}

// parseTaprootSig parses a 64- or 65-byte Schnorr signature blob, splitting
// into r/s and (if 65 bytes) the explicit sighash flag.
func parseTaprootSig(sig []byte, scheme string) *BtcInputSig {
	if len(sig) != 64 && len(sig) != 65 {
		return nil
	}
	flag := uint32(0)
	rs := sig
	if len(sig) == 65 {
		flag = uint32(sig[64])
		rs = sig[:64]
	}
	return &BtcInputSig{
		Scheme:      scheme,
		R:           slices.Clone(rs[:32]),
		S:           slices.Clone(rs[32:]),
		SigHashFlag: flag,
	}
}

// parseP2TRScriptPath decodes the simple `<push32 xpk> OP_CHECKSIG` tapscript
// pattern (the common case for single-sig taproot script-path spends).
// Returns nil for any other leaf shape.
func parseP2TRScriptPath(witness [][]byte) ([]*BtcInputSig, error) {
	if len(witness) < 3 {
		return nil, nil
	}
	cb := witness[len(witness)-1]
	leaf := witness[len(witness)-2]
	stack := witness[:len(witness)-2]

	// Only handle the canonical 34-byte single-sig leaf:
	//   PUSH32 <xpk> OP_CHECKSIG
	if len(leaf) != 34 || leaf[0] != 0x20 || leaf[33] != 0xac {
		return nil, nil
	}
	if len(stack) != 1 {
		return nil, nil
	}
	parsed := parseTaprootSig(stack[0], "p2tr-scriptpath")
	if parsed == nil {
		return nil, nil
	}
	parsed.PubKey = slices.Clone(leaf[1:33])
	parsed.LeafScript = slices.Clone(leaf)
	parsed.ControlBlock = slices.Clone(cb)
	return []*BtcInputSig{parsed}, nil
}

// parseP2SHMultisig parses an OP_0-prefixed scriptSig of form
// OP_0 <push sig1> ... <push sigM> <push redeemScript> where redeemScript has
// shape OP_M <push pk1> ... <push pkN> OP_N OP_CHECKMULTISIG. Returns nil if
// the structure does not match.
func parseP2SHMultisig(scriptSig []byte) []*BtcInputSig {
	if len(scriptSig) < 2 || scriptSig[0] != 0x00 {
		return nil
	}
	cur := scriptSig[1:]
	var pushes [][]byte
	for len(cur) > 0 {
		data, n := ParsePushBytes(cur)
		if n == 0 {
			return nil
		}
		pushes = append(pushes, data)
		cur = cur[n:]
	}
	if len(pushes) < 2 {
		return nil
	}
	redeem := pushes[len(pushes)-1]
	sigPushes := pushes[:len(pushes)-1]

	pubkeys := parseMultisigPubkeys(redeem)
	if pubkeys == nil {
		return nil
	}

	out := make([]*BtcInputSig, 0, len(sigPushes))
	for _, s := range sigPushes {
		if len(s) == 0 {
			continue
		}
		parsed, err := parseEcdsaSig(s, nil, "p2sh-multisig")
		if err != nil {
			return nil
		}
		parsed.RedeemScript = redeem
		parsed.Pubkeys = pubkeys
		out = append(out, parsed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseMultisigPubkeys validates and extracts the N pubkeys from a multisig
// redeem script: OP_M <push pk1> ... <push pkN> OP_N OP_CHECKMULTISIG.
// Returns nil if the script is not a recognizable multisig template.
func parseMultisigPubkeys(rs []byte) [][]byte {
	if len(rs) < 4 || rs[len(rs)-1] != 0xae { // OP_CHECKMULTISIG
		return nil
	}
	if rs[0] < 0x51 || rs[0] > 0x60 { // OP_1..OP_16
		return nil
	}
	nOp := rs[len(rs)-2]
	if nOp < 0x51 || nOp > 0x60 {
		return nil
	}
	n := int(nOp) - 0x50
	cur := rs[1 : len(rs)-2]
	var pubkeys [][]byte
	for len(cur) > 0 {
		data, off := ParsePushBytes(cur)
		if data == nil || off == 0 {
			return nil
		}
		pubkeys = append(pubkeys, data)
		cur = cur[off:]
	}
	if len(pubkeys) != n {
		return nil
	}
	return pubkeys
}

// parseEcdsaSig splits a DER-encoded ECDSA signature followed by a trailing
// sighash flag byte into its r/s components.
func parseEcdsaSig(sigWithFlag, pubKey []byte, scheme string) (*BtcInputSig, error) {
	if len(sigWithFlag) < 9 {
		return nil, fmt.Errorf("signature too short: %d bytes", len(sigWithFlag))
	}
	flag := uint32(sigWithFlag[len(sigWithFlag)-1])
	der := sigWithFlag[:len(sigWithFlag)-1]
	if len(der) < 8 || der[0] != 0x30 {
		return nil, errors.New("not a DER signature")
	}
	if int(der[1]) != len(der)-2 {
		return nil, errors.New("DER length mismatch")
	}
	if der[2] != 0x02 {
		return nil, errors.New("expected INTEGER for r")
	}
	rLen := int(der[3])
	if 4+rLen+2 > len(der) {
		return nil, errors.New("DER r overrun")
	}
	r := der[4 : 4+rLen]
	if der[4+rLen] != 0x02 {
		return nil, errors.New("expected INTEGER for s")
	}
	sLen := int(der[4+rLen+1])
	if 4+rLen+2+sLen != len(der) {
		return nil, errors.New("DER s overrun")
	}
	s := der[4+rLen+2 : 4+rLen+2+sLen]

	rN, err := normalize32(r)
	if err != nil {
		return nil, fmt.Errorf("invalid r: %w", err)
	}
	sN, err := normalize32(s)
	if err != nil {
		return nil, fmt.Errorf("invalid s: %w", err)
	}

	return &BtcInputSig{
		Scheme:      scheme,
		R:           rN,
		S:           sN,
		SigHashFlag: flag,
		PubKey:      pubKey,
	}, nil
}

// normalize32 strips DER's leading zero (when present to keep the integer
// positive) and left-pads with zeros so the result is exactly 32 bytes.
func normalize32(b []byte) ([]byte, error) {
	b = bytes.TrimLeft(b, "\x00")
	if len(b) > 32 {
		return nil, fmt.Errorf("value longer than 32 bytes (%d)", len(b))
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out, nil
}

// InputSighash computes the 32-byte digest the signature at input n committed
// to, given the parsed signature, the previous output's scriptPubKey, and the
// previous output's amount. Supports p2pkh, p2wpkh, and p2sh-multisig with
// SIGHASH_ALL. For p2sh-multisig the signature's RedeemScript is used and
// prevScript is ignored; for p2wpkh, amount is required and prevScript is
// ignored.
func (tx *BtcTx) InputSighash(n int, sig *BtcInputSig, prevScript []byte, amount BtcAmount) ([]byte, error) {
	if n < 0 || n >= len(tx.In) {
		return nil, fmt.Errorf("input index %d out of range (have %d inputs)", n, len(tx.In))
	}
	if sig.SigHashFlag != 1 {
		return nil, fmt.Errorf("unsupported sighash flag 0x%x (only SIGHASH_ALL=1 supported)", sig.SigHashFlag)
	}
	switch sig.Scheme {
	case "p2pkh":
		return legacySighash(tx, n, prevScript, sig.SigHashFlag), nil
	case "p2sh-multisig":
		if sig.RedeemScript == nil {
			return nil, errors.New("p2sh-multisig requires RedeemScript")
		}
		return legacySighash(tx, n, sig.RedeemScript, sig.SigHashFlag), nil
	case "p2wpkh":
		pfx, sfx := tx.preimage()
		pkHash := gobottle.Hash(sig.PubKey, sha256.New, ripemd160.New)
		scriptCode := append(append([]byte{0x76, 0xa9}, PushBytes(pkHash)...), 0x88, 0xac)
		amountBytes := binary.LittleEndian.AppendUint64(nil, uint64(amount))
		input, inputSeq := tx.In[n].preimageBytes()
		signString := slices.Concat(pfx, input, PushBytes(scriptCode), amountBytes, inputSeq, sfx)
		signString = binary.LittleEndian.AppendUint32(signString, sig.SigHashFlag)
		return gobottle.Hash(signString, sha256.New, sha256.New), nil
	}
	return nil, fmt.Errorf("unsupported scheme: %s", sig.Scheme)
}

// legacySighash is the pre-segwit (BIP-143-free) sighash: clear all inputs'
// scripts, substitute scriptCode at input n, serialize without witness,
// append sigHashFlag as uint32 LE, double-SHA256.
func legacySighash(tx *BtcTx, n int, scriptCode []byte, sigHashFlag uint32) []byte {
	wtx := tx.Dup()
	wtx.ClearInputs()
	wtx.In[n].Script = scriptCode
	buf := wtx.exportBytes(false)
	buf = binary.LittleEndian.AppendUint32(buf, sigHashFlag)
	return gobottle.Hash(buf, sha256.New, sha256.New)
}
