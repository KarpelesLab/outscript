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
// signature in a P2PKH, P2WPKH, or P2SH-multisig spend.
type BtcInputSig struct {
	Scheme       string   // "p2pkh", "p2wpkh", or "p2sh-multisig"
	R            []byte   // 32 bytes, big-endian
	S            []byte   // 32 bytes, big-endian
	SigHashFlag  uint32   // sighash flag byte (e.g. 1 = SIGHASH_ALL)
	PubKey       []byte   // signing pubkey (p2pkh/p2wpkh); nil for unmatched multisig
	RedeemScript []byte   // populated for p2sh-multisig; required by InputSighash
	Pubkeys      [][]byte // for p2sh-multisig: all N pubkeys from the redeem script
}

// ExtractBtcInputSig parses a Bitcoin transaction input's scriptSig and witness,
// recognizing P2PKH, P2WPKH, and P2SH-multisig spend patterns. Returns nil and
// no error when the input does not match any of those (e.g. P2WSH, P2TR,
// P2SH-P2WPKH). Multisig spends return one entry per signature; the redeem
// script and full pubkey list are attached to every returned entry.
func ExtractBtcInputSig(scriptSig []byte, witness [][]byte) ([]*BtcInputSig, error) {
	switch {
	case len(scriptSig) == 0 && len(witness) == 2:
		// P2WPKH: witness = [sig, pubkey], empty scriptSig
		s, err := parseEcdsaSig(witness[0], witness[1], "p2wpkh")
		if err != nil {
			return nil, err
		}
		return []*BtcInputSig{s}, nil
	case len(witness) == 0 && len(scriptSig) > 0:
		if scriptSig[0] == 0x00 {
			// Likely P2SH-multisig: OP_0 <sig1>...<sigM> <redeemScript>.
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
	return nil, nil
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
