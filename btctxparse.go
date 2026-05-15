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

// BtcInputSig holds parsed Bitcoin input signature data for P2PKH and P2WPKH spends.
type BtcInputSig struct {
	Scheme      string // "p2pkh" or "p2wpkh"
	R           []byte // 32 bytes, big-endian
	S           []byte // 32 bytes, big-endian
	SigHashFlag uint32 // sighash flag byte (e.g. 1 = SIGHASH_ALL)
	PubKey      []byte // compressed or uncompressed pubkey from the input
}

// ExtractBtcInputSig parses a Bitcoin transaction input's scriptSig and witness,
// recognizing P2PKH and P2WPKH spend patterns. Returns (nil, nil) when the input
// does not match either pattern (e.g. P2SH, P2TR, multisig).
func ExtractBtcInputSig(scriptSig []byte, witness [][]byte) (*BtcInputSig, error) {
	switch {
	case len(scriptSig) == 0 && len(witness) == 2:
		// P2WPKH: witness = [sig, pubkey], empty scriptSig
		return parseEcdsaSig(witness[0], witness[1], "p2wpkh")
	case len(witness) == 0 && len(scriptSig) > 0:
		// P2PKH: scriptSig = <push sig> <push pubkey>
		sigB, n := ParsePushBytes(scriptSig)
		if sigB == nil {
			return nil, nil
		}
		pubB, m := ParsePushBytes(scriptSig[n:])
		if pubB == nil || n+m != len(scriptSig) {
			return nil, nil
		}
		return parseEcdsaSig(sigB, pubB, "p2pkh")
	}
	return nil, nil
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
// previous output's amount. Supports p2pkh and p2wpkh with SIGHASH_ALL.
func (tx *BtcTx) InputSighash(n int, sig *BtcInputSig, prevScript []byte, amount BtcAmount) ([]byte, error) {
	if n < 0 || n >= len(tx.In) {
		return nil, fmt.Errorf("input index %d out of range (have %d inputs)", n, len(tx.In))
	}
	if sig.SigHashFlag != 1 {
		return nil, fmt.Errorf("unsupported sighash flag 0x%x (only SIGHASH_ALL=1 supported)", sig.SigHashFlag)
	}
	switch sig.Scheme {
	case "p2pkh":
		wtx := tx.Dup()
		wtx.ClearInputs()
		wtx.In[n].Script = prevScript
		buf := wtx.exportBytes(false)
		buf = binary.LittleEndian.AppendUint32(buf, sig.SigHashFlag)
		return gobottle.Hash(buf, sha256.New, sha256.New), nil
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
