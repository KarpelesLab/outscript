package outscript

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/KarpelesLab/secp256k1"
)

// TaprootSighash computes the BIP-341 key-path SIGHASH_DEFAULT digest for
// input idx. keys must line up 1:1 with tx.In; each key's PrevScript and
// Amount must be set (BIP-341 commits to every input's scriptPubKey and
// value, not only the one being signed). Intended for callers that sign
// externally — e.g. TSS / MuSig / FROST — and feed the returned 32-byte
// digest into their own BIP-340 Schnorr protocol.
func (tx *BtcTx) TaprootSighash(keys []*BtcTxSign, idx int) ([]byte, error) {
	parts, err := tx.taprootSighashParts(keys)
	if err != nil {
		return nil, err
	}
	return tx.taprootKeySpendSighash(idx, 0x00, parts)
}

// taprootSighashParts caches the per-transaction BIP-341 sighash components
// (sha_prevouts, sha_amounts, sha_scriptpubkeys, sha_sequences, sha_outputs).
// Each is a 32-byte SHA-256 digest over the concatenation of the
// corresponding per-input or per-output fields.
type taprootSighashParts struct {
	shaPrevouts     []byte
	shaAmounts      []byte
	shaScriptPubs   []byte
	shaSequences    []byte
	shaOutputs      []byte
	prevScriptsByIn [][]byte
	amountsByIn     []uint64
}

// taprootSighashParts computes the shared BIP-341 sighash components for the
// transaction. keys must line up 1:1 with tx.In and each key must have
// PrevScript and Amount set (BIP-341 commits to the scriptPubKey and amount
// of every input, regardless of which input is being signed).
func (tx *BtcTx) taprootSighashParts(keys []*BtcTxSign) (*taprootSighashParts, error) {
	if len(keys) != len(tx.In) {
		return nil, errors.New("taproot: keys length does not match number of inputs")
	}
	prevScripts := make([][]byte, len(keys))
	amounts := make([]BtcAmount, len(keys))
	for i, k := range keys {
		if len(k.PrevScript) == 0 {
			return nil, fmt.Errorf("taproot: input %d missing PrevScript (required when any input uses p2tr)", i)
		}
		prevScripts[i] = k.PrevScript
		amounts[i] = k.Amount
	}
	return tx.taprootSighashPartsRaw(prevScripts, amounts)
}

// taprootSighashPartsRaw is the keyless variant used both by signers and by
// signature extractors (which don't have a BtcTxSign for each input). The
// caller must supply prevScripts and amounts for every input.
func (tx *BtcTx) taprootSighashPartsRaw(prevScripts [][]byte, amounts []BtcAmount) (*taprootSighashParts, error) {
	if len(prevScripts) != len(tx.In) {
		return nil, fmt.Errorf("taproot: prevScripts (%d) must match input count (%d)", len(prevScripts), len(tx.In))
	}
	if len(amounts) != len(tx.In) {
		return nil, fmt.Errorf("taproot: amounts (%d) must match input count (%d)", len(amounts), len(tx.In))
	}
	prev := sha256.New()
	amt := sha256.New()
	spk := sha256.New()
	seq := sha256.New()

	parts := &taprootSighashParts{
		prevScriptsByIn: make([][]byte, len(tx.In)),
		amountsByIn:     make([]uint64, len(tx.In)),
	}

	for i, in := range tx.In {
		if len(prevScripts[i]) == 0 {
			return nil, fmt.Errorf("taproot: input %d missing prev script", i)
		}
		parts.prevScriptsByIn[i] = prevScripts[i]
		parts.amountsByIn[i] = uint64(amounts[i])

		txid := slices.Clone(in.TXID[:])
		slices.Reverse(txid)
		prev.Write(txid)
		prev.Write(binary.LittleEndian.AppendUint32(nil, in.Vout))

		amt.Write(binary.LittleEndian.AppendUint64(nil, uint64(amounts[i])))

		spk.Write(BtcVarInt(len(prevScripts[i])).Bytes())
		spk.Write(prevScripts[i])

		seq.Write(binary.LittleEndian.AppendUint32(nil, in.Sequence))
	}

	out := sha256.New()
	for _, o := range tx.Out {
		out.Write(binary.LittleEndian.AppendUint64(nil, uint64(o.Amount)))
		out.Write(BtcVarInt(len(o.Script)).Bytes())
		out.Write(o.Script)
	}

	parts.shaPrevouts = prev.Sum(nil)
	parts.shaAmounts = amt.Sum(nil)
	parts.shaScriptPubs = spk.Sum(nil)
	parts.shaSequences = seq.Sum(nil)
	parts.shaOutputs = out.Sum(nil)
	return parts, nil
}

// TaprootInputSighash computes the BIP-341 sighash digest for input n given
// the parsed taproot signature and the prev_out script and amount of every
// input in the transaction (BIP-341 commits to all of them). Supports both
// key-path and script-path (single-sig `<xpk> OP_CHECKSIG` leaf) spends with
// SIGHASH_DEFAULT. Annexes are not supported.
func (tx *BtcTx) TaprootInputSighash(n int, sig *BtcInputSig, prevScripts [][]byte, amounts []BtcAmount) ([]byte, error) {
	if n < 0 || n >= len(tx.In) {
		return nil, fmt.Errorf("input index %d out of range (have %d inputs)", n, len(tx.In))
	}
	if sig.SigHashFlag != 0 {
		return nil, fmt.Errorf("taproot: only SIGHASH_DEFAULT (0) supported, got 0x%x", sig.SigHashFlag)
	}
	parts, err := tx.taprootSighashPartsRaw(prevScripts, amounts)
	if err != nil {
		return nil, err
	}
	switch sig.Scheme {
	case "p2tr-keypath":
		return tx.taprootKeySpendSighash(n, 0x00, parts)
	case "p2tr-scriptpath":
		if sig.LeafScript == nil {
			return nil, errors.New("p2tr-scriptpath requires LeafScript")
		}
		return tx.taprootScriptPathSighash(n, 0x00, parts, sig.LeafScript)
	}
	return nil, fmt.Errorf("not a taproot scheme: %s", sig.Scheme)
}

// taprootScriptPathSighash computes the BIP-341 script-path sighash with the
// BIP-342 tapscript ext fields appended (tapleaf hash, key version, codesep
// position). leafScript is the tapleaf script bytes; the leaf version is
// assumed to be 0xc0 (the only one currently defined). Annex is not supported.
func (tx *BtcTx) taprootScriptPathSighash(n int, hashType byte, parts *taprootSighashParts, leafScript []byte) ([]byte, error) {
	if hashType != 0x00 {
		return nil, fmt.Errorf("taproot: only SIGHASH_DEFAULT (0x00) is supported, got 0x%02x", hashType)
	}
	leafLen := BtcVarInt(len(leafScript)).Bytes()
	tapleafHash := bip340TaggedHash("TapLeaf", []byte{0xc0}, leafLen, leafScript)

	buf := make([]byte, 0, 207)
	buf = append(buf, 0x00) // epoch
	buf = append(buf, hashType)
	buf = binary.LittleEndian.AppendUint32(buf, tx.Version)
	buf = binary.LittleEndian.AppendUint32(buf, tx.Locktime)
	buf = append(buf, parts.shaPrevouts...)
	buf = append(buf, parts.shaAmounts...)
	buf = append(buf, parts.shaScriptPubs...)
	buf = append(buf, parts.shaSequences...)
	buf = append(buf, parts.shaOutputs...)
	buf = append(buf, 0x02) // spend_type: script-path, no annex
	buf = binary.LittleEndian.AppendUint32(buf, uint32(n))

	// BIP-342 ext: tapleaf_hash || key_version || codesep_position
	buf = append(buf, tapleafHash...)
	buf = append(buf, 0x00) // key_version: 0
	buf = binary.LittleEndian.AppendUint32(buf, 0xFFFFFFFF)

	return bip340TaggedHash("TapSighash", buf), nil
}

// taprootKeySpendSighash computes the BIP-341 SIGHASH_DEFAULT sighash digest
// for a key-path spend of input n. hashType must be 0 (SIGHASH_DEFAULT).
// No annex, no script-path.
func (tx *BtcTx) taprootKeySpendSighash(n int, hashType byte, parts *taprootSighashParts) ([]byte, error) {
	if hashType != 0x00 {
		return nil, fmt.Errorf("taproot: only SIGHASH_DEFAULT (0x00) is supported, got 0x%02x", hashType)
	}
	buf := make([]byte, 0, 175)
	buf = append(buf, 0x00) // epoch
	buf = append(buf, hashType)
	buf = binary.LittleEndian.AppendUint32(buf, tx.Version)
	buf = binary.LittleEndian.AppendUint32(buf, tx.Locktime)
	buf = append(buf, parts.shaPrevouts...)
	buf = append(buf, parts.shaAmounts...)
	buf = append(buf, parts.shaScriptPubs...)
	buf = append(buf, parts.shaSequences...)
	buf = append(buf, parts.shaOutputs...)
	buf = append(buf, 0x00) // spend_type: no annex, key-path
	buf = binary.LittleEndian.AppendUint32(buf, uint32(n))

	// TapSighash tagged hash, stripping the leading epoch 0x00 from the data
	// that follows the tag prefix (the epoch is already included in buf).
	return bip340TaggedHash("TapSighash", buf), nil
}

// p2trSign signs input n with a BIP-341 key-path spend. Produces a 64-byte
// Schnorr signature witness. SigHash 0 and 1 are both treated as
// SIGHASH_DEFAULT (64-byte sig, no trailing hash-type byte).
//
// If k.Key implements [TaprootSigner], that path is used (TSS, HSM, mock
// signer, etc.) and the signer is trusted to apply its own taproot tweak.
// Otherwise k.Key must be a *secp256k1.PrivateKey so that the tweak can be
// applied here.
func (tx *BtcTx) p2trSign(n int, k *BtcTxSign, parts *taprootSighashParts) error {
	if k.SigHash != 0 && k.SigHash != 1 {
		return fmt.Errorf("taproot: SigHash 0x%x not supported (only SIGHASH_DEFAULT)", k.SigHash)
	}

	sigHash, err := tx.taprootKeySpendSighash(n, 0x00, parts)
	if err != nil {
		return err
	}

	if ts, ok := k.Key.(TaprootSigner); ok {
		sig, err := ts.SignTaproot(sigHash)
		if err != nil {
			return err
		}
		if len(sig) != 64 {
			return fmt.Errorf("taproot: TaprootSigner returned %d-byte sig, want 64", len(sig))
		}
		tx.In[n].Witnesses = [][]byte{sig}
		tx.In[n].Script = nil
		return nil
	}

	priv, err := taprootPrivKey(k.Key)
	if err != nil {
		return err
	}

	// Tweak the private key per BIP-341 (key-path, no merkle root):
	//   d' = d if P.y even else n-d
	//   d_sig = (d' + hashTapTweak(P.x)) mod n
	// If Q.y is odd, negate d_sig.
	pubBytes := priv.PubKey().SerializeCompressed()
	xOnly := pubBytes[1:]
	_, parity, tweak, err := taprootTweakPubKey(xOnly)
	if err != nil {
		return err
	}

	// Build the tweaked private scalar:
	//   d' = d if internal P.y is even else n-d
	//   d_tweaked = d' + t (mod n)
	//   if tweaked Q.y is odd, negate d_tweaked
	var d secp256k1.ModNScalar
	d.Set(&priv.Key)
	if pubBytes[0] == 0x03 {
		d.Negate()
	}
	var tScalar secp256k1.ModNScalar
	if overflow := tScalar.SetByteSlice(tweak[:]); overflow {
		return errors.New("taproot: tweak >= curve order")
	}
	d.Add(&tScalar)
	if parity == 1 {
		d.Negate()
	}

	var aux [32]byte // deterministic, BIP-340-compatible
	sig, err := bip340Sign(&d, sigHash, aux[:])
	if err != nil {
		return err
	}

	tx.In[n].Witnesses = [][]byte{sig}
	tx.In[n].Script = nil
	return nil
}
