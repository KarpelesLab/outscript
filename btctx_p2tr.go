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
	prev := sha256.New()
	amt := sha256.New()
	spk := sha256.New()
	seq := sha256.New()

	parts := &taprootSighashParts{
		prevScriptsByIn: make([][]byte, len(tx.In)),
		amountsByIn:     make([]uint64, len(tx.In)),
	}

	for i, in := range tx.In {
		k := keys[i]
		if len(k.PrevScript) == 0 {
			return nil, fmt.Errorf("taproot: input %d missing PrevScript (required when any input uses p2tr)", i)
		}
		parts.prevScriptsByIn[i] = k.PrevScript
		parts.amountsByIn[i] = uint64(k.Amount)

		txid := slices.Clone(in.TXID[:])
		slices.Reverse(txid)
		prev.Write(txid)
		prev.Write(binary.LittleEndian.AppendUint32(nil, in.Vout))

		amt.Write(binary.LittleEndian.AppendUint64(nil, uint64(k.Amount)))

		spk.Write(BtcVarInt(len(k.PrevScript)).Bytes())
		spk.Write(k.PrevScript)

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
