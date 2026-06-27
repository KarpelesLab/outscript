package outscript

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"
)

// CardanoTx is a Cardano (Shelley/Conway-era) transaction. It serializes to the
// CBOR wire format expected by the Cardano ledger:
//
//	transaction = [transaction_body, transaction_witness_set, bool, auxiliary_data/nil]
//
// Only Ed25519 vkey witnesses and ADA/native-asset outputs are supported; Plutus
// scripts, certificates, metadata and staking actions are out of scope. Inputs are
// encoded as a plain array (the CDDL `set` form without the optional #6.258 tag).
//
// The transaction is signed by hashing the CBOR-encoded transaction body with
// blake2b-256 and producing Ed25519 signatures over that 32-byte hash. Note that
// Cardano HD wallets typically use BIP32-Ed25519 extended keys; this type signs
// with the standard crypto/ed25519, so the signing key must correspond to the
// public key used to derive the spent address.
type CardanoTx struct {
	Inputs  []*CardanoInput
	Outputs []*CardanoOutput
	Fee     uint64 // fee in lovelace
	TTL     uint64 // optional time-to-live (slot); 0 means omit

	Witnesses []*CardanoVkeyWitness
}

// CardanoInput references an unspent transaction output being spent.
type CardanoInput struct {
	TxID  []byte // 32-byte id of the transaction that produced the output
	Index uint64 // index of the output within that transaction
}

// CardanoAsset is a native-token amount within an output (multiasset value).
type CardanoAsset struct {
	PolicyID  []byte // 28-byte minting policy id (script hash)
	AssetName []byte // 0..32 byte asset name
	Amount    uint64
}

// CardanoOutput is a transaction output: a destination address, an ADA amount in
// lovelace, and optional native tokens. Address holds the raw address bytes
// (header byte followed by credentials), as produced by [Out.Bytes] for a parsed
// Cardano address.
type CardanoOutput struct {
	Address []byte
	Amount  uint64 // lovelace
	Assets  []CardanoAsset
}

// CardanoVkeyWitness is an Ed25519 verification-key witness: the 32-byte public
// key and its 64-byte signature over the transaction body hash.
type CardanoVkeyWitness struct {
	VKey      []byte
	Signature []byte
}

// cardanoEncMode is the canonical CBOR encoder (definite lengths, shortest ints,
// sorted map keys) required for deterministic Cardano serialization.
var cardanoEncMode = func() cbor.EncMode {
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return em
}()

// cardanoAssetMap groups assets by policy id into the CBOR multiasset structure
// {policy_id => {asset_name => amount}}.
func cardanoAssetMap(assets []CardanoAsset) (map[string]map[string]uint64, error) {
	out := make(map[string]map[string]uint64)
	for _, a := range assets {
		inner, ok := out[string(a.PolicyID)]
		if !ok {
			inner = make(map[string]uint64)
			out[string(a.PolicyID)] = inner
		}
		prev := inner[string(a.AssetName)]
		sum := prev + a.Amount
		if sum < prev {
			// uint64 overflow when aggregating duplicate (policy, asset name) entries.
			return nil, fmt.Errorf("cardano asset amount overflow for policy %x asset %x", a.PolicyID, a.AssetName)
		}
		inner[string(a.AssetName)] = sum
	}
	return out, nil
}

// outputValue returns the CBOR representation of an output's value: a bare coin
// (uint) for ADA-only outputs, or [coin, multiasset] when native tokens present.
func (o *CardanoOutput) outputValue() (interface{}, error) {
	if len(o.Assets) == 0 {
		return o.Amount, nil
	}
	assetMap, err := cardanoAssetMap(o.Assets)
	if err != nil {
		return nil, err
	}
	multiasset := make(map[cbor.ByteString]map[cbor.ByteString]uint64)
	for policy, names := range assetMap {
		inner := make(map[cbor.ByteString]uint64, len(names))
		for name, amount := range names {
			inner[cbor.ByteString(name)] = amount
		}
		multiasset[cbor.ByteString(policy)] = inner
	}
	return []interface{}{o.Amount, multiasset}, nil
}

// bodyMap builds the transaction_body as an integer-keyed CBOR map.
func (tx *CardanoTx) bodyMap() (map[uint64]interface{}, error) {
	if len(tx.Inputs) == 0 {
		return nil, errors.New("cardano transaction has no inputs")
	}
	if len(tx.Outputs) == 0 {
		return nil, errors.New("cardano transaction has no outputs")
	}

	inputs := make([]interface{}, 0, len(tx.Inputs))
	for _, in := range tx.Inputs {
		if len(in.TxID) != 32 {
			return nil, fmt.Errorf("cardano input txid must be 32 bytes, got %d", len(in.TxID))
		}
		inputs = append(inputs, []interface{}{in.TxID, in.Index})
	}

	outputs := make([]interface{}, 0, len(tx.Outputs))
	for _, out := range tx.Outputs {
		if len(out.Address) == 0 {
			return nil, errors.New("cardano output has empty address")
		}
		value, err := out.outputValue()
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, []interface{}{out.Address, value})
	}

	body := map[uint64]interface{}{
		0: inputs,
		1: outputs,
		2: tx.Fee,
	}
	if tx.TTL != 0 {
		body[3] = tx.TTL
	}
	return body, nil
}

// BodyBytes returns the canonical CBOR encoding of the transaction body.
func (tx *CardanoTx) BodyBytes() ([]byte, error) {
	body, err := tx.bodyMap()
	if err != nil {
		return nil, err
	}
	return cardanoEncMode.Marshal(body)
}

// SignBytes returns the 32-byte blake2b-256 hash of the transaction body, which
// is the digest that Ed25519 witnesses sign and also the transaction id.
func (tx *CardanoTx) SignBytes() ([]byte, error) {
	bodyBytes, err := tx.BodyBytes()
	if err != nil {
		return nil, err
	}
	h := blake2b.Sum256(bodyBytes)
	return h[:], nil
}

// Hash returns the transaction id: the blake2b-256 hash of the transaction body.
func (tx *CardanoTx) Hash() ([]byte, error) {
	return tx.SignBytes()
}

// Sign signs the transaction body with each provided standard Ed25519 private key
// and appends a vkey witness for each. Existing witnesses are preserved. For
// BIP32-Ed25519 extended keys or external signers, use [CardanoTx.SignWith].
func (tx *CardanoTx) Sign(keys ...ed25519.PrivateKey) error {
	signers := make([]CardanoSigner, len(keys))
	for i, key := range keys {
		signers[i] = cardanoStdSigner{key: key}
	}
	return tx.SignWith(signers...)
}

// SignWith signs the transaction body with each provided [CardanoSigner] and
// appends a vkey witness for each. Existing witnesses are preserved.
func (tx *CardanoTx) SignWith(signers ...CardanoSigner) error {
	digest, err := tx.SignBytes()
	if err != nil {
		return err
	}
	for _, signer := range signers {
		pub := signer.CardanoPublicKey()
		if len(pub) != 32 {
			return fmt.Errorf("cardano signer public key must be 32 bytes, got %d", len(pub))
		}
		sig, err := signer.SignCardano(digest)
		if err != nil {
			return err
		}
		if len(sig) != 64 {
			return fmt.Errorf("cardano signature must be 64 bytes, got %d", len(sig))
		}
		tx.Witnesses = append(tx.Witnesses, &CardanoVkeyWitness{
			VKey:      append([]byte(nil), pub...),
			Signature: append([]byte(nil), sig...),
		})
	}
	return nil
}

// witnessSet builds the transaction_witness_set CBOR map. It returns nil (an
// empty map) when there are no witnesses.
func (tx *CardanoTx) witnessSet() map[uint64]interface{} {
	ws := map[uint64]interface{}{}
	if len(tx.Witnesses) == 0 {
		return ws
	}
	vkeys := make([]interface{}, 0, len(tx.Witnesses))
	for _, w := range tx.Witnesses {
		vkeys = append(vkeys, []interface{}{w.VKey, w.Signature})
	}
	ws[0] = vkeys
	return ws
}

// MarshalBinary encodes the full transaction (body, witness set, validity flag,
// and null auxiliary data) as canonical CBOR. The body bytes embedded here are
// byte-identical to those hashed for signing.
func (tx *CardanoTx) MarshalBinary() ([]byte, error) {
	bodyBytes, err := tx.BodyBytes()
	if err != nil {
		return nil, err
	}
	transaction := []interface{}{
		cbor.RawMessage(bodyBytes),
		tx.witnessSet(),
		true, // script validity flag; always true (no Plutus phase-2 support)
		nil,  // auxiliary data
	}
	return cardanoEncMode.Marshal(transaction)
}

// UnmarshalBinary decodes a CBOR-encoded Cardano transaction into tx. It supports
// the subset produced by [CardanoTx.MarshalBinary]: ADA/native-asset outputs in
// the legacy (alonzo) array form and Ed25519 vkey witnesses.
func (tx *CardanoTx) UnmarshalBinary(data []byte) error {
	var raw []cbor.RawMessage
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("failed to decode cardano transaction: %w", err)
	}
	if len(raw) < 2 {
		return fmt.Errorf("cardano transaction must have at least 2 elements, got %d", len(raw))
	}

	var body map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(raw[0], &body); err != nil {
		return fmt.Errorf("failed to decode transaction body: %w", err)
	}

	parsed := &CardanoTx{}

	if rawInputs, ok := body[0]; ok {
		var inputs [][]cbor.RawMessage
		if err := cbor.Unmarshal(rawInputs, &inputs); err != nil {
			return fmt.Errorf("failed to decode inputs: %w", err)
		}
		for _, in := range inputs {
			if len(in) != 2 {
				return errors.New("invalid transaction input")
			}
			var txid []byte
			var index uint64
			if err := cbor.Unmarshal(in[0], &txid); err != nil {
				return fmt.Errorf("failed to decode input txid: %w", err)
			}
			if err := cbor.Unmarshal(in[1], &index); err != nil {
				return fmt.Errorf("failed to decode input index: %w", err)
			}
			parsed.Inputs = append(parsed.Inputs, &CardanoInput{TxID: txid, Index: index})
		}
	}

	if rawOutputs, ok := body[1]; ok {
		var outputs []cbor.RawMessage
		if err := cbor.Unmarshal(rawOutputs, &outputs); err != nil {
			return fmt.Errorf("failed to decode outputs: %w", err)
		}
		for _, rawOut := range outputs {
			out, err := decodeCardanoOutput(rawOut)
			if err != nil {
				return err
			}
			parsed.Outputs = append(parsed.Outputs, out)
		}
	}

	if rawFee, ok := body[2]; ok {
		if err := cbor.Unmarshal(rawFee, &parsed.Fee); err != nil {
			return fmt.Errorf("failed to decode fee: %w", err)
		}
	}
	if rawTTL, ok := body[3]; ok {
		if err := cbor.Unmarshal(rawTTL, &parsed.TTL); err != nil {
			return fmt.Errorf("failed to decode ttl: %w", err)
		}
	}

	var ws map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(raw[1], &ws); err != nil {
		return fmt.Errorf("failed to decode witness set: %w", err)
	}
	if rawVkeys, ok := ws[0]; ok {
		var vkeys [][]cbor.RawMessage
		if err := cbor.Unmarshal(rawVkeys, &vkeys); err != nil {
			return fmt.Errorf("failed to decode vkey witnesses: %w", err)
		}
		for _, vk := range vkeys {
			if len(vk) != 2 {
				return errors.New("invalid vkey witness")
			}
			var pub, sig []byte
			if err := cbor.Unmarshal(vk[0], &pub); err != nil {
				return fmt.Errorf("failed to decode vkey: %w", err)
			}
			if err := cbor.Unmarshal(vk[1], &sig); err != nil {
				return fmt.Errorf("failed to decode signature: %w", err)
			}
			parsed.Witnesses = append(parsed.Witnesses, &CardanoVkeyWitness{VKey: pub, Signature: sig})
		}
	}

	*tx = *parsed
	return nil
}

// decodeCardanoOutput decodes a single transaction output in the legacy (alonzo)
// array form [address, value, ? datum_hash].
func decodeCardanoOutput(rawOut cbor.RawMessage) (*CardanoOutput, error) {
	var fields []cbor.RawMessage
	if err := cbor.Unmarshal(rawOut, &fields); err != nil {
		return nil, fmt.Errorf("only legacy (array) cardano outputs are supported: %w", err)
	}
	if len(fields) < 2 {
		return nil, errors.New("invalid transaction output")
	}
	out := &CardanoOutput{}
	if err := cbor.Unmarshal(fields[0], &out.Address); err != nil {
		return nil, fmt.Errorf("failed to decode output address: %w", err)
	}
	// value is either a bare coin (uint) or [coin, multiasset]
	if err := cbor.Unmarshal(fields[1], &out.Amount); err == nil {
		return out, nil
	}
	var value []cbor.RawMessage
	if err := cbor.Unmarshal(fields[1], &value); err != nil || len(value) != 2 {
		return nil, errors.New("failed to decode output value")
	}
	if err := cbor.Unmarshal(value[0], &out.Amount); err != nil {
		return nil, fmt.Errorf("failed to decode output coin: %w", err)
	}
	var multiasset map[cbor.ByteString]map[cbor.ByteString]uint64
	if err := cbor.Unmarshal(value[1], &multiasset); err != nil {
		return nil, fmt.Errorf("failed to decode multiasset: %w", err)
	}
	out.Assets = flattenCardanoAssets(multiasset)
	return out, nil
}

// flattenCardanoAssets converts a decoded {policy => {name => amount}} map into a
// deterministically ordered slice of [CardanoAsset].
func flattenCardanoAssets(multiasset map[cbor.ByteString]map[cbor.ByteString]uint64) []CardanoAsset {
	var assets []CardanoAsset
	for policy, names := range multiasset {
		for name, amount := range names {
			assets = append(assets, CardanoAsset{
				PolicyID:  []byte(policy),
				AssetName: []byte(name),
				Amount:    amount,
			})
		}
	}
	sort.Slice(assets, func(i, j int) bool {
		if c := bytes.Compare(assets[i].PolicyID, assets[j].PolicyID); c != 0 {
			return c < 0
		}
		return bytes.Compare(assets[i].AssetName, assets[j].AssetName) < 0
	})
	return assets
}
