package outscript_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/KarpelesLab/outscript"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"
)

// TestCardanoRealTxBodyHash validates the core txid logic against real mainnet
// chain data: a Cardano transaction id is blake2b-256 of the transaction body's
// exact CBOR bytes. The fixture is mainnet tx
// b94c3185280a4217d5ab922619f74d768e0a7189f653c644c4f2aaccc7498217 fetched from
// the public Koios API.
func TestCardanoRealTxBodyHash(t *testing.T) {
	const wantTxID = "b94c3185280a4217d5ab922619f74d768e0a7189f653c644c4f2aaccc7498217"
	raw, err := os.ReadFile("testdata/cardano_mainnet_tx.hex")
	if err != nil {
		t.Fatalf("read fixture: %s", err)
	}
	buf, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("decode hex: %s", err)
	}
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(buf, &arr); err != nil {
		t.Fatalf("decode transaction: %s", err)
	}
	if len(arr) != 4 {
		t.Fatalf("expected 4-element transaction, got %d", len(arr))
	}
	h := blake2b.Sum256(arr[0])
	if got := hex.EncodeToString(h[:]); got != wantTxID {
		t.Fatalf("body hash mismatch:\n got %s\nwant %s", got, wantTxID)
	}
}

func mustAddrBytes(t *testing.T, addr string) []byte {
	t.Helper()
	out, err := outscript.ParseCardanoAddress(addr)
	if err != nil {
		t.Fatalf("parse %s: %s", addr, err)
	}
	return out.Bytes()
}

func sampleCardanoTx(t *testing.T) *outscript.CardanoTx {
	t.Helper()
	txid, _ := hex.DecodeString("5c32d3c670337ad0ef69e5bf8cbd26cee7a736ee0fba41e63ec071671c1a6376")
	return &outscript.CardanoTx{
		Inputs: []*outscript.CardanoInput{
			{TxID: txid, Index: 0},
		},
		Outputs: []*outscript.CardanoOutput{
			{
				Address: mustAddrBytes(t, "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"),
				Amount:  1_000_000,
			},
			{
				Address: mustAddrBytes(t, "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"),
				Amount:  8_500_000,
			},
		},
		Fee: 170_000,
		TTL: 41_000_000,
	}
}

func TestCardanoTxSignAndVerify(t *testing.T) {
	tx := sampleCardanoTx(t)

	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)

	digest, err := tx.SignBytes()
	if err != nil {
		t.Fatalf("SignBytes: %s", err)
	}
	if len(digest) != 32 {
		t.Fatalf("expected 32-byte digest, got %d", len(digest))
	}

	if err := tx.Sign(key); err != nil {
		t.Fatalf("Sign: %s", err)
	}
	if len(tx.Witnesses) != 1 {
		t.Fatalf("expected 1 witness, got %d", len(tx.Witnesses))
	}
	w := tx.Witnesses[0]
	if !bytes.Equal(w.VKey, pub) {
		t.Errorf("witness vkey mismatch")
	}
	if !ed25519.Verify(pub, digest, w.Signature) {
		t.Errorf("signature does not verify against body digest")
	}

	// Hash() must equal the signing digest (the transaction id).
	h, err := tx.Hash()
	if err != nil {
		t.Fatalf("Hash: %s", err)
	}
	if !bytes.Equal(h, digest) {
		t.Errorf("Hash != SignBytes")
	}
}

func TestCardanoTxRoundTrip(t *testing.T) {
	tx := sampleCardanoTx(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x07}, ed25519.SeedSize))
	if err := tx.Sign(key); err != nil {
		t.Fatalf("Sign: %s", err)
	}

	enc, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %s", err)
	}

	// the encoded transaction must be a 4-element CBOR array
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(enc, &arr); err != nil {
		t.Fatalf("decode array: %s", err)
	}
	if len(arr) != 4 {
		t.Fatalf("expected 4-element transaction, got %d", len(arr))
	}
	// txid must be blake2b-256 of the embedded body bytes
	bodyHash := blake2b.Sum256(arr[0])
	h, _ := tx.Hash()
	if !bytes.Equal(bodyHash[:], h) {
		t.Errorf("embedded body hash != Hash()")
	}

	var decoded outscript.CardanoTx
	if err := decoded.UnmarshalBinary(enc); err != nil {
		t.Fatalf("UnmarshalBinary: %s", err)
	}
	if decoded.Fee != tx.Fee || decoded.TTL != tx.TTL {
		t.Errorf("fee/ttl mismatch: got fee=%d ttl=%d", decoded.Fee, decoded.TTL)
	}
	if len(decoded.Inputs) != len(tx.Inputs) || len(decoded.Outputs) != len(tx.Outputs) {
		t.Fatalf("input/output count mismatch")
	}
	for i, in := range decoded.Inputs {
		if !bytes.Equal(in.TxID, tx.Inputs[i].TxID) || in.Index != tx.Inputs[i].Index {
			t.Errorf("input %d mismatch", i)
		}
	}
	for i, out := range decoded.Outputs {
		if !bytes.Equal(out.Address, tx.Outputs[i].Address) || out.Amount != tx.Outputs[i].Amount {
			t.Errorf("output %d mismatch", i)
		}
	}
	if len(decoded.Witnesses) != 1 || !bytes.Equal(decoded.Witnesses[0].Signature, tx.Witnesses[0].Signature) {
		t.Errorf("witness mismatch after round-trip")
	}

	// re-marshaling the decoded transaction must be byte-identical (deterministic)
	enc2, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatalf("re-MarshalBinary: %s", err)
	}
	if !bytes.Equal(enc, enc2) {
		t.Errorf("round-trip is not byte-identical:\n %s\n %s", hex.EncodeToString(enc), hex.EncodeToString(enc2))
	}
}

func TestCardanoTxMultiAsset(t *testing.T) {
	txid, _ := hex.DecodeString("5c32d3c670337ad0ef69e5bf8cbd26cee7a736ee0fba41e63ec071671c1a6376")
	policy, _ := hex.DecodeString("00000000000000000000000000000000000000000000000000000000")
	tx := &outscript.CardanoTx{
		Inputs: []*outscript.CardanoInput{{TxID: txid, Index: 1}},
		Outputs: []*outscript.CardanoOutput{
			{
				Address: mustAddrBytes(t, "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"),
				Amount:  2_000_000,
				Assets: []outscript.CardanoAsset{
					{PolicyID: policy, AssetName: []byte("TOKEN"), Amount: 42},
				},
			},
		},
		Fee: 180_000,
	}
	enc, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %s", err)
	}
	var decoded outscript.CardanoTx
	if err := decoded.UnmarshalBinary(enc); err != nil {
		t.Fatalf("UnmarshalBinary: %s", err)
	}
	if len(decoded.Outputs) != 1 || len(decoded.Outputs[0].Assets) != 1 {
		t.Fatalf("expected 1 output with 1 asset, got %+v", decoded.Outputs)
	}
	a := decoded.Outputs[0].Assets[0]
	if !bytes.Equal(a.PolicyID, policy) || string(a.AssetName) != "TOKEN" || a.Amount != 42 {
		t.Errorf("asset mismatch: %+v", a)
	}
	if decoded.Outputs[0].Amount != 2_000_000 {
		t.Errorf("coin amount mismatch: %d", decoded.Outputs[0].Amount)
	}
}
