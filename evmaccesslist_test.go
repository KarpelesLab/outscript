package outscript_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/KarpelesLab/outscript"
	"github.com/KarpelesLab/secp256k1"
)

// TestEvmAccessListVector decodes a hand-computed EIP-2930 transaction whose
// access list RLP was built by hand, then re-encodes it. This validates both the
// decoder and the encoder against an independent reference:
//
//	0x01 || rlp([1, 2, 3, 4, "", 5, "", [[0x01, [0x02]]]])
//	access_list = c4 c3 01 c1 02
func TestEvmAccessListVector(t *testing.T) {
	raw := must(hex.DecodeString("01cc01020304800580c4c301c102"))

	var tx outscript.EvmTx
	if err := tx.ParseTransaction(raw); err != nil {
		t.Fatalf("ParseTransaction failed: %s", err)
	}
	if tx.Type != outscript.EvmTxEIP2930 {
		t.Errorf("expected EIP2930, got type %d", tx.Type)
	}
	if len(tx.AccessList) != 1 {
		t.Fatalf("expected 1 access tuple, got %d", len(tx.AccessList))
	}
	if tx.AccessList[0].Address != "0x01" {
		t.Errorf("unexpected access address: %s", tx.AccessList[0].Address)
	}
	if len(tx.AccessList[0].StorageKeys) != 1 || tx.AccessList[0].StorageKeys[0] != "0x02" {
		t.Errorf("unexpected storage keys: %v", tx.AccessList[0].StorageKeys)
	}

	// re-encode must reproduce the exact hand-computed bytes
	out, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %s", err)
	}
	if !bytes.Equal(raw, out) {
		t.Errorf("re-encode mismatch:\n got %x\nwant %x", out, raw)
	}
}

// TestEvmAccessListEmptyRoundTrip verifies a tuple with an empty storage key
// list survives a round-trip (access_list = [[address, []]]).
func TestEvmAccessListEmptyRoundTrip(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	tx := &outscript.EvmTx{
		Type:      outscript.EvmTxEIP1559,
		ChainId:   1,
		Nonce:     0,
		GasTipCap: big.NewInt(1000000000),
		GasFeeCap: big.NewInt(20000000000),
		Gas:       21000,
		To:        "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7",
		Value:     big.NewInt(0),
		AccessList: []*outscript.EvmAccessTuple{
			{Address: "0x00000000000000000000000000000000000000aa"},
		},
	}
	if err := tx.Sign(key); err != nil {
		t.Fatalf("Sign failed: %s", err)
	}
	data, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %s", err)
	}
	var tx2 outscript.EvmTx
	if err := tx2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %s", err)
	}
	if len(tx2.AccessList) != 1 {
		t.Fatalf("expected 1 access tuple, got %d", len(tx2.AccessList))
	}
	if len(tx2.AccessList[0].StorageKeys) != 0 {
		t.Errorf("expected 0 storage keys, got %d", len(tx2.AccessList[0].StorageKeys))
	}
	remarshaled, err := tx2.MarshalBinary()
	if err != nil {
		t.Fatalf("re-MarshalBinary failed: %s", err)
	}
	if !bytes.Equal(data, remarshaled) {
		t.Error("binary round-trip mismatch")
	}
}

// TestEvmTxAccessListRoundTrip signs an EIP-1559 transaction carrying a
// non-trivial access list and verifies binary round-trip plus sender recovery.
// Because SenderAddress reconstructs the signed bytes (including the access
// list), a correct recovery proves the access list is encoded per spec.
func TestEvmTxAccessListRoundTrip(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))

	accessList := []*outscript.EvmAccessTuple{
		{
			Address: "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
			StorageKeys: []string{
				"0x0000000000000000000000000000000000000000000000000000000000000003",
				"0x0000000000000000000000000000000000000000000000000000000000000007",
			},
		},
		{
			Address:     "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
			StorageKeys: []string{},
		},
	}

	tx := &outscript.EvmTx{
		Type:       outscript.EvmTxEIP1559,
		ChainId:    1,
		Nonce:      9,
		GasTipCap:  big.NewInt(1500000000),
		GasFeeCap:  big.NewInt(30000000000),
		Gas:        120000,
		To:         "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7",
		Value:      big.NewInt(1000),
		AccessList: accessList,
	}
	if err := tx.Sign(key); err != nil {
		t.Fatalf("Sign failed: %s", err)
	}

	sender, err := tx.SenderAddress()
	if err != nil {
		t.Fatalf("SenderAddress failed: %s", err)
	}
	if sender != "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7" {
		t.Errorf("unexpected sender: %s", sender)
	}

	data, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %s", err)
	}

	var tx2 outscript.EvmTx
	if err := tx2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %s", err)
	}
	assertAccessListEqual(t, accessList, tx2.AccessList)

	// re-marshaling the parsed tx must reproduce identical bytes
	remarshaled, err := tx2.MarshalBinary()
	if err != nil {
		t.Fatalf("re-MarshalBinary failed: %s", err)
	}
	if !bytes.Equal(data, remarshaled) {
		t.Error("binary round-trip mismatch")
	}

	// parsed tx must still recover the same sender
	sender2, err := tx2.SenderAddress()
	if err != nil {
		t.Fatalf("parsed SenderAddress failed: %s", err)
	}
	if sender2 != sender {
		t.Errorf("sender mismatch after round-trip: %s != %s", sender2, sender)
	}
}

// TestEvmTxAccessListJSONRoundTrip verifies the access list survives JSON
// encoding/decoding.
func TestEvmTxAccessListJSONRoundTrip(t *testing.T) {
	accessList := []*outscript.EvmAccessTuple{
		{
			Address:     "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
			StorageKeys: []string{"0x0000000000000000000000000000000000000000000000000000000000000003"},
		},
	}
	tx := &outscript.EvmTx{
		Type:       outscript.EvmTxEIP1559,
		ChainId:    1,
		Nonce:      9,
		GasTipCap:  big.NewInt(1500000000),
		GasFeeCap:  big.NewInt(30000000000),
		Gas:        120000,
		To:         "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7",
		Value:      big.NewInt(1000),
		AccessList: accessList,
	}

	jsonData, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %s", err)
	}

	var tx2 outscript.EvmTx
	if err := json.Unmarshal(jsonData, &tx2); err != nil {
		t.Fatalf("UnmarshalJSON failed: %s", err)
	}
	assertAccessListEqual(t, accessList, tx2.AccessList)
}

// TestEvmTxAccessListMalformed verifies a malformed access list tuple is
// rejected rather than panicking (tuple with 1 field instead of 2).
func TestEvmTxAccessListMalformed(t *testing.T) {
	// 0x01 || rlp([1, 2, 3, 4, "", 5, "", [[0x01]]]) -- tuple has 1 field
	// access_list = c2 c1 01
	buf := must(hex.DecodeString("01ca01020304800580c2c101"))
	var tx outscript.EvmTx
	if err := tx.ParseTransaction(buf); err == nil {
		t.Fatal("expected error for malformed access list tuple, got nil")
	}
}

func assertAccessListEqual(t *testing.T, want, got []*outscript.EvmAccessTuple) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("access list length mismatch: want %d, got %d", len(want), len(got))
	}
	for i := range want {
		if want[i].Address != got[i].Address {
			t.Errorf("tuple %d address mismatch: want %s, got %s", i, want[i].Address, got[i].Address)
		}
		if len(want[i].StorageKeys) != len(got[i].StorageKeys) {
			t.Errorf("tuple %d storage key count mismatch: want %d, got %d", i, len(want[i].StorageKeys), len(got[i].StorageKeys))
			continue
		}
		for j := range want[i].StorageKeys {
			if want[i].StorageKeys[j] != got[i].StorageKeys[j] {
				t.Errorf("tuple %d key %d mismatch: want %s, got %s", i, j, want[i].StorageKeys[j], got[i].StorageKeys[j])
			}
		}
	}
}
