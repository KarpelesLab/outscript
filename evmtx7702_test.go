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

// TestEvmAuthorizationSign verifies an EIP-7702 authorization can be signed and
// its authority recovered.
func TestEvmAuthorizationSign(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))

	auth := &outscript.EvmAuthorization{
		ChainId: 1,
		Address: "0x1111111111111111111111111111111111111111",
		Nonce:   7,
	}
	if err := auth.Sign(key); err != nil {
		t.Fatalf("authorization Sign failed: %s", err)
	}
	if !auth.Signed {
		t.Fatal("expected authorization to be signed")
	}
	// y_parity must be 0 or 1 (no EIP-155 on authorizations)
	if v := auth.Y.Uint64(); v != 0 && v != 1 {
		t.Errorf("expected y_parity 0 or 1, got %d", v)
	}

	authority, err := auth.Authority()
	if err != nil {
		t.Fatalf("Authority failed: %s", err)
	}
	// the signing key's own eth address, since it authorized itself
	if authority != "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7" {
		t.Errorf("unexpected authority: %s", authority)
	}
}

// TestEvmTxEIP7702SignRoundTrip signs an EIP-7702 transaction bundling an
// authorization and verifies binary round-trip and sender/authority recovery.
func TestEvmTxEIP7702SignRoundTrip(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))

	auth := &outscript.EvmAuthorization{
		ChainId: 1,
		Address: "0x00000000000000000000000000000000000000aa",
		Nonce:   0,
	}
	if err := auth.Sign(key); err != nil {
		t.Fatalf("authorization Sign failed: %s", err)
	}

	tx := &outscript.EvmTx{
		Type:      outscript.EvmTxEIP7702,
		ChainId:   1,
		Nonce:     3,
		GasTipCap: big.NewInt(1000000000),
		GasFeeCap: big.NewInt(20000000000),
		Gas:       100000,
		To:        "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7",
		Value:     big.NewInt(0),
		AuthList:  []*outscript.EvmAuthorization{auth},
	}
	if err := tx.Sign(key); err != nil {
		t.Fatalf("tx Sign failed: %s", err)
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
	if data[0] != 0x04 {
		t.Errorf("expected type byte 0x04, got 0x%02x", data[0])
	}

	var tx2 outscript.EvmTx
	if err := tx2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %s", err)
	}
	if tx2.Type != outscript.EvmTxEIP7702 {
		t.Errorf("expected EIP7702 type, got %d", tx2.Type)
	}
	if len(tx2.AuthList) != 1 {
		t.Fatalf("expected 1 authorization, got %d", len(tx2.AuthList))
	}
	if tx2.AuthList[0].Address != "0x00000000000000000000000000000000000000aa" {
		t.Errorf("unexpected authorization address: %s", tx2.AuthList[0].Address)
	}
	if tx2.Nonce != tx.Nonce || tx2.ChainId != tx.ChainId {
		t.Error("scalar field mismatch after round-trip")
	}

	// recovered authority from parsed tx must match
	authority, err := tx2.AuthList[0].Authority()
	if err != nil {
		t.Fatalf("parsed Authority failed: %s", err)
	}
	if authority != "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7" {
		t.Errorf("unexpected parsed authority: %s", authority)
	}

	// re-marshaling the parsed tx must reproduce the identical bytes
	remarshaled, err := tx2.MarshalBinary()
	if err != nil {
		t.Fatalf("re-MarshalBinary failed: %s", err)
	}
	if !bytes.Equal(data, remarshaled) {
		t.Error("binary round-trip mismatch for EIP-7702")
	}
}

// TestEvmTxEIP7702JSONRoundTrip verifies the authorization list survives JSON
// encoding/decoding.
func TestEvmTxEIP7702JSONRoundTrip(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))

	auth := &outscript.EvmAuthorization{ChainId: 0, Address: "0x00000000000000000000000000000000000000aa", Nonce: 5}
	if err := auth.Sign(key); err != nil {
		t.Fatalf("authorization Sign failed: %s", err)
	}
	tx := &outscript.EvmTx{
		Type:      outscript.EvmTxEIP7702,
		ChainId:   1,
		Nonce:     3,
		GasTipCap: big.NewInt(1000000000),
		GasFeeCap: big.NewInt(20000000000),
		Gas:       100000,
		To:        "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7",
		Value:     big.NewInt(0),
		AuthList:  []*outscript.EvmAuthorization{auth},
	}
	if err := tx.Sign(key); err != nil {
		t.Fatalf("Sign failed: %s", err)
	}

	jsonData, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %s", err)
	}

	var tx2 outscript.EvmTx
	if err := json.Unmarshal(jsonData, &tx2); err != nil {
		t.Fatalf("UnmarshalJSON failed: %s", err)
	}
	if tx2.Type != outscript.EvmTxEIP7702 {
		t.Errorf("expected EIP7702 type from JSON, got %d", tx2.Type)
	}
	if len(tx2.AuthList) != 1 {
		t.Fatalf("expected 1 authorization from JSON, got %d", len(tx2.AuthList))
	}
	if tx2.AuthList[0].Nonce != 5 || tx2.AuthList[0].ChainId != 0 {
		t.Errorf("authorization scalar mismatch: nonce=%d chainId=%d", tx2.AuthList[0].Nonce, tx2.AuthList[0].ChainId)
	}
	authority, err := tx2.AuthList[0].Authority()
	if err != nil {
		t.Fatalf("Authority from JSON failed: %s", err)
	}
	if authority != "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7" {
		t.Errorf("unexpected authority from JSON: %s", authority)
	}
}

// TestEvmTxEIP7702ParseMalformed verifies malformed authorization tuples are
// rejected rather than panicking.
func TestEvmTxEIP7702ParseMalformed(t *testing.T) {
	// 0x04 || rlp([...8 scalar fields..., access_list=[], authorization_list=[ [a,b] ] ])
	// the authorization tuple has 2 fields instead of 6
	buf := must(hex.DecodeString("04" + "cd" + "01018080808080" + "80" + "c0" + "c4c20102"))
	var tx outscript.EvmTx
	if err := tx.ParseTransaction(buf); err == nil {
		t.Fatal("expected error for malformed authorization tuple, got nil")
	}
}
