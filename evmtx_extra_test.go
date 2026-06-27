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

func TestEvmTxMarshalUnmarshalBinary(t *testing.T) {
	// Parse a known legacy tx, marshal it back, verify round-trip
	txBin := must(hex.DecodeString("f86b1e8507ea8ed4008252089443badf0e63ac147ace611dc1113afe0ea3f8691787d529ae9e8600008026a0cacce90eb140f837a139e5d8acbe73527663aea163d4e4c6e8218681d1d37b0fa07fdb860517234804b71bbc518ecb4dc4bb96c1944ab28d502fc429baac939b3c"))
	tx := &outscript.EvmTx{}
	err := tx.UnmarshalBinary(txBin)
	if err != nil {
		t.Fatalf("UnmarshalBinary failed: %s", err)
	}

	marshaled, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %s", err)
	}
	if !bytes.Equal(txBin, marshaled) {
		t.Error("round-trip binary mismatch")
	}
}

func TestEvmTxEIP1559MarshalUnmarshal(t *testing.T) {
	txBin := must(hex.DecodeString("02f87101830bdfbb80850243e1963982798e94e866fecdb429c72c30868d3582192a878298698487d3c0ba13571e2080c080a08032999a5ae9477f5f52134c9dc1690d1e25d0bb78ef0f22b949afd0df73a9e4a07106563a788499eb370a48e7c86c08e357866fcc12867a8c530b5ca22175e784"))
	tx := &outscript.EvmTx{}
	err := tx.UnmarshalBinary(txBin)
	if err != nil {
		t.Fatalf("UnmarshalBinary failed: %s", err)
	}

	if tx.Type != outscript.EvmTxEIP1559 {
		t.Errorf("expected EIP1559, got type %d", tx.Type)
	}
	if tx.ChainId != 1 {
		t.Errorf("expected chainId 1, got %d", tx.ChainId)
	}

	marshaled, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %s", err)
	}
	if !bytes.Equal(txBin, marshaled) {
		t.Error("round-trip binary mismatch for EIP-1559")
	}
}

func TestEvmTxJSONRoundTrip(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	tx := &outscript.EvmTx{
		ChainId:   1,
		Nonce:     42,
		GasFeeCap: big.NewInt(30000000000),
		Gas:       21000,
		To:        "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7",
		Value:     big.NewInt(1000000000000000000),
	}
	err := tx.Sign(key)
	if err != nil {
		t.Fatalf("Sign failed: %s", err)
	}

	jsonData, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %s", err)
	}

	var tx2 outscript.EvmTx
	err = json.Unmarshal(jsonData, &tx2)
	if err != nil {
		t.Fatalf("UnmarshalJSON failed: %s", err)
	}

	if tx2.Nonce != tx.Nonce {
		t.Errorf("nonce mismatch: %d != %d", tx2.Nonce, tx.Nonce)
	}
	if tx2.Gas != tx.Gas {
		t.Errorf("gas mismatch: %d != %d", tx2.Gas, tx.Gas)
	}
	if tx2.ChainId != tx.ChainId {
		t.Errorf("chainId mismatch: %d != %d", tx2.ChainId, tx.ChainId)
	}
	if tx2.Value.Cmp(tx.Value) != 0 {
		t.Errorf("value mismatch: %s != %s", tx2.Value, tx.Value)
	}
}

func TestEvmTxCall(t *testing.T) {
	tx := &outscript.EvmTx{}
	// Use a function with uint256 params only since AppendAddressAny is not yet implemented
	err := tx.Call("approve(uint256,uint256)", big.NewInt(100), big.NewInt(200))
	if err != nil {
		t.Fatalf("Call failed: %s", err)
	}
	if len(tx.Data) != 68 { // 4 byte selector + 32 byte uint256 + 32 byte uint256
		t.Errorf("expected 68 bytes of calldata, got %d", len(tx.Data))
	}
	// Verify we got a 4-byte selector followed by encoded params
	if len(tx.Data) >= 4 {
		// selector should be non-zero
		if tx.Data[0] == 0 && tx.Data[1] == 0 && tx.Data[2] == 0 && tx.Data[3] == 0 {
			t.Error("expected non-zero function selector")
		}
	}
}

func TestEvmTxHashUnsigned(t *testing.T) {
	tx := &outscript.EvmTx{
		ChainId:   1,
		Nonce:     0,
		GasFeeCap: big.NewInt(1000000000),
		Gas:       21000,
		To:        "0x0000000000000000000000000000000000000000",
		Value:     big.NewInt(0),
	}
	// Hash of unsigned tx should still work (it hashes the sign bytes)
	h, err := tx.Hash()
	if err != nil {
		t.Fatalf("Hash failed: %s", err)
	}
	if len(h) != 32 {
		t.Errorf("expected 32-byte hash, got %d", len(h))
	}
}

func TestEvmTxEIP1559Sign(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	tx := &outscript.EvmTx{
		Type:      outscript.EvmTxEIP1559,
		ChainId:   1,
		Nonce:     0,
		GasTipCap: big.NewInt(1000000000),
		GasFeeCap: big.NewInt(20000000000),
		Gas:       21000,
		To:        "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7",
		Value:     big.NewInt(1000000000000000000),
	}

	err := tx.Sign(key)
	if err != nil {
		t.Fatalf("Sign EIP1559 failed: %s", err)
	}
	if !tx.Signed {
		t.Error("expected tx to be signed")
	}

	sender, err := tx.SenderAddress()
	if err != nil {
		t.Fatalf("SenderAddress failed: %s", err)
	}
	if sender != "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7" {
		t.Errorf("unexpected sender: %s", sender)
	}

	// Binary round-trip
	data, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %s", err)
	}
	var tx2 outscript.EvmTx
	err = tx2.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("UnmarshalBinary failed: %s", err)
	}
	if tx2.Type != outscript.EvmTxEIP1559 {
		t.Errorf("expected EIP1559 type after round-trip")
	}
}

// TestEvmTxPreEIP155NoPanic verifies that a pre-EIP-155 legacy transaction
// (ChainId == 0, v == 27/28) can be signed and have its sender recovered without
// panicking in Signature()/SenderAddress()/MarshalJSON().
func TestEvmTxPreEIP155NoPanic(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))

	// ChainId == 0 => super-legacy / pre-EIP-155, Y becomes 27 or 28
	tx := &outscript.EvmTx{ChainId: 0, Nonce: 42, GasFeeCap: big.NewInt(30000000000), Gas: 21000, To: "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7", Value: new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)}

	if err := tx.Sign(key); err != nil {
		t.Fatalf("Sign failed: %s", err)
	}
	v := tx.Y.Uint64()
	if v != 27 && v != 28 {
		t.Fatalf("expected pre-EIP-155 v of 27 or 28, got %d", v)
	}

	// Signature() must not panic and must succeed
	if _, err := tx.Signature(); err != nil {
		t.Fatalf("Signature failed: %s", err)
	}

	sender, err := tx.SenderAddress()
	if err != nil {
		t.Fatalf("SenderAddress failed: %s", err)
	}
	if sender != "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7" {
		t.Errorf("unexpected sender: %s", sender)
	}

	// MarshalJSON must not panic
	if _, err := json.Marshal(tx); err != nil {
		t.Fatalf("MarshalJSON failed: %s", err)
	}
}

// TestEvmTxSignatureInvalidLegacyV verifies an out-of-range pre-EIP-155 v value
// is rejected with an error rather than panicking.
func TestEvmTxSignatureInvalidLegacyV(t *testing.T) {
	tx := &outscript.EvmTx{
		Type:   outscript.EvmTxLegacy,
		Signed: true,
		Y:      big.NewInt(30), // invalid: not 27/28 and < 35
		R:      big.NewInt(1),
		S:      big.NewInt(1),
	}
	if _, err := tx.Signature(); err == nil {
		t.Fatal("expected error for invalid pre-EIP-155 v value, got nil")
	}
}

// TestParseTransactionMalformedNonce verifies a legacy tx with a 9-byte nonce
// field returns an error instead of panicking in rlp.DecodeUint64.
func TestParseTransactionMalformedNonce(t *testing.T) {
	// legacy 6-field list: nonce(9 bytes), gasPrice, gas, to, value, data
	buf := must(hex.DecodeString("cf89000000000000000001" + "8080808080"))
	var tx outscript.EvmTx
	err := tx.ParseTransaction(buf)
	if err == nil {
		t.Fatal("expected error for 9-byte nonce field, got nil")
	}
}

// TestParseTransactionMalformedTypedTx verifies a typed (EIP-1559) tx with a
// list where bytes are expected returns an error instead of panicking.
func TestParseTransactionMalformedTypedTx(t *testing.T) {
	// 0x02 || rlp([ [], 80, 80, 80, 80, 80, 80, 80, [] ]) -- field0 is a list
	buf := must(hex.DecodeString("02" + "c9" + "c0" + "80808080808080" + "c0"))
	var tx outscript.EvmTx
	err := tx.ParseTransaction(buf)
	if err == nil {
		t.Fatal("expected error for typed tx with list where bytes expected, got nil")
	}
}
