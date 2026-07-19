package outscript_test

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/KarpelesLab/outscript"
	"github.com/KarpelesLab/secp256k1"
)

// TestTronAddressVector validates Base58Check encode/decode against a well-known
// mainnet address: the USDT (TRC20) contract.
//
//	TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t <-> 41a614f803b6fd780986a42c78ec9c7f77e6ded13c
func TestTronAddressVector(t *testing.T) {
	const addr = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
	const wantHex = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"

	raw, err := outscript.DecodeTronAddress(addr)
	if err != nil {
		t.Fatalf("DecodeTronAddress failed: %s", err)
	}
	if got := hex.EncodeToString(raw); got != wantHex {
		t.Errorf("decode mismatch: got %s, want %s", got, wantHex)
	}
	if got := outscript.EncodeTronAddress(raw); got != addr {
		t.Errorf("encode mismatch: got %s, want %s", got, addr)
	}
}

func TestTronAddressBadChecksum(t *testing.T) {
	// flip the last character of a valid address
	if _, err := outscript.DecodeTronAddress("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6a"); err == nil {
		t.Fatal("expected checksum error, got nil")
	}
}

// TestTronAddressFromKey derives a Tron address from a key whose eth address is
// already known-correct, and asserts the address payload is 0x41 || <eth hash>.
func TestTronAddressFromKey(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))

	addr, err := outscript.New(key.PubKey()).Address("tron")
	if err != nil {
		t.Fatalf("Address(tron) failed: %s", err)
	}
	if addr[0] != 'T' {
		t.Errorf("tron address should start with T, got %s", addr)
	}

	raw, err := outscript.DecodeTronAddress(addr)
	if err != nil {
		t.Fatalf("round-trip DecodeTronAddress failed: %s", err)
	}
	// 0x41 followed by the key's known eth 20-byte account hash
	const wantHex = "412aeb8add8337360e088b7d9ce4e857b9be60f3a7"
	if got := hex.EncodeToString(raw); got != wantHex {
		t.Errorf("tron payload mismatch: got %s, want %s", got, wantHex)
	}

	// ParseTronAddress must reproduce the same raw payload
	out, err := outscript.ParseTronAddress(addr)
	if err != nil {
		t.Fatalf("ParseTronAddress failed: %s", err)
	}
	if hex.EncodeToString(out.Bytes()) != wantHex {
		t.Errorf("ParseTronAddress raw mismatch: got %x", out.Bytes())
	}
}

// TestTronTxTransfer builds and signs a native TRX transfer, then independently
// validates the resulting protobuf structure and recovers the signer.
func TestTronTxTransfer(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	from, err := outscript.New(key.PubKey()).Address("tron")
	if err != nil {
		t.Fatalf("from address failed: %s", err)
	}
	const to = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
	const amount = 1000000

	tx := &outscript.TronTx{
		RefBlockBytes: []byte{0x12, 0x34},
		RefBlockHash:  []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Expiration:    1600000060000,
		Timestamp:     1600000000000,
		FeeLimit:      1000000000,
	}
	if err := tx.AddTransfer(from, to, amount); err != nil {
		t.Fatalf("AddTransfer failed: %s", err)
	}
	if err := tx.Sign(key); err != nil {
		t.Fatalf("Sign failed: %s", err)
	}

	// signer recovery must match the from address
	signers, err := tx.SignerAddresses()
	if err != nil {
		t.Fatalf("SignerAddresses failed: %s", err)
	}
	if len(signers) != 1 || signers[0] != from {
		t.Errorf("signer mismatch: got %v, want [%s]", signers, from)
	}

	bin, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %s", err)
	}

	// --- independent protobuf structure validation ---
	top, err := pbScan(bin)
	if err != nil {
		t.Fatalf("pbScan(top) failed: %s", err)
	}
	rawEntry := pbFind(top, 1) // raw_data
	if rawEntry == nil || rawEntry.wire != 2 {
		t.Fatal("missing raw_data (field 1)")
	}
	sigEntry := pbFind(top, 2) // signature
	if sigEntry == nil || len(sigEntry.data) != 65 {
		t.Fatalf("missing/invalid signature (field 2): %+v", sigEntry)
	}

	raw, err := pbScan(rawEntry.data)
	if err != nil {
		t.Fatalf("pbScan(raw) failed: %s", err)
	}
	if e := pbFind(raw, 1); e == nil || hex.EncodeToString(e.data) != "1234" {
		t.Errorf("ref_block_bytes mismatch: %+v", e)
	}
	if e := pbFind(raw, 4); e == nil || hex.EncodeToString(e.data) != "0102030405060708" {
		t.Errorf("ref_block_hash mismatch: %+v", e)
	}
	if e := pbFind(raw, 8); e == nil || e.val != 1600000060000 {
		t.Errorf("expiration mismatch: %+v", e)
	}
	if e := pbFind(raw, 14); e == nil || e.val != 1600000000000 {
		t.Errorf("timestamp mismatch: %+v", e)
	}
	if e := pbFind(raw, 18); e == nil || e.val != 1000000000 {
		t.Errorf("fee_limit mismatch: %+v", e)
	}

	contractEntry := pbFind(raw, 11)
	if contractEntry == nil {
		t.Fatal("missing contract (field 11)")
	}
	contract, err := pbScan(contractEntry.data)
	if err != nil {
		t.Fatalf("pbScan(contract) failed: %s", err)
	}
	if e := pbFind(contract, 1); e == nil || e.val != uint64(outscript.TronTransferContract) {
		t.Errorf("contract type mismatch: %+v", e)
	}
	anyEntry := pbFind(contract, 2)
	if anyEntry == nil {
		t.Fatal("missing contract parameter (Any)")
	}
	anyFields, err := pbScan(anyEntry.data)
	if err != nil {
		t.Fatalf("pbScan(any) failed: %s", err)
	}
	if e := pbFind(anyFields, 1); e == nil || string(e.data) != "type.googleapis.com/protocol.TransferContract" {
		t.Errorf("type_url mismatch: %q", e)
	}
	valueEntry := pbFind(anyFields, 2)
	if valueEntry == nil {
		t.Fatal("missing Any.value")
	}
	value, err := pbScan(valueEntry.data)
	if err != nil {
		t.Fatalf("pbScan(value) failed: %s", err)
	}
	fromRaw := must(outscript.DecodeTronAddress(from))
	toRaw := must(outscript.DecodeTronAddress(to))
	if e := pbFind(value, 1); e == nil || hex.EncodeToString(e.data) != hex.EncodeToString(fromRaw) {
		t.Errorf("owner_address mismatch: %+v", e)
	}
	if e := pbFind(value, 2); e == nil || hex.EncodeToString(e.data) != hex.EncodeToString(toRaw) {
		t.Errorf("to_address mismatch: %+v", e)
	}
	if e := pbFind(value, 3); e == nil || e.val != amount {
		t.Errorf("amount mismatch: %+v", e)
	}
}

// TestTronTxTriggerSmartContract exercises the TRC20-style contract call path.
func TestTronTxTriggerSmartContract(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	from := must(outscript.New(key.PubKey()).Address("tron"))
	const usdt = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

	// arbitrary call data (would normally be an ABI-encoded transfer(address,uint256))
	data := must(hex.DecodeString("a9059cbb"))

	tx := &outscript.TronTx{
		RefBlockBytes: []byte{0x00, 0x01},
		RefBlockHash:  []byte{8, 7, 6, 5, 4, 3, 2, 1},
		Expiration:    1600000060000,
		Timestamp:     1600000000000,
		FeeLimit:      100000000,
	}
	if err := tx.AddTriggerSmartContract(from, usdt, 0, data); err != nil {
		t.Fatalf("AddTriggerSmartContract failed: %s", err)
	}
	if err := tx.Sign(key); err != nil {
		t.Fatalf("Sign failed: %s", err)
	}

	signers, err := tx.SignerAddresses()
	if err != nil {
		t.Fatalf("SignerAddresses failed: %s", err)
	}
	if len(signers) != 1 || signers[0] != from {
		t.Errorf("signer mismatch: got %v, want [%s]", signers, from)
	}

	// verify the contract type url encodes as TriggerSmartContract
	bin := must(tx.MarshalBinary())
	top := must(pbScan(bin))
	raw := must(pbScan(pbFind(top, 1).data))
	contract := must(pbScan(pbFind(raw, 11).data))
	if e := pbFind(contract, 1); e == nil || e.val != uint64(outscript.TronTriggerSmartContract) {
		t.Errorf("contract type mismatch: %+v", e)
	}
	anyFields := must(pbScan(pbFind(contract, 2).data))
	if e := pbFind(anyFields, 1); e == nil || string(e.data) != "type.googleapis.com/protocol.TriggerSmartContract" {
		t.Errorf("type_url mismatch: %q", e)
	}
	value := must(pbScan(pbFind(anyFields, 2).data))
	if e := pbFind(value, 4); e == nil || hex.EncodeToString(e.data) != "a9059cbb" {
		t.Errorf("call data mismatch: %+v", e)
	}
}

// TestTronTxTRC20Transfer verifies the TRC20 convenience helper builds correct
// transfer(address,uint256) calldata inside a TriggerSmartContract.
func TestTronTxTRC20Transfer(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	from := must(outscript.New(key.PubKey()).Address("tron"))
	const usdt = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
	const recipient = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t" // reuse a known-valid T address
	amount := big.NewInt(123456)

	tx := &outscript.TronTx{
		RefBlockBytes: []byte{0x00, 0x01},
		RefBlockHash:  []byte{8, 7, 6, 5, 4, 3, 2, 1},
		Expiration:    1600000060000,
		Timestamp:     1600000000000,
		FeeLimit:      100000000,
	}
	if err := tx.AddTRC20Transfer(from, usdt, recipient, amount); err != nil {
		t.Fatalf("AddTRC20Transfer failed: %s", err)
	}
	if err := tx.Sign(key); err != nil {
		t.Fatalf("Sign failed: %s", err)
	}

	signers := must(tx.SignerAddresses())
	if len(signers) != 1 || signers[0] != from {
		t.Errorf("signer mismatch: got %v, want [%s]", signers, from)
	}

	bin := must(tx.MarshalBinary())
	top := must(pbScan(bin))
	raw := must(pbScan(pbFind(top, 1).data))
	contract := must(pbScan(pbFind(raw, 11).data))
	if e := pbFind(contract, 1); e == nil || e.val != uint64(outscript.TronTriggerSmartContract) {
		t.Errorf("contract type mismatch: %+v", e)
	}
	anyFields := must(pbScan(pbFind(contract, 2).data))
	if e := pbFind(anyFields, 1); e == nil || string(e.data) != "type.googleapis.com/protocol.TriggerSmartContract" {
		t.Errorf("type_url mismatch: %q", e)
	}
	value := must(pbScan(pbFind(anyFields, 2).data))
	// contract_address (field 2) must be the token contract
	usdtRaw := must(outscript.DecodeTronAddress(usdt))
	if e := pbFind(value, 2); e == nil || hex.EncodeToString(e.data) != hex.EncodeToString(usdtRaw) {
		t.Errorf("contract address mismatch: %+v", e)
	}
	// call data (field 4) = selector || padded(recipient 20 bytes) || padded(amount)
	dataEntry := pbFind(value, 4)
	if dataEntry == nil {
		t.Fatal("missing call data (field 4)")
	}
	data := dataEntry.data
	if len(data) != 68 {
		t.Fatalf("expected 68 bytes of calldata, got %d", len(data))
	}
	if hex.EncodeToString(data[:4]) != "a9059cbb" {
		t.Errorf("wrong selector: %x", data[:4])
	}
	// recipient is the 20-byte form (Tron address minus 0x41 prefix), left-padded
	recipient20 := must(outscript.DecodeTronAddress(recipient))[1:]
	if hex.EncodeToString(data[4:36][12:]) != hex.EncodeToString(recipient20) {
		t.Errorf("recipient mismatch in calldata: %x", data[4:36])
	}
	if got := new(big.Int).SetBytes(data[36:68]); got.Cmp(amount) != 0 {
		t.Errorf("amount mismatch in calldata: got %s, want %s", got, amount)
	}
}

func TestTronTxTRC20TransferNegative(t *testing.T) {
	tx := &outscript.TronTx{}
	err := tx.AddTRC20Transfer("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", big.NewInt(-1))
	if err == nil {
		t.Fatal("expected error for negative amount, got nil")
	}
}

func TestTronTxNoContracts(t *testing.T) {
	tx := &outscript.TronTx{}
	if _, err := tx.MarshalBinary(); err == nil {
		t.Fatal("expected error for tx with no contracts, got nil")
	}
}

// --- generic protobuf scanner used to validate the encoder independently ---

type pbEntry struct {
	field int
	wire  int
	val   uint64 // for varint (wire 0)
	data  []byte // for length-delimited (wire 2)
}

func pbScan(buf []byte) ([]pbEntry, error) {
	var out []pbEntry
	i := 0
	for i < len(buf) {
		tag, n := binary.Uvarint(buf[i:])
		if n <= 0 {
			return nil, fmt.Errorf("bad tag at %d", i)
		}
		i += n
		field := int(tag >> 3)
		wire := int(tag & 7)
		switch wire {
		case 0:
			v, n := binary.Uvarint(buf[i:])
			if n <= 0 {
				return nil, fmt.Errorf("bad varint at %d", i)
			}
			i += n
			out = append(out, pbEntry{field: field, wire: wire, val: v})
		case 2:
			l, n := binary.Uvarint(buf[i:])
			if n <= 0 {
				return nil, fmt.Errorf("bad length at %d", i)
			}
			i += n
			if i+int(l) > len(buf) {
				return nil, fmt.Errorf("truncated length-delimited field at %d", i)
			}
			out = append(out, pbEntry{field: field, wire: wire, data: buf[i : i+int(l)]})
			i += int(l)
		default:
			return nil, fmt.Errorf("unsupported wire type %d for field %d", wire, field)
		}
	}
	return out, nil
}

func pbFind(entries []pbEntry, field int) *pbEntry {
	for i := range entries {
		if entries[i].field == field {
			return &entries[i]
		}
	}
	return nil
}
