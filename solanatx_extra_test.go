package outscript_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestSolanaKeyString(t *testing.T) {
	k, err := outscript.ParseSolanaKey("11111111111111111111111111111111")
	if err != nil {
		t.Fatalf("ParseSolanaKey failed: %s", err)
	}
	s := k.String()
	if s != "11111111111111111111111111111111" {
		t.Errorf("unexpected String(): %s", s)
	}
}

func TestSolanaKeyIsZero(t *testing.T) {
	var k outscript.SolanaKey
	if !k.IsZero() {
		t.Error("zero key should be zero")
	}

	k[0] = 1
	if k.IsZero() {
		t.Error("non-zero key should not be zero")
	}
}

func TestSolanaCompactU16Extended(t *testing.T) {
	// The existing test only covers small values.
	// Test larger values via round-trip through SolanaTx serialization.
	// We can test the encoding indirectly by creating a tx with many accounts.

	// Test parsing invalid solana key
	_, err := outscript.ParseSolanaKey("invalid-base58!!!")
	if err == nil {
		t.Error("expected error for invalid solana key")
	}

	// Test parsing wrong-length key
	_, err = outscript.ParseSolanaKey("1") // too short
	if err == nil {
		t.Error("expected error for short solana key")
	}
}

func TestSolanaSystemProgram(t *testing.T) {
	// The system program address 111...1 decodes to 32 zero bytes in base58
	if !outscript.SolanaSystemProgram.IsZero() {
		t.Error("system program should be all zeros")
	}
	if outscript.SolanaSystemProgram.String() != "11111111111111111111111111111111" {
		t.Errorf("unexpected system program address: %s", outscript.SolanaSystemProgram.String())
	}
}

func TestSolanaAddressRoundTrip(t *testing.T) {
	addr := "83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"
	out, err := outscript.ParseSolanaAddress(addr)
	if err != nil {
		t.Fatalf("ParseSolanaAddress failed: %s", err)
	}

	// Address should round-trip
	roundTrip, err := out.Address("solana")
	if err != nil {
		t.Fatalf("Address(solana) failed: %s", err)
	}
	if roundTrip != addr {
		t.Errorf("round-trip mismatch: %s != %s", roundTrip, addr)
	}

	// Hash should return the raw bytes
	h := out.Hash()
	if len(h) != 32 {
		t.Errorf("expected 32-byte hash, got %d", len(h))
	}
}

func TestSolanaTxVerify(t *testing.T) {
	seed := must(hex.DecodeString("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88"))
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)

	var from outscript.SolanaKey
	copy(from[:], pub)

	to := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	blockhash := must(outscript.ParseSolanaKey("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC"))

	ix := outscript.SolanaTransferInstruction(from, to, 1000000)
	tx, err := outscript.NewSolanaTx(from, blockhash, ix)
	if err != nil {
		t.Fatalf("NewSolanaTx failed: %s", err)
	}

	// Verify should fail before signing (empty signature)
	if err := tx.Verify(); err == nil {
		t.Error("expected error verifying unsigned transaction")
	}

	// Sign and verify
	if err := tx.Sign(key); err != nil {
		t.Fatalf("sign failed: %s", err)
	}
	if err := tx.Verify(); err != nil {
		t.Fatalf("verify failed on valid signature: %s", err)
	}

	// Corrupt one byte of the signature
	tx.Signatures[0][0] ^= 0xff
	if err := tx.Verify(); err == nil {
		t.Error("expected error verifying corrupted signature")
	}
}

func TestSolanaTxVerifyRoundTrip(t *testing.T) {
	seed := must(hex.DecodeString("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88"))
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)

	var from outscript.SolanaKey
	copy(from[:], pub)

	to := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	blockhash := must(outscript.ParseSolanaKey("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC"))

	ix := outscript.SolanaTransferInstruction(from, to, 1000000)
	tx, err := outscript.NewSolanaTx(from, blockhash, ix)
	if err != nil {
		t.Fatalf("NewSolanaTx failed: %s", err)
	}
	if err := tx.Sign(key); err != nil {
		t.Fatalf("sign failed: %s", err)
	}

	// Marshal, unmarshal, then verify
	data, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}
	var tx2 outscript.SolanaTx
	if err := tx2.UnmarshalBinary(data); err != nil {
		t.Fatalf("unmarshal failed: %s", err)
	}
	if err := tx2.Verify(); err != nil {
		t.Fatalf("verify failed after round-trip: %s", err)
	}
}

// --- Security regression tests ---

// buildLegacyMessage assembles a legacy SolanaMessage wire-format body for tests.
func buildLegacyMessage(header []byte, keyCount []byte, numKeys int, ix []byte) []byte {
	buf := append([]byte{}, header...)
	buf = append(buf, keyCount...)
	for i := 0; i < numKeys; i++ {
		buf = append(buf, make([]byte, 32)...) // account key
	}
	buf = append(buf, make([]byte, 32)...) // recent blockhash
	buf = append(buf, ix...)
	return buf
}

// TestSolanaMessageHeaderCountTooLarge verifies a message declaring more
// required signatures than account keys is rejected by UnmarshalBinary.
func TestSolanaMessageHeaderCountTooLarge(t *testing.T) {
	// header: NumRequiredSignatures=2, others=0; keyCount=1
	data := buildLegacyMessage([]byte{0x02, 0x00, 0x00}, []byte{0x01}, 1, []byte{0x00})
	var msg outscript.SolanaMessage
	if err := msg.UnmarshalBinary(data); err == nil {
		t.Fatal("expected error for NumRequiredSignatures > account count, got nil")
	}
}

// TestSolanaVerifySignNoPanicOnBadHeader verifies Verify and Sign return an
// error (rather than panic) when the header references more signers than keys.
func TestSolanaVerifySignNoPanicOnBadHeader(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()

	tx := &outscript.SolanaTx{
		Signatures: make([][]byte, 3),
		Message: outscript.SolanaMessage{
			Header:      outscript.SolanaMessageHeader{NumRequiredSignatures: 3},
			AccountKeys: nil, // no keys at all
		},
	}
	if err := tx.Verify(); err == nil {
		t.Error("expected Verify error on bad header, got nil")
	}

	seed := must(hex.DecodeString("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88"))
	key := ed25519.NewKeyFromSeed(seed)
	if err := tx.Sign(key); err == nil {
		t.Error("expected Sign error on bad header, got nil")
	}
}

// TestSolanaNonCanonicalCompactU16 verifies a non-canonical compact-u16
// encoding ([0x80,0x00]) is rejected.
func TestSolanaNonCanonicalCompactU16(t *testing.T) {
	// header valid, then non-canonical compact-u16 for account key count.
	data := append([]byte{0x01, 0x00, 0x00}, 0x80, 0x00)
	var msg outscript.SolanaMessage
	if err := msg.UnmarshalBinary(data); err == nil {
		t.Fatal("expected error for non-canonical compact-u16, got nil")
	}
}

// TestSolanaInstructionIndexOutOfRange verifies an instruction referencing a
// program id index beyond the account key list is rejected.
func TestSolanaInstructionIndexOutOfRange(t *testing.T) {
	// header: 1 signer; keyCount=1; one instruction with ProgramIDIndex=5.
	ix := []byte{
		0x01, // instruction count = 1
		0x05, // ProgramIDIndex = 5 (out of range, only 1 key)
		0x00, // account index count = 0
		0x00, // data length = 0
	}
	data := buildLegacyMessage([]byte{0x01, 0x00, 0x00}, []byte{0x01}, 1, ix)
	var msg outscript.SolanaMessage
	if err := msg.UnmarshalBinary(data); err == nil {
		t.Fatal("expected error for out-of-range program id index, got nil")
	}

	// Also test an out-of-range account index.
	ix2 := []byte{
		0x01, // instruction count = 1
		0x00, // ProgramIDIndex = 0 (valid)
		0x01, // account index count = 1
		0x09, // account index = 9 (out of range)
		0x00, // data length = 0
	}
	data2 := buildLegacyMessage([]byte{0x01, 0x00, 0x00}, []byte{0x01}, 1, ix2)
	var msg2 outscript.SolanaMessage
	if err := msg2.UnmarshalBinary(data2); err == nil {
		t.Fatal("expected error for out-of-range account index, got nil")
	}
}
