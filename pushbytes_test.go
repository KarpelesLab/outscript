package outscript_test

import (
	"bytes"
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestPushBytesSmall(t *testing.T) {
	data := make([]byte, 10)
	for i := range data {
		data[i] = byte(i)
	}
	pushed := outscript.PushBytes(data)
	if pushed[0] != 10 {
		t.Errorf("expected length byte 10, got %d", pushed[0])
	}
	if !bytes.Equal(pushed[1:], data) {
		t.Error("pushed data mismatch")
	}

	// Round-trip
	parsed, n := outscript.ParsePushBytes(pushed)
	if n != len(pushed) {
		t.Errorf("expected consumed %d bytes, got %d", len(pushed), n)
	}
	if !bytes.Equal(parsed, data) {
		t.Error("round-trip data mismatch")
	}
}

func TestPushBytes75(t *testing.T) {
	data := make([]byte, 75)
	pushed := outscript.PushBytes(data)
	if pushed[0] != 75 {
		t.Errorf("expected length byte 75, got %d", pushed[0])
	}
	parsed, n := outscript.ParsePushBytes(pushed)
	if n != 76 {
		t.Errorf("expected 76 bytes consumed, got %d", n)
	}
	if !bytes.Equal(parsed, data) {
		t.Error("round-trip mismatch for 75-byte push")
	}
}

func TestPushBytesOP_PUSHDATA1(t *testing.T) {
	data := make([]byte, 100)
	pushed := outscript.PushBytes(data)
	if pushed[0] != 0x4c {
		t.Errorf("expected OP_PUSHDATA1 (0x4c), got 0x%02x", pushed[0])
	}
	if pushed[1] != 100 {
		t.Errorf("expected length 100, got %d", pushed[1])
	}
	parsed, n := outscript.ParsePushBytes(pushed)
	if n != 102 {
		t.Errorf("expected 102 bytes consumed, got %d", n)
	}
	if !bytes.Equal(parsed, data) {
		t.Error("round-trip mismatch for OP_PUSHDATA1")
	}
}

func TestPushBytesOP_PUSHDATA2(t *testing.T) {
	data := make([]byte, 300)
	pushed := outscript.PushBytes(data)
	if pushed[0] != 0x4d {
		t.Errorf("expected OP_PUSHDATA2 (0x4d), got 0x%02x", pushed[0])
	}
	parsed, n := outscript.ParsePushBytes(pushed)
	if n != 303 {
		t.Errorf("expected 303 bytes consumed, got %d", n)
	}
	if !bytes.Equal(parsed, data) {
		t.Error("round-trip mismatch for OP_PUSHDATA2")
	}
}

func TestPushBytesOP_PUSHDATA4(t *testing.T) {
	data := make([]byte, 70000)
	pushed := outscript.PushBytes(data)
	if pushed[0] != 0x4e {
		t.Errorf("expected OP_PUSHDATA4 (0x4e), got 0x%02x", pushed[0])
	}
	parsed, n := outscript.ParsePushBytes(pushed)
	if n != 70005 {
		t.Errorf("expected 70005 bytes consumed, got %d", n)
	}
	if !bytes.Equal(parsed, data) {
		t.Error("round-trip mismatch for OP_PUSHDATA4")
	}
}

func TestParsePushBytesEmpty(t *testing.T) {
	parsed, n := outscript.ParsePushBytes(nil)
	if parsed != nil || n != 0 {
		t.Error("expected nil,0 for empty input")
	}
}

func TestParsePushBytesTooShort(t *testing.T) {
	// Length byte says 10, but only 5 bytes of data follow
	buf := []byte{10, 1, 2, 3, 4, 5}
	parsed, n := outscript.ParsePushBytes(buf)
	if parsed != nil || n != 0 {
		t.Error("expected nil,0 for truncated input")
	}
}

func TestParsePushBytesUnknownOpcode(t *testing.T) {
	buf := []byte{0x50, 0x00} // not a valid push opcode
	parsed, n := outscript.ParsePushBytes(buf)
	if parsed != nil || n != 0 {
		t.Error("expected nil,0 for unknown opcode")
	}
}

func TestParsePushBytesTruncatedPushData(t *testing.T) {
	// These inputs previously caused out-of-bounds panics because the length
	// prefix was read before checking the buffer length.
	cases := [][]byte{
		{0x4c},                   // OP_PUSHDATA1 with no length byte
		{0x4d, 0x00},             // OP_PUSHDATA2 with only 1 of 2 length bytes
		{0x4e, 0x01, 0x02, 0x03}, // OP_PUSHDATA4 with only 3 of 4 length bytes
		{0x4c, 0x05, 0xaa},       // OP_PUSHDATA1 declaring 5 bytes but only 1 present
	}
	for i, buf := range cases {
		parsed, n := outscript.ParsePushBytes(buf)
		if parsed != nil || n != 0 {
			t.Errorf("case %d: expected nil,0 for truncated pushdata, got %v,%d", i, parsed, n)
		}
	}
}
