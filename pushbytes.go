package outscript

import (
	"encoding/binary"
	"fmt"
)

// IPushBytes is an [Insertable] that encodes the output of another [Insertable] as a
// Bitcoin script push operation.
type IPushBytes struct {
	v Insertable
}

// Bytes generates the inner value and wraps it as a Bitcoin script push operation.
func (i IPushBytes) Bytes(s *Script) ([]byte, error) {
	v, err := i.v.Bytes(s)
	if err != nil {
		return nil, err
	}
	return PushBytes(v), nil
}

// String returns a human-readable representation of the push operation.
func (i IPushBytes) String() string {
	return fmt.Sprintf("PushBytes(%s)", i.v)
}

// PushBytes encodes a byte slice as a Bitcoin script push operation, choosing the
// appropriate opcode (direct push for <=75 bytes, OP_PUSHDATA1/2/4 for larger data).
func PushBytes(v []byte) []byte {
	// see: https://en.bitcoin.it/wiki/Script
	if len(v) <= 75 {
		return append([]byte{byte(len(v))}, v...)
	}
	if len(v) <= 0xff {
		return append([]byte{0x4c, byte(len(v))}, v...) // OP_PUSHDATA1
	}
	if len(v) <= 0xffff {
		var op [3]byte
		op[0] = 0x4d // OP_PUSHDATA2
		binary.LittleEndian.PutUint16(op[1:], uint16(len(v)))
		return append(op[:], v...)
	}
	// really?
	var op [5]byte
	op[0] = 0x4e // OP_PUSHDATA4
	binary.LittleEndian.PutUint32(op[1:], uint32(len(v)))
	return append(op[:], v...)
}

// ParsePushBytes decodes a Bitcoin script push operation at the start of v, returning
// the pushed data and the total number of bytes consumed. It returns (nil, 0) on error.
func ParsePushBytes(v []byte) ([]byte, int) {
	if len(v) == 0 {
		return nil, 0
	}
	p := v[0]
	v = v[1:]
	if p <= 75 {
		if len(v) >= int(p) {
			return v[:p], int(p) + 1
		}
		// not enough data → error
		return nil, 0
	}
	switch p {
	case 0x4c: // OP_PUSHDATA1
		if len(v) < 1 {
			return nil, 0
		}
		p = v[0]
		v = v[1:]
		if len(v) >= int(p) {
			return v[:p], int(p) + 2
		}
		// not enough data → error
		return nil, 0
	case 0x4d: // OP_PUSHDATA2
		if len(v) < 2 {
			return nil, 0
		}
		l := binary.LittleEndian.Uint16(v[:2])
		v = v[2:]
		if len(v) >= int(l) {
			return v[:l], int(l) + 3
		}
		return nil, 0
	case 0x4e: // OP_PUSHDATA4
		if len(v) < 4 {
			return nil, 0
		}
		l := binary.LittleEndian.Uint32(v[:4])
		v = v[4:]
		if len(v) >= int(l) {
			return v[:l], int(l) + 5
		}
		return nil, 0
	default:
		return nil, 0
	}
}
