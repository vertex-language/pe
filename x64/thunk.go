package x64

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/backend"
)

// The x64 import thunk is one instruction:
//
//	ff 25 <rel32>    jmp qword ptr [rip + disp32]
//
// Six bytes, and the displacement is RIP-relative — measured from the byte
// after the instruction, which is the thunk's own address plus six. That is
// what makes this shape need no base relocation of its own: both the thunk and
// the IAT slot are inside the image, so the distance between them does not
// change when the image moves.
//
// The x86 shape looks almost identical (ff 25 followed by four bytes) and is
// not the same thing at all: there the operand is an absolute address, so the
// thunk needs a HIGHLOW base relocation and the x86 backend has to report one
// during Scan.
const (
	thunkSize  = 6
	thunkAlign = 16
)

var thunkOpcode = [2]byte{0xff, 0x25}

type importThunk struct{}

func (importThunk) Size() int  { return thunkSize }
func (importThunk) Align() int { return thunkAlign }

// Write emits the thunk at s, jumping through the IAT slot at slot.
func (importThunk) Write(s *backend.Site, slot pe.RVA) error {
	if s.Len() < thunkSize {
		return &backend.RangeError{
			Chunk: s.Chunk.Name, Input: s.Chunk.Input,
			Reason: "chunk is too small to hold an import thunk",
		}
	}
	b, err := s.Bytes(0, thunkSize)
	if err != nil {
		return err
	}
	b[0], b[1] = thunkOpcode[0], thunkOpcode[1]

	// Measured from the end of the instruction, not from its start.
	delta := int64(slot) - int64(s.RVA) - thunkSize
	if delta < -0x80000000 || delta > 0x7fffffff {
		return &backend.RangeError{
			Chunk: s.Chunk.Name, Input: s.Chunk.Input,
			Value: delta, Bits: 32,
		}
	}
	v := uint32(int32(delta))
	b[2], b[3], b[4], b[5] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
	return nil
}