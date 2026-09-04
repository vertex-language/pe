package format

import "github.com/vertex-language/pe/internal/binio"

// .pdata is an array of fixed-width records, one per stack-manipulating
// function, sorted by the function's start RVA because the runtime binary
// searches it to find the unwind data for a faulting address.
//
// The records are per-machine and this tree does not interpret them: it
// relocates the RVAs inside, drops the ones whose function was swept, and
// sorts. What it therefore needs from this package is exactly two things — the
// record width, which the backend supplies, and the sort key.
//
// The sort key is the same in every architecture Microsoft has defined: the
// function's start RVA is the first 32-bit word of the record. x64 follows it
// with an end RVA and an RVA to the UNWIND_INFO, twelve bytes in all; ARM64
// and ARMNT follow it with a single word that is either an .xdata pointer or a
// packed unwind description, eight bytes in all. A sort that reads the first
// word needs to know none of that.

const (
	// RuntimeFunctionSizeX64 is one RUNTIME_FUNCTION on x64: a start RVA,
	// an end RVA, and an RVA to the unwind information.
	RuntimeFunctionSizeX64 = 12

	// RuntimeFunctionSizeARM64 is one on ARM64 and ARMNT, whose second
	// word packs the function length and the unwind data together when it
	// can and points at .xdata when it cannot.
	RuntimeFunctionSizeARM64 = 8

	// RuntimeFunctionAlign is the alignment the record array requires.
	// Both forms are arrays of DWORDs and the runtime indexes them.
	RuntimeFunctionAlign = 4
)

// FunctionStart returns the start RVA a .pdata record describes.
//
// rec must be one whole record. This is the only field of an unwind record
// this tree reads, and the reason the sort in link needs no backend beyond a
// width.
func FunctionStart(rec []byte) (uint32, bool) {
	if len(rec) < 4 {
		return 0, false
	}
	return uint32(rec[0]) | uint32(rec[1])<<8 |
		uint32(rec[2])<<16 | uint32(rec[3])<<24, true
}

// RuntimeFunctionX64 is one x64 unwind record.
//
// UnwindInfoAddress has an undocumented variant: with its low bit set it
// points at another RUNTIME_FUNCTION rather than at an UNWIND_INFO, which is
// how a chained entry for a separated function segment is spelled. This tree
// preserves the field rather than following it, so the variant costs nothing.
type RuntimeFunctionX64 struct {
	BeginAddress      uint32
	EndAddress        uint32
	UnwindInfoAddress uint32
}

func (r *RuntimeFunctionX64) Decode(c *binio.Cursor) error {
	r.BeginAddress = c.U32()
	r.EndAddress = c.U32()
	r.UnwindInfoAddress = c.U32()
	return c.Err()
}

func (r *RuntimeFunctionX64) Encode(b *binio.Buf) {
	b.U32(r.BeginAddress)
	b.U32(r.EndAddress)
	b.U32(r.UnwindInfoAddress)
}

// RuntimeFunctionARM64 is one ARM64 or ARMNT unwind record.
//
// UnwindData is a union decided by its low two bits: zero means the remaining
// thirty bits are an RVA to an .xdata record, and any other value means the
// word is packed unwind data describing a canonical prolog and epilog inline.
// A function longer than 8K cannot be described in packed form and always has
// an .xdata record.
type RuntimeFunctionARM64 struct {
	BeginAddress uint32
	UnwindData   uint32
}

// PackedUnwindMask is the low two bits of UnwindData: zero for an .xdata
// pointer, non-zero for packed data.
const PackedUnwindMask uint32 = 0x3

// Packed reports whether the record carries packed unwind data rather than an
// .xdata pointer.
func (r *RuntimeFunctionARM64) Packed() bool {
	return r.UnwindData&PackedUnwindMask != 0
}

// XDataRVA returns the .xdata address, valid only when Packed is false.
func (r *RuntimeFunctionARM64) XDataRVA() (uint32, bool) {
	if r.Packed() {
		return 0, false
	}
	return r.UnwindData, true
}

func (r *RuntimeFunctionARM64) Decode(c *binio.Cursor) error {
	r.BeginAddress = c.U32()
	r.UnwindData = c.U32()
	return c.Err()
}

func (r *RuntimeFunctionARM64) Encode(b *binio.Buf) {
	b.U32(r.BeginAddress)
	b.U32(r.UnwindData)
}