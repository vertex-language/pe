// Package x64 is the backend for AMD64.
//
// It is the simplest of the four, and the reason is one field width. A REL32
// displacement is signed and 32 bits, so a branch reaches ±2 GB — further than
// a PE image can be, since PE32+ caps an image at 2 GB. No call ever needs a
// veneer, this package therefore does not implement backend.Thunker, and the
// layout fixpoint that exists for aarch64's benefit runs exactly once here.
//
// Importing this package registers the backend:
//
//	import _ "github.com/vertex-language/pe/x64"
package x64

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/backend"
	"github.com/vertex-language/pe/image"
)

func init() { backend.Register(Backend{}) }

// Backend implements backend.Backend for AMD64.
type Backend struct{}

func (Backend) Machine() pe.Machine { return pe.MachineAMD64 }
func (Backend) SubArch() pe.SubArch { return pe.SubArchNone }
func (Backend) WordSize() int       { return 8 }

// UnwindEntrySize is one RUNTIME_FUNCTION: a start RVA, an end RVA, and an
// RVA to the unwind information. ARM64's is 8 because its second word packs
// the length and the unwind data together.
func (Backend) UnwindEntrySize() int { return 12 }

// ImportThunk returns the six-byte indirect jump through an IAT slot.
func (Backend) ImportThunk() backend.ThunkShape { return importThunk{} }

// Classify says what kind of thing a relocation type is.
//
// SREL32 and SSPAN32 are span-dependent values that this tree does not
// implement, and they classify as unsupported rather than ignored. The
// difference matters: an ignored relocation has no effect, an unsupported one
// has an effect nobody applied, and silently treating the second as the first
// produces an image missing a fixup with nothing to say so.
func (Backend) Classify(typ uint16) backend.Kind {
	switch pe.RelocAMD64(typ) {
	case pe.IMAGE_REL_AMD64_ABSOLUTE:
		return backend.KindIgnored
	case pe.IMAGE_REL_AMD64_ADDR64, pe.IMAGE_REL_AMD64_ADDR32:
		return backend.KindVA
	case pe.IMAGE_REL_AMD64_ADDR32NB:
		return backend.KindRVA
	case pe.IMAGE_REL_AMD64_REL32,
		pe.IMAGE_REL_AMD64_REL32_1,
		pe.IMAGE_REL_AMD64_REL32_2,
		pe.IMAGE_REL_AMD64_REL32_3,
		pe.IMAGE_REL_AMD64_REL32_4,
		pe.IMAGE_REL_AMD64_REL32_5:
		// Relative, not Branch. The distinction is the whole difference
		// between this backend and aarch64: a 32-bit signed displacement
		// always reaches, so these are never thunk candidates.
		return backend.KindRelative
	case pe.IMAGE_REL_AMD64_SECTION:
		return backend.KindSectionIndex
	case pe.IMAGE_REL_AMD64_SECREL, pe.IMAGE_REL_AMD64_SECREL7:
		return backend.KindSectionRel
	case pe.IMAGE_REL_AMD64_TOKEN:
		return backend.KindToken
	case pe.IMAGE_REL_AMD64_PAIR:
		return backend.KindPair
	}
	return backend.KindUnsupported
}

// BaseRelocKind returns the base relocation a relocation needs.
//
// Two entries, and the second is the one that has been an actual bug in
// shipping linkers: an ADDR32 on a 64-bit machine needs a HIGHLOW, not
// nothing. Mapping it to nothing produces an image that runs correctly at its
// preferred base and faults the first time ASLR moves it, which is a failure
// that appears in production and not in testing.
//
// The absolute-symbol case is the mirror of that mistake and just as quiet. A
// relocation against a symbol whose value is a constant writes a number, not
// an address — the CRT's load configuration references __guard_fids_count with
// an ADDR64 and means the count — so relocating it would have the loader add
// the image delta to a table length. The image loads, the guard table is
// described as having several billion entries, and nothing anywhere says why.
//
// This is checked here rather than in Scan because Scan asks this function,
// and putting the test in one place is what keeps the two answers from
// diverging.
func (Backend) BaseRelocKind(r image.Reloc) (pe.BaseRelocKind, bool) {
	if isAbsolute(r) {
		return pe.BaseRelocAbsolute, false
	}
	switch pe.RelocAMD64(r.Type) {
	case pe.IMAGE_REL_AMD64_ADDR64:
		return pe.BaseRelocDir64, true
	case pe.IMAGE_REL_AMD64_ADDR32:
		return pe.BaseRelocHighLow, true
	}
	// ADDR32NB is image-relative and REL32 is a displacement between two
	// things that move together. Neither changes when the image does.
	return pe.BaseRelocAbsolute, false
}

// isAbsolute reports whether a relocation names a symbol whose value is a
// constant rather than an address.
//
// image.Symbol keeps the two states apart and image.Symbol.RVA refuses an
// absolute outright, which is what makes this a case to handle rather than a
// case that silently produces a wrong address. Everything that asks "where is
// this symbol" has to ask this first.
func isAbsolute(r image.Reloc) bool {
	return r.Sym != nil && r.Sym.Kind() == image.SymAbsolute
}

// Scan records what the link will need, before layout assigns anything.
//
// For x64 that is base relocation sites and nothing else: there are no
// veneers, and import thunk liveness is decided by link during resolution
// rather than by inspecting relocations. Every absolute pointer must be
// recorded here rather than discovered during apply, because .reloc has to be
// sized before layout and apply runs after it.
func (b Backend) Scan(img *image.Image, reqs *backend.Reqs) error {
	for _, sec := range img.Sections() {
		for _, c := range sec.Chunks() {
			if !c.Live() {
				continue
			}
			for _, r := range c.Relocs() {
				if k, need := b.BaseRelocKind(r); need {
					reqs.NeedBaseReloc(c, r.Off, k)
				}
			}
		}
	}
	return nil
}

// Apply writes one relocation into a chunk's bytes.
//
// Every case adds to the field rather than replacing it, because the addend
// lives in the field. The displacement forms subtract the address of the byte
// *after* the field, which for the plain REL32 is four bytes past the site and
// for REL32_1 through _5 is one to five bytes further — those forms exist for
// instructions carrying an immediate after the displacement, where the
// program counter at the branch is further along than the field's end.
func (b Backend) Apply(s *backend.Site, r image.Reloc) error {
	typ := pe.RelocAMD64(r.Type)

	switch b.Classify(r.Type) {
	case backend.KindIgnored, backend.KindPair:
		return nil
	case backend.KindUnsupported:
		return &backend.RangeError{
			Chunk: s.Chunk.Name, Input: s.Chunk.Input, Off: r.Off,
			Reason: "unsupported relocation " + typ.String(),
		}
	case backend.KindToken:
		return &backend.RangeError{
			Chunk: s.Chunk.Name, Input: s.Chunk.Input, Off: r.Off,
			Reason: "CLR token relocation in a native link",
		}
	}

	// SECTION and SECREL are the two that ask about the target's placement
	// rather than its address, and the two with an absolute-symbol case of
	// their own.
	switch typ {
	case pe.IMAGE_REL_AMD64_SECTION:
		return b.applySecIdx(s, r)
	case pe.IMAGE_REL_AMD64_SECREL, pe.IMAGE_REL_AMD64_SECREL7:
		return b.applySecRel(s, r, typ)
	}

	// Everything below wants an address, and an absolute symbol has a
	// value instead. Asking r.Target() for one returns ErrAbsoluteSymbol,
	// which is the right refusal in the wrong place — the value is usable
	// for two of these types and meaningless for the rest.
	if isAbsolute(r) {
		return b.applyAbsolute(s, r, typ)
	}

	target, err := r.Target()
	if err != nil {
		return err
	}
	p := s.AddrOf(r.Off)

	switch typ {
	case pe.IMAGE_REL_AMD64_ADDR64:
		return s.Add64(r.Off, uint64(target.VA(s.Img.Cfg.ImageBase)))

	case pe.IMAGE_REL_AMD64_ADDR32:
		// A 32-bit absolute VA. With the conventional x64 image base of
		// 0x140000000 this cannot fit at all, which is why the form is
		// only usable under /LARGEADDRESSAWARE:NO. lld truncates here;
		// this refuses, because a truncated absolute address is a
		// pointer into the wrong page rather than a smaller pointer.
		va := uint64(target.VA(s.Img.Cfg.ImageBase))
		if va > 0xffffffff {
			return &backend.RangeError{
				Chunk: s.Chunk.Name, Input: s.Chunk.Input, Off: r.Off,
				Value: int64(va), Bits: 32,
			}
		}
		return s.Add32(r.Off, uint32(va))

	case pe.IMAGE_REL_AMD64_ADDR32NB:
		return s.Add32(r.Off, uint32(target))
	}

	// The REL32 family. adjust is the distance from the field's start to
	// the point the displacement is measured from.
	adjust := uint32(0)
	switch typ {
	case pe.IMAGE_REL_AMD64_REL32:
		adjust = 4
	case pe.IMAGE_REL_AMD64_REL32_1:
		adjust = 5
	case pe.IMAGE_REL_AMD64_REL32_2:
		adjust = 6
	case pe.IMAGE_REL_AMD64_REL32_3:
		adjust = 7
	case pe.IMAGE_REL_AMD64_REL32_4:
		adjust = 8
	case pe.IMAGE_REL_AMD64_REL32_5:
		adjust = 9
	default:
		return &backend.RangeError{
			Chunk: s.Chunk.Name, Input: s.Chunk.Input, Off: r.Off,
			Reason: "unhandled relocation " + typ.String(),
		}
	}

	delta := int64(target) - int64(p) - int64(adjust)
	if delta < -0x80000000 || delta > 0x7fffffff {
		// Unreachable in practice: an image is capped at 2 GB and this
		// field spans 4. It is checked anyway because the arithmetic
		// above is signed and a wrapped displacement is a branch into
		// unrelated code.
		return &backend.RangeError{
			Chunk: s.Chunk.Name, Input: s.Chunk.Input, Off: r.Off,
			Value: delta, Bits: 32,
		}
	}
	return s.Add32(r.Off, uint32(int32(delta)))
}

// applyAbsolute writes a relocation whose target is a constant.
//
// This is how the linker's answers reach the CRT. The load configuration is
// declared in an object with its fields already initialized —
// `(ULONGLONG)__guard_fids_count`, `__guard_flags` — against symbols the
// linker defines as absolutes once it knows the counts. The relocation is an
// ordinary ADDR64 and the value it writes is the number.
//
// Two of the six types can carry one and the rest cannot, and the ones that
// cannot are refused rather than approximated:
//
// ADDR32NB asks for an image-relative address. An absolute symbol is not in
// the image, so there is no base to be relative to. lld answers by subtracting
// the image base, which for a symbol holding a table length produces a value
// that has wrapped around zero; this refuses instead, because no real object
// emits the combination and a wrong number here is a wrong number nothing
// checks.
//
// The REL32 family asks for a displacement from the instruction to the target.
// A constant is not somewhere the program counter can be relative to.
func (b Backend) applyAbsolute(s *backend.Site, r image.Reloc, typ pe.RelocAMD64) error {
	v, ok := r.Sym.Value()
	if !ok {
		// Kind said absolute and Value disagreed, which cannot happen
		// from an input and can happen from a bug in resolve.
		return &backend.RangeError{
			Chunk: s.Chunk.Name, Input: s.Chunk.Input, Off: r.Off,
			Reason: "symbol " + r.Sym.Name + " is absolute but carries no value",
		}
	}

	switch typ {
	case pe.IMAGE_REL_AMD64_ADDR64:
		return s.Add64(r.Off, v)

	case pe.IMAGE_REL_AMD64_ADDR32:
		if v > 0xffffffff {
			return &backend.RangeError{
				Chunk: s.Chunk.Name, Input: s.Chunk.Input, Off: r.Off,
				Value: int64(v), Bits: 32,
			}
		}
		return s.Add32(r.Off, uint32(v))
	}

	return &backend.RangeError{
		Chunk: s.Chunk.Name, Input: s.Chunk.Input, Off: r.Off,
		Reason: typ.String() + " against the absolute symbol " + r.Sym.Name +
			", which has a value rather than an address",
	}
}

// applySecIdx writes the one-based output section number of the target.
//
// An absolute symbol belongs to no section, and MSVC writes one past the last
// section index for it rather than zero or an error. lld matches that for
// compatibility and so does this: a debugger reading the value compares it
// against the section count, and zero would name the first section.
func (b Backend) applySecIdx(s *backend.Site, r image.Reloc) error {
	if isAbsolute(r) {
		return s.Add16(r.Off, uint16(len(s.Img.Sections())+1))
	}
	target, err := r.Target()
	if err != nil {
		return err
	}
	sec := s.Img.SectionAt(target)
	if sec == nil {
		return &backend.RangeError{
			Chunk: s.Chunk.Name, Input: s.Chunk.Input, Off: r.Off,
			Reason: "SECTION relocation target is in no output section",
		}
	}
	return s.Add16(r.Off, uint16(sec.Number()))
}

// applySecRel writes the target's offset from the start of its section.
//
// This is what a static thread-local access resolves to: an offset within the
// TLS template rather than an address, which is the only form that can mean
// anything before the template is copied per-thread. Debug information uses it
// for the same reason, one indirection removed.
//
// An absolute symbol has no section to be relative to. MSVC rejects that
// outside debug sections, and so does this — the debug-section exemption is
// moot here, since .debug$S and .debug$T are dropped rather than emitted.
func (b Backend) applySecRel(s *backend.Site, r image.Reloc, typ pe.RelocAMD64) error {
	if isAbsolute(r) {
		return &backend.RangeError{
			Chunk: s.Chunk.Name, Input: s.Chunk.Input, Off: r.Off,
			Reason: "SECREL relocation against an absolute symbol",
		}
	}
	target, err := r.Target()
	if err != nil {
		return err
	}
	sec := s.Img.SectionAt(target)
	if sec == nil {
		return &backend.RangeError{
			Chunk: s.Chunk.Name, Input: s.Chunk.Input, Off: r.Off,
			Reason: "SECREL relocation target is in no output section",
		}
	}
	base, err := sec.RVA()
	if err != nil {
		return err
	}
	off := uint32(target - base)

	if typ == pe.IMAGE_REL_AMD64_SECREL7 {
		// Seven unsigned bits, written into the low byte.
		if off > 0x7f {
			return &backend.RangeError{
				Chunk: s.Chunk.Name, Input: s.Chunk.Input, Off: r.Off,
				Value: int64(off), Bits: 7,
			}
		}
		return s.Add8(r.Off, byte(off))
	}
	return s.Add32(r.Off, off)
}