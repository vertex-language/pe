package coff

import "github.com/vertex-language/pe"

// The write side of relocations, and the one invariant that cannot be checked
// after the fact.
//
// A PAIR record's SymbolTableIndex is a displacement, not a symbol index, and
// nothing in either record names the other — the association is adjacency and
// only adjacency. So a Writer must never reorder, and both halves of a pair
// must arrive through one call. RelocPair is that call, and Reloc refuses a
// type belonging to a pair so the invariant cannot be broken from outside.

// RelocSpec is one relocation submitted to a Writer.
//
// Sym names the target for an ordinary relocation. Disp replaces it for the
// PAIR half, where the field is a displacement — the type reflects that rather
// than documenting it, which is why there are two fields and not one.
type RelocSpec struct {
	// Address is the offset within the section of the field to patch.
	Address uint32

	// Sym is the target symbol. It must belong to the same Writer.
	Sym *SymbolRef

	// Disp is the displacement carried by a PAIR record. It is read only
	// when Type is a pair type, and Sym must be nil in that case.
	Disp uint32

	// Type is the machine-specific relocation type, as a raw uint16. The
	// per-machine defined types in pe are the source of the values; the
	// wire edge is where they become integers again.
	Type uint16
}

// relocEntry is a submitted relocation plus how it was submitted, which is
// what lets Close tell a correctly paired SREL32 from one that merely happens
// to be followed by a PAIR.
type relocEntry struct {
	spec RelocSpec
	lead bool // first half of a RelocPair call
	tail bool // second half of a RelocPair call
}

// relocTakesPair reports whether a type must be immediately followed by a
// PAIR. Of the seeded machines only AMD64 has one.
//
// This is the generic counterpart of RelocAMD64.TakesPair. It belongs beside
// pe.RelocIsPair and lives here only because the writer is its one caller; if
// a second caller appears, move both to pe together.
func relocTakesPair(m pe.Machine, typ uint16) bool {
	if m == pe.MachineAMD64 {
		return pe.RelocAMD64(typ).TakesPair()
	}
	return false
}

// relocIsAbsolute reports whether a type is the machine's ignored type, which
// is the one case where a relocation need not name a symbol.
func relocIsAbsolute(m pe.Machine, typ uint16) bool {
	switch m {
	case pe.MachineAMD64:
		return pe.RelocAMD64(typ).IsAbsolute()
	case pe.MachineI386:
		return pe.RelocI386(typ).IsAbsolute()
	case pe.MachineARM64, pe.MachineARM64EC, pe.MachineARM64X:
		return pe.RelocARM64(typ).IsAbsolute()
	}
	return false
}

// Reloc submits one relocation against a section.
//
// A type that is half of a pair — either the span-dependent value or the PAIR
// itself — is rejected here. Both halves go through RelocPair, so a caller
// cannot submit one and forget the other, and the adjacency the format
// requires is established by construction rather than checked later.
func (w *Writer) Reloc(s *SectionBuilder, spec RelocSpec) {
	if w.fail(w.checkSection(s)) {
		return
	}
	m := w.opt.Target.Machine
	if pe.RelocIsPair(m, spec.Type) || relocTakesPair(m, spec.Type) {
		w.Fail(ErrUnpairedReloc)
		return
	}
	if err := w.checkRelocSym(spec); err != nil {
		w.Fail(err)
		return
	}
	s.relocs = append(s.relocs, relocEntry{spec: spec})
}

// RelocPair submits a span-dependent relocation and the PAIR that modifies it,
// in that order and adjacently.
//
// For AMD64 that is IMAGE_REL_AMD64_SREL32 followed by IMAGE_REL_AMD64_PAIR.
// The specification pairs "every span-dependent value"; SSPAN32 is applied at
// link time rather than emitted, and observed output does not pair it, so
// RelocAMD64.TakesPair excludes it and this call follows that judgement.
func (w *Writer) RelocPair(s *SectionBuilder, value, pair RelocSpec) {
	if w.fail(w.checkSection(s)) {
		return
	}
	m := w.opt.Target.Machine
	if !relocTakesPair(m, value.Type) || !pe.RelocIsPair(m, pair.Type) {
		w.Fail(ErrUnpairedReloc)
		return
	}
	if err := w.checkRelocSym(value); err != nil {
		w.Fail(err)
		return
	}
	if pair.Sym != nil {
		// The field holds a displacement. A symbol here means the caller
		// believes otherwise, and encoding it would relocate against an
		// arbitrary slot.
		w.Fail(ErrBadRelocation)
		return
	}
	s.relocs = append(s.relocs,
		relocEntry{spec: value, lead: true},
		relocEntry{spec: pair, tail: true})
}

// checkRelocSym validates the symbol reference of a non-PAIR relocation.
func (w *Writer) checkRelocSym(spec RelocSpec) error {
	if spec.Sym == nil {
		if relocIsAbsolute(w.opt.Target.Machine, spec.Type) {
			return nil
		}
		return ErrBadRelocation
	}
	if spec.Sym.w != w {
		// A symbol from another Writer has a slot in that Writer's table
		// and would name something arbitrary in this one.
		return ErrBadRelocation
	}
	return nil
}

// checkRelocOrder verifies the pairing invariant across a finished section.
//
// Reloc and RelocPair make it impossible to submit a broken pair, so this is a
// second line rather than the first: it catches a pair that was submitted
// correctly and then separated, which today cannot happen and tomorrow might.
func (s *SectionBuilder) checkRelocOrder(m pe.Machine) error {
	for i, e := range s.relocs {
		if relocTakesPair(m, e.spec.Type) {
			if !e.lead || i+1 >= len(s.relocs) || !s.relocs[i+1].tail {
				return ErrUnpairedReloc
			}
		}
		if pe.RelocIsPair(m, e.spec.Type) {
			if !e.tail || i == 0 || !s.relocs[i-1].lead {
				return ErrUnpairedReloc
			}
		}
	}
	return nil
}