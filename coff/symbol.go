package coff

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/internal/format"
)

// Symbol is one entry of the COFF symbol table.
//
// Slot is a physical index: auxiliary records occupy slots of their own, so
// the slot of the n-th symbol is not n. Relocations and associative COMDATs
// reference slots, which is why this is exposed while an ordinal is not.
//
// Symbols are decoded once and cached, so pointer identity is stable for the
// life of the File. link relies on that during resolution — a symbol is
// identified by its address, not by re-comparing names.
type Symbol struct {
	Name    string
	Value   uint32
	Section pe.SectionNumber
	Type    pe.SymType
	Class   pe.StorageClass

	// Slot is this symbol's physical index in the table.
	Slot int

	aux []Aux
	f   *File
}

// External reports whether the symbol has external linkage.
func (s *Symbol) External() bool { return s.Class == pe.ClassExternal }

// Undefined reports whether the symbol is a reference with no definition here.
//
// An undefined external with a non-zero Value is a common-block request: the
// Value is the size to allocate, not an address. Common reports that case.
func (s *Symbol) Undefined() bool {
	return s.Section == pe.SectionUndefined && s.Class == pe.ClassExternal && s.Value == 0
}

// Common reports whether the symbol requests a common block, and its size.
func (s *Symbol) Common() (uint32, bool) {
	if s.Section == pe.SectionUndefined && s.Class == pe.ClassExternal && s.Value != 0 {
		return s.Value, true
	}
	return 0, false
}

// Absolute reports whether Value is a constant rather than an address.
func (s *Symbol) Absolute() bool { return s.Section == pe.SectionAbsolute }

// Defined reports whether the symbol is defined in a real section here.
func (s *Symbol) Defined() bool { return s.Section.Defined() }

// Sec returns the section defining this symbol, or nil.
func (s *Symbol) Sec() *Section {
	if !s.Section.Defined() || int(s.Section) > len(s.f.Sections) {
		return nil
	}
	return s.f.Sections[s.Section-1]
}

// Aux returns the auxiliary records following this symbol.
//
// The concrete types are AuxFunctionDef, AuxBfEf, AuxWeakExternal, AuxFile,
// AuxSectionDef, and AuxCLRToken where the kind is known, and AuxOpaque
// otherwise. Opaque records round-trip unchanged rather than being dropped:
// the traditional COFF array and structure formats land there, as will
// whatever a future toolchain invents.
func (s *Symbol) Aux() []Aux { return s.aux }

// Symbols returns every symbol in the table, in slot order.
//
// The result includes only standard records; auxiliary records are attached to
// the symbol they follow rather than appearing as entries of their own. Use
// Slot to index back into the physical table.
func (f *File) Symbols() ([]*Symbol, error) {
	if f.symOnce {
		return f.syms, f.symErr
	}
	f.symOnce = true
	f.syms, f.symErr = f.decodeSymbols()
	return f.syms, f.symErr
}

// SymbolAt returns the symbol occupying a physical slot.
//
// A slot that holds an auxiliary record has no symbol, and neither does one
// past the end; both return nil. A relocation naming such a slot is corrupt,
// and the caller reports it with the context this function lacks.
func (f *File) SymbolAt(slot uint32) *Symbol {
	syms, err := f.Symbols()
	if err != nil {
		return nil
	}
	// Slots ascend, so a binary search would work; a linear scan is used
	// because callers resolve relocations in file order and the common case
	// is a short table. If this shows up in a profile, index it once.
	for _, s := range syms {
		if uint32(s.Slot) == slot {
			return s
		}
	}
	return nil
}

func (f *File) decodeSymbols() ([]*Symbol, error) {
	if f.symPtr == 0 || f.symCount == 0 {
		return nil, nil
	}
	slotSize := format.SymbolSlotSize(f.BigObj)
	c, err := f.ext.Table("symbols", int64(f.symPtr), f.symCount, slotSize)
	if err != nil {
		return nil, err
	}

	out := make([]*Symbol, 0, f.symCount)
	for slot := 0; slot < int(f.symCount); {
		var raw format.Symbol
		if err := raw.Decode(c, f.BigObj); err != nil {
			return nil, &SymbolError{Slot: slot, Err: err}
		}
		name, err := f.strs.SymbolName(raw.NameInline)
		if err != nil {
			return nil, &SymbolError{Slot: slot, Err: err}
		}

		sym := &Symbol{
			Name:    name,
			Value:   raw.Value,
			Section: pe.SectionNumber(raw.SectionNumber),
			Type:    pe.SymType(raw.Type),
			Class:   pe.StorageClass(raw.StorageClass),
			Slot:    slot,
			f:       f,
		}

		n := int(raw.NumberOfAuxSymbols)
		if slot+1+n > int(f.symCount) {
			return nil, &SymbolError{Slot: slot, Name: name, Err: ErrBadAuxRecord}
		}
		if n > 0 {
			aux, err := f.decodeAux(c, sym, n)
			if err != nil {
				return nil, &SymbolError{Slot: slot, Name: name, Err: err}
			}
			sym.aux = aux
		}

		out = append(out, sym)
		slot += 1 + n
	}
	return out, nil
}

// isSectionDef reports whether a symbol is its section's definition record.
//
// The test needs the section table, which is why it lives here rather than in
// pe: a STATIC symbol carries a section-definition aux record when its name is
// the name of the section it belongs to, and nothing else distinguishes it
// from an ordinary local label.
func (f *File) isSectionDef(s *Symbol) bool {
	if s.Class != pe.ClassStatic || !s.Section.Defined() {
		return false
	}
	if int(s.Section) > len(f.Sections) {
		return false
	}
	return f.Sections[s.Section-1].Name == s.Name
}