package coff

import "github.com/vertex-language/pe"

// Comdat describes a COMDAT section's election terms.
type Comdat struct {
	// Selection is how the linker resolves duplicates.
	Selection pe.Selection

	// Leader is the key symbol: the name duplicates are elected on. It is
	// nil for SelectAssociative, which elects on nothing.
	Leader *Symbol

	// Def is the section-definition record, carrying the length and
	// checksum that SelectSameSize and SelectExactMatch compare.
	Def AuxSectionDef

	// Associated is the section this one lives or dies with, set only for
	// SelectAssociative.
	Associated *Section
}

// IsComdat reports whether the section carries the LNK_COMDAT flag.
func (s *Section) IsComdat() bool { return s.kind.Has(pe.SecLnkComdat) }

// Comdat returns the section's election terms, or nil if it is not COMDAT.
//
// The layout the specification describes is positional: the first symbol with
// this section's number is the section definition, carrying the auxiliary
// record with the selection; the *second* is the COMDAT symbol, whose name is
// what duplicates are elected on. Neither is found by searching for a name —
// they are found by order.
//
// A section flagged COMDAT with no second symbol is ErrNoComdatLeader. There
// is nothing to elect on, and defaulting to the section name would silently
// merge sections that were never meant to be equivalent.
//
// Associative is the exception, and the common case in a real object: a
// section whose selection is SelectAssociative is elected on nothing at all —
// it lives or dies with the section its auxiliary record names — so it needs
// no key symbol and MSVC emits none for the .pdata and .xdata it attaches to
// each /Gy function. Its Leader is nil, and the one caller that reads a
// Leader is the one that already skips associative sections.
func (s *Section) Comdat() (*Comdat, error) {
	if !s.IsComdat() {
		return nil, nil
	}
	syms, err := s.f.Symbols()
	if err != nil {
		return nil, err
	}
	num := s.Number()

	var def *Symbol
	var leader *Symbol
	for _, sym := range syms {
		if int32(sym.Section) != num {
			continue
		}
		if def == nil {
			def = sym
			continue
		}
		leader = sym
		break
	}
	if def == nil {
		return nil, &SectionError{Index: s.index, Name: s.Name, Err: ErrNoComdatLeader}
	}
	aux, ok := def.SectionDef()
	if !ok {
		return nil, &SectionError{Index: s.index, Name: s.Name, Err: ErrNoComdatLeader}
	}
	if !aux.Selection.Valid() {
		return nil, &SectionError{Index: s.index, Name: s.Name, Err: ErrCorrupt}
	}
	if leader == nil && !aux.Selection.Associative() {
		return nil, &SectionError{Index: s.index, Name: s.Name, Err: ErrNoComdatLeader}
	}

	c := &Comdat{Selection: aux.Selection, Leader: leader, Def: aux}
	if aux.Selection.Associative() {
		if aux.Number == 0 || int(aux.Number) > len(s.f.Sections) {
			return nil, &SectionError{Index: s.index, Name: s.Name, Err: ErrCorrupt}
		}
		c.Associated = s.f.Sections[aux.Number-1]
	}
	return c, nil
}

// CheckComdatCycles verifies that every associative chain terminates.
//
// An associative COMDAT points at the section it depends on, which may itself
// be associative. A chain that loops is an infinite loop in every consumer
// downstream — sweep, merge, and emit all walk it — so the check belongs here,
// where the file is read, rather than wherever the loop happens to hang.
//
// It is O(sections) with a colour map rather than O(sections²) with repeated
// walks, because /Gy objects routinely have thousands of COMDATs.
func (f *File) CheckComdatCycles() error {
	const (
		white = 0 // unvisited
		grey  = 1 // on the current path
		black = 2 // proven to terminate
	)
	colour := make([]uint8, len(f.Sections))

	for i, s := range f.Sections {
		if colour[i] != white {
			continue
		}
		// Walk this chain iteratively, marking as we go.
		var path []int
		cur := i
		for {
			if colour[cur] == grey {
				return &SectionError{Index: cur, Name: f.Sections[cur].Name, Err: ErrComdatCycle}
			}
			if colour[cur] == black {
				break
			}
			colour[cur] = grey
			path = append(path, cur)

			c, err := f.Sections[cur].Comdat()
			if err != nil {
				return err
			}
			if c == nil || c.Associated == nil {
				break
			}
			cur = c.Associated.index
		}
		for _, n := range path {
			colour[n] = black
		}
		_ = s
	}
	return nil
}