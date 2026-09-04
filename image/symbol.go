package image

import "github.com/vertex-language/pe"

// A Symbol is a name the output image defines.
//
// Its address is derived, never stored. A defined symbol is a chunk and an
// offset into it, and RVA answers by asking the chunk — so a symbol cannot
// disagree with the thing it names, and the bind step is a verification pass
// rather than a copy. Storing an address here would create a second place for
// it to be wrong, and the wrong one would look exactly as authoritative.
type Symbol struct {
	Name string

	kind   SymbolKind
	chunk  *Chunk
	offset uint32
	value  uint64 // absolute symbols only
	rva    pe.RVA // fixed symbols only
}

// SymbolKind is what a symbol's value means.
type SymbolKind uint8

const (
	// SymUndefined is a name with no definition in this image. It survives
	// into the table only long enough to be reported; a link that reaches
	// emit with one is a bug in check.
	SymUndefined SymbolKind = iota

	// SymDefined is a name at an offset within a chunk. Nearly everything
	// is this, including every import slot: __imp_foo names an IAT entry,
	// and an IAT entry is a chunk like any other.
	SymDefined

	// SymAbsolute is a name whose value is a constant rather than an
	// address. The linker-supplied symbols the load config reads are these,
	// and asking one for an RVA is a mistake rather than a conversion.
	SymAbsolute

	// SymFixed is a name at an address the linker chose, belonging to no
	// chunk. __ImageBase is the one: it names the start of the image,
	// which is the PE headers and so is in no section, and the CRT takes
	// its address to get the module handle without asking the loader.
	//
	// It is an address and not a constant, which is the whole distinction
	// from SymAbsolute — a REL32 to it is a displacement and an ADDR64 to
	// it needs a base relocation, both of which an absolute refuses.
	SymFixed
)

func (k SymbolKind) String() string {
	switch k {
	case SymDefined:
		return "defined"
	case SymAbsolute:
		return "absolute"
	case SymFixed:
		return "fixed"
	}
	return "undefined"
}

// Kind returns what this symbol's value means.
func (s *Symbol) Kind() SymbolKind { return s.kind }

// Chunk returns the chunk defining this symbol, or nil.
func (s *Symbol) Chunk() *Chunk { return s.chunk }

// Offset returns the symbol's offset within its chunk.
func (s *Symbol) Offset() uint32 { return s.offset }

// Value returns an absolute symbol's constant.
func (s *Symbol) Value() (uint64, bool) {
	if s.kind != SymAbsolute {
		return 0, false
	}
	return s.value, true
}

// RVA returns the symbol's address.
//
// It fails before layout with ErrNoRVA, for an absolute symbol with
// ErrAbsoluteSymbol, and for an undefined one with ErrUndefinedSymbol. The
// three are separate because a caller reacts differently to each: the first is
// a phase mistake, the second a category mistake, and the third a link that
// should already have failed.
func (s *Symbol) RVA() (pe.RVA, error) {
	switch s.kind {
	case SymDefined:
		if s.chunk == nil {
			return 0, ErrUndefinedSymbol
		}
		r, err := s.chunk.RVA()
		if err != nil {
			return 0, err
		}
		return r.Add(s.offset), nil
	case SymFixed:
		return s.rva, nil
	case SymAbsolute:
		return 0, ErrAbsoluteSymbol
	}
	return 0, ErrUndefinedSymbol
}

// VA returns the symbol's virtual address at the image's preferred base.
//
// The TLS directory is the one place in an image where a stored address is a
// VA rather than an RVA, which is why this exists at all — and why every field
// filled from it needs a base relocation. A caller reaching for this anywhere
// else is almost certainly reaching for RVA.
func (s *Symbol) VA(base pe.VA) (pe.VA, error) {
	r, err := s.RVA()
	if err != nil {
		return 0, err
	}
	return r.VA(base), nil
}

// Live reports whether the symbol's definition survived election and sweep.
func (s *Symbol) Live() bool {
	switch s.kind {
	case SymAbsolute, SymFixed:
		return true
	}
	return s.chunk != nil && s.chunk.Live()
}

// SymbolTable is one view's output symbols.
//
// Pointer identity is stable for the life of the table: a symbol is looked up
// once and then referred to by address, which is what lets a relocation hold a
// *Symbol rather than a name and a map lookup. An ARM64X image has two of
// these and they are genuinely separate namespaces — the same name may resolve
// to different definitions in each, which is the whole reason a hybrid image
// needs two views rather than a flag.
type SymbolTable struct {
	byName map[string]*Symbol
	order  []*Symbol
}

// NewSymbolTable returns an empty table.
func NewSymbolTable() *SymbolTable {
	return &SymbolTable{byName: make(map[string]*Symbol)}
}

// Lookup returns the symbol with this name, or nil.
func (t *SymbolTable) Lookup(name string) *Symbol { return t.byName[name] }

// Symbols returns every symbol in insertion order.
//
// Insertion order rather than sorted order, because nothing in the image
// consumes this table sorted — the tables that must be sorted (.pdata, the
// guard tables, the export name pointers) are sorted by fill, over their own
// entries, after addresses are final.
func (t *SymbolTable) Symbols() []*Symbol { return t.order }

// Define records a symbol at an offset within a chunk, replacing any previous
// definition of the same name.
//
// Replacement is deliberate and is not an election: resolve has already
// decided which definition wins, and this table records the outcome. Two
// competing definitions reaching here is a bug in resolve, not something to
// arbitrate a second time with different information.
func (t *SymbolTable) Define(name string, c *Chunk, off uint32) *Symbol {
	s := t.intern(name)
	s.kind, s.chunk, s.offset, s.value = SymDefined, c, off, 0
	return s
}

// Absolute records a symbol whose value is a constant.
func (t *SymbolTable) Absolute(name string, v uint64) *Symbol {
	s := t.intern(name)
	s.kind, s.chunk, s.offset, s.value = SymAbsolute, nil, 0, v
	return s
}

// Fixed records a symbol at an address in no chunk. See SymFixed.
func (t *SymbolTable) Fixed(name string, r pe.RVA) *Symbol {
	s := t.intern(name)
	s.kind, s.chunk, s.offset, s.value, s.rva = SymFixed, nil, 0, 0, r
	return s
}

// Undefined records a name with no definition, returning the existing symbol
// if the name is already known. It never downgrades a definition.
func (t *SymbolTable) Undefined(name string) *Symbol {
	if s, ok := t.byName[name]; ok {
		return s
	}
	return t.intern(name)
}

func (t *SymbolTable) intern(name string) *Symbol {
	if s, ok := t.byName[name]; ok {
		return s
	}
	s := &Symbol{Name: name}
	t.byName[name] = s
	t.order = append(t.order, s)
	return s
}