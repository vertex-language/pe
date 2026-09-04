package image

import "github.com/vertex-language/pe"

// A Reloc is one relocation to apply to a chunk's bytes.
//
// It is the output-side form of coff.Reloc: the symbol is resolved to an
// image.Symbol rather than a slot number, and the offset is within the chunk
// rather than within the input section. Everything else is carried through
// unchanged, including the type, which stays a raw uint16 because its meaning
// is the backend's and giving it a type here would mean this package knowing
// five relocation tables.
type Reloc struct {
	// Off is the offset within the chunk of the field to patch.
	Off uint32

	// Type is the machine-specific relocation type.
	Type uint16

	// Sym is the target. It is nil for a type that names no symbol — the
	// machine's ignored type, and the PAIR half.
	Sym *Symbol

	// Disp is the displacement a PAIR record carries in place of a symbol
	// index. It is read only for a pair type, and Sym is nil in that case.
	//
	// The two fields exist separately for the reason coff.RelocSpec has
	// them separately: nothing in either record names the other, so a
	// reader that resolves this field as an index looks up an arbitrary
	// symbol and relocates against it.
	Disp uint32
}

// Target returns the relocation's target address.
func (r Reloc) Target() (pe.RVA, error) {
	if r.Sym == nil {
		return 0, ErrUndefinedSymbol
	}
	return r.Sym.RVA()
}

// Relocs returns the relocations attached to this chunk, in input order.
//
// The order is preserved exactly, for the same reason coff preserves it: a
// PAIR is associated with the entry before it by adjacency and by nothing
// else, so sorting these — for any reason, including determinism — destroys
// the only thing that pairs them.
func (c *Chunk) Relocs() []Reloc { return c.relocs }

// AddReloc attaches a relocation to the chunk.
func (c *Chunk) AddReloc(r Reloc) { c.relocs = append(c.relocs, r) }

// SetRelocs replaces the chunk's relocations, preserving the order given.
func (c *Chunk) SetRelocs(rs []Reloc) { c.relocs = rs }