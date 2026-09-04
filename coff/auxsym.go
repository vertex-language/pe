package coff

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
)

// Aux is one auxiliary symbol record. The concrete types below cover the
// formats this tree understands; AuxOpaque covers the rest.
type Aux interface{ Kind() pe.AuxKind }

// AuxFunctionDef follows a function definition: storage class EXTERNAL, a
// function type, and a section number above zero, all three.
type AuxFunctionDef struct {
	TagIndex              uint32
	TotalSize             uint32
	PointerToLinenumber   uint32
	PointerToNextFunction uint32
}

func (AuxFunctionDef) Kind() pe.AuxKind { return pe.AuxFunctionDef }

// AuxBfEf follows a .bf or .ef symbol, bracketing a function's line numbers.
type AuxBfEf struct {
	Linenumber            uint16
	PointerToNextFunction uint32
}

func (AuxBfEf) Kind() pe.AuxKind { return pe.AuxBfEf }

// AuxWeakExternal follows a weak external and names its alternate.
type AuxWeakExternal struct {
	// TagIndex is the physical slot of the alternate symbol — the
	// definition to use if nothing else ever defines this name.
	TagIndex uint32
	Kind_    pe.WeakKind
}

func (AuxWeakExternal) Kind() pe.AuxKind { return pe.AuxWeakExternal }

// AuxFile is a .file symbol's filename.
//
// Unlike the others this is one record per *symbol*, not per slot: the name
// spans every auxiliary slot the symbol declares, so a long path occupies
// several and this type represents all of them.
type AuxFile struct {
	Name string
}

func (AuxFile) Kind() pe.AuxKind { return pe.AuxFile }

// AuxSectionDef follows a section definition symbol and duplicates part of the
// section header, plus the COMDAT selection.
type AuxSectionDef struct {
	Length              uint32
	NumberOfRelocations uint16
	NumberOfLinenumbers uint16
	CheckSum            uint32

	// Number is the one-based section number of the associated section,
	// meaningful only when Selection is SelectAssociative. Its high half
	// lives in bytes that are padding in a standard object, so a section
	// number above 65535 can only be expressed in a bigobj.
	Number    uint32
	Selection pe.Selection
}

func (AuxSectionDef) Kind() pe.AuxKind { return pe.AuxSectionDef }

// AuxCLRToken follows a CLR token symbol. This tree does not link managed
// code; the record is decoded so it round-trips.
type AuxCLRToken struct {
	AuxType          uint8
	SymbolTableIndex uint32
}

func (AuxCLRToken) Kind() pe.AuxKind { return pe.AuxCLRToken }

// AuxOpaque is an auxiliary slot this tree does not interpret. Raw holds the
// whole slot, padding included, so encoding it reproduces the input byte for
// byte.
type AuxOpaque struct {
	Raw []byte
}

func (AuxOpaque) Kind() pe.AuxKind { return pe.AuxOpaque }

// decodeAux reads the n auxiliary slots following sym.
//
// Dispatch is by the parent symbol, since only the CLR token format
// self-identifies. The function-definition case needs all three of its
// conditions: an undefined external function symbol matches class and type but
// has no auxiliary record, and treating it as though it did would consume the
// next symbol and desynchronise the rest of the table.
func (f *File) decodeAux(c *binio.Cursor, sym *Symbol, n int) ([]Aux, error) {
	switch {
	case sym.Class == pe.ClassExternal && sym.Type.IsFunction() && sym.Section.Defined():
		return decodeEach(c, f.BigObj, n, func() Aux {
			var a format.AuxFunctionDef
			a.Decode(c, f.BigObj)
			return AuxFunctionDef{
				TagIndex:              a.TagIndex,
				TotalSize:             a.TotalSize,
				PointerToLinenumber:   a.PointerToLinenumber,
				PointerToNextFunction: a.PointerToNextFunction,
			}
		})

	case sym.Class == pe.ClassFunction && (sym.Name == ".bf" || sym.Name == ".ef"):
		return decodeEach(c, f.BigObj, n, func() Aux {
			var a format.AuxBfEf
			a.Decode(c, f.BigObj)
			return AuxBfEf{Linenumber: a.Linenumber, PointerToNextFunction: a.PointerToNextFunction}
		})

	case sym.Class == pe.ClassWeakExternal:
		return decodeEach(c, f.BigObj, n, func() Aux {
			var a format.AuxWeakExternal
			a.Decode(c, f.BigObj)
			return AuxWeakExternal{TagIndex: a.TagIndex, Kind_: pe.WeakKind(a.Characteristics)}
		})

	case sym.Class == pe.ClassFile:
		a, err := format.DecodeAuxFile(c, n, f.BigObj)
		if err != nil {
			return nil, err
		}
		return []Aux{AuxFile{Name: a.Name}}, nil

	case f.isSectionDef(sym):
		return decodeEach(c, f.BigObj, n, func() Aux {
			var a format.AuxSectionDef
			a.Decode(c, f.BigObj)
			return AuxSectionDef{
				Length:              a.Length,
				NumberOfRelocations: a.NumberOfRelocations,
				NumberOfLinenumbers: a.NumberOfLinenumbers,
				CheckSum:            a.CheckSum,
				Number:              a.Number,
				Selection:           pe.Selection(a.Selection),
			}
		})

	case sym.Class == pe.ClassCLRToken:
		return decodeEach(c, f.BigObj, n, func() Aux {
			var a format.AuxCLRToken
			a.Decode(c, f.BigObj)
			return AuxCLRToken{AuxType: a.AuxType, SymbolTableIndex: a.SymbolTableIndex}
		})
	}

	return decodeEach(c, f.BigObj, n, func() Aux {
		var a format.AuxOpaque
		a.Decode(c, f.BigObj)
		return AuxOpaque{Raw: a.Raw}
	})
}

func decodeEach(c *binio.Cursor, bigObj bool, n int, one func() Aux) ([]Aux, error) {
	out := make([]Aux, n)
	for i := 0; i < n; i++ {
		out[i] = one()
	}
	return out, c.Err()
}

// SectionDef returns the section-definition record attached to a symbol.
func (s *Symbol) SectionDef() (AuxSectionDef, bool) {
	for _, a := range s.aux {
		if d, ok := a.(AuxSectionDef); ok {
			return d, true
		}
	}
	return AuxSectionDef{}, false
}