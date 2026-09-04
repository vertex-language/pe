package coff

import (
	"io"
	"os"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
	"github.com/vertex-language/pe/internal/strtab"
)

// File is a relocatable COFF object, open for reading.
//
// It is immutable after Open. Nothing here writes; the writer is a separate
// type family, because a decoder that can also be mutated is a decoder whose
// invariants hold only by convention.
//
// Section data is read on demand from the underlying extent, so opening a
// forty-megabyte object costs the headers and the symbol table, not the object.
type File struct {
	// BigObj reports whether this is an ANON_OBJECT_HEADER_BIGOBJ. It
	// changes the symbol slot stride and the section count width, and
	// nothing else visible.
	BigObj bool

	Machine         pe.Machine
	TimeDateStamp   uint32
	Characteristics pe.FileChar

	// Sections is the section table in file order. There is deliberately no
	// lookup by name: /Gy gives every function its own .text$mn, so .text
	// is not unique within an object, and a by-name accessor would return
	// an arbitrary one of them.
	Sections []*Section

	ext    *binio.Extent
	closer io.Closer

	strs *strtab.Table

	symPtr   uint32
	symCount uint32

	syms    []*Symbol
	symErr  error
	symOnce bool

	directives []Directive
}

// Open reads the object at path.
//
// The returned File holds the open descriptor, so Close must be called. Reads
// of section data go to the file, which is what keeps a large object cheap to
// open.
func Open(name string) (*File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	ext, err := binio.NewExtent(f, fi.Size())
	if err != nil {
		f.Close()
		return nil, err
	}
	obj, err := NewFile(ext)
	if err != nil {
		f.Close()
		return nil, err
	}
	obj.closer = f
	return obj, nil
}

// NewFile reads an object from an extent.
//
// The extent bounds every read, so passing one member of a mapped archive
// parses that member without copying it out and without any chance of a
// malformed header reaching into the next one.
func NewFile(ext *binio.Extent) (*File, error) {
	head, err := ext.Head(pe.KindPrefix)
	if err != nil {
		return nil, err
	}

	switch k := pe.KindOf(head); k {
	case pe.KindObject:
		return openStandard(ext)
	case pe.KindBigObj:
		return openBigObj(ext)
	case pe.KindShortImport:
		return nil, ErrShortImport
	case pe.KindLTCG:
		return nil, ErrLTCGObject
	case pe.KindImage:
		return nil, pe.ErrImageFile
	case pe.KindArchive:
		return nil, ErrCorrupt
	default:
		return nil, pe.ErrNotCOFF
	}
}

func openStandard(ext *binio.Extent) (*File, error) {
	c, err := ext.Cursor(0, format.FileHeaderSize)
	if err != nil {
		return nil, err
	}
	var h format.FileHeader
	if err := h.Decode(c); err != nil {
		return nil, err
	}
	f := &File{
		BigObj:          false,
		Machine:         pe.Machine(h.Machine),
		TimeDateStamp:   h.TimeDateStamp,
		Characteristics: pe.FileChar(h.Characteristics),
		ext:             ext,
		symPtr:          h.PointerToSymbolTable,
		symCount:        h.NumberOfSymbols,
	}
	// The section table follows the optional header, whose size the file
	// header states. An object should have no optional header at all, but
	// some producers emit one, and the offset must honour whatever the
	// field says regardless.
	return f.finish(h.SectionTableOffset(), uint32(h.NumberOfSections))
}

func openBigObj(ext *binio.Extent) (*File, error) {
	c, err := ext.Cursor(0, format.BigObjHeaderSize)
	if err != nil {
		return nil, err
	}
	var h format.BigObjHeader
	if err := h.Decode(c); err != nil {
		return nil, err
	}
	f := &File{
		BigObj:        true,
		Machine:       pe.Machine(h.Machine),
		TimeDateStamp: h.TimeDateStamp,
		ext:           ext,
		symPtr:        h.PointerToSymbolTable,
		symCount:      h.NumberOfSymbols,
	}
	// A bigobj header has no Characteristics field. That absence is why
	// promoting an object with characteristics set to bigobj has to be an
	// error rather than a silent drop.
	return f.finish(format.BigObjHeaderSize, h.NumberOfSections)
}

// finish reads the section table and the string table, which both kinds share.
func (f *File) finish(secOff int64, nsec uint32) (*File, error) {
	c, err := f.ext.Table("sections", secOff, nsec, format.SectionHeaderSize)
	if err != nil {
		return nil, err
	}
	hdrs := make([]format.SectionHeader, nsec)
	for i := range hdrs {
		if err := hdrs[i].Decode(c); err != nil {
			return nil, &SectionError{Index: i, Err: err}
		}
	}

	if err := f.readStrings(); err != nil {
		return nil, err
	}

	f.Sections = make([]*Section, nsec)
	for i := range hdrs {
		s, err := newSection(f, i, &hdrs[i])
		if err != nil {
			return nil, err
		}
		f.Sections[i] = s
	}

	if err := f.readDirectives(); err != nil {
		return nil, err
	}
	return f, nil
}

// readStrings locates the string table, which sits immediately after the
// symbol table.
//
// An object with no symbols has no string table either, and that is legal
// rather than an error — a purely data object produced by a resource compiler
// looks exactly like this.
func (f *File) readStrings() error {
	if f.symPtr == 0 || f.symCount == 0 {
		f.strs = strtab.New(nil)
		return nil
	}
	slot := int64(format.SymbolSlotSize(f.BigObj))
	off := int64(f.symPtr) + int64(f.symCount)*slot
	if off >= f.ext.Size() {
		// The symbol table runs to the end of the object with no room for
		// a string table. Legal: the table may be omitted entirely.
		f.strs = strtab.New(nil)
		return nil
	}
	c, err := f.ext.Cursor(off, f.ext.Size()-off)
	if err != nil {
		return err
	}
	t, err := strtab.Decode(c)
	if err != nil {
		return err
	}
	f.strs = t
	return nil
}

// Target returns the target this object was compiled for.
//
// Machine comes from the header. ABI and OS do not: an object records neither,
// so they are assumed to be MSVC and Windows. That assumption is right for the
// overwhelming majority of objects and wrong for every MinGW one, and there is
// no field that would say which — the difference shows up only in section
// naming conventions and .drectve spellings, both of which are heuristics.
//
// A caller that knows better should construct its own Target. link does
// exactly that: its target comes from the command line, and an input whose
// machine disagrees is ErrMachineMismatch rather than a re-inference.
func (f *File) Target() pe.Target {
	return pe.Target{
		Machine: f.Machine,
		SubArch: f.Machine.SubArch(),
		ABI:     pe.ABIMSVC,
		OS:      pe.OSWindows,
	}
}

// Close releases the underlying file, if this File owns one. It is a no-op for
// a File built from an extent the caller owns.
func (f *File) Close() error {
	if f.closer != nil {
		err := f.closer.Close()
		f.closer = nil
		return err
	}
	return nil
}

// Strings returns the object's string table.
func (f *File) Strings() *strtab.Table { return f.strs }

// Directives returns the parsed contents of the .drectve section, or nil if
// there is none.
//
// Parsing happens at Open, so this cannot fail here. The directives are
// returned uninterpreted: this package tokenizes and normalizes them, and
// deciding what /DEFAULTLIB or /EXPORT means is link's job.
func (f *File) Directives() []Directive { return f.directives }