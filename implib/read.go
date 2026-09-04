package implib

import (
	"strings"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/ar"
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
)

// Lib is a decoded import library.
type Lib struct {
	// DLL is the library every entry imports from. An import library names
	// exactly one DLL in practice; if members disagree, this is the first
	// and Mixed is set.
	DLL string

	// Mixed reports that members named more than one DLL. lib.exe can
	// produce this by merging two import libraries, and a caller that
	// assumes one DLL will silently bind half its imports wrong.
	Mixed bool

	Entries []Entry

	// Objects holds members that are real COFF objects rather than
	// short-import ones: the import descriptor, the null descriptor, and
	// the null thunk. They are kept as bytes because link consumes them as
	// ordinary inputs, not as imports.
	Objects [][]byte
}

// Open reads the import library at path.
func Open(name string) (*Lib, error) {
	a, err := ar.Open(name)
	if err != nil {
		return nil, err
	}
	defer a.Close()
	return fromArchive(a)
}

// Read decodes an import library already in memory.
func Read(data []byte) (*Lib, error) {
	ext, err := binio.NewExtent(bytesReaderAt(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	a, err := ar.NewFile(ext)
	if err != nil {
		return nil, err
	}
	return fromArchive(a)
}

// bytesReaderAt adapts a byte slice to io.ReaderAt without pulling in bytes.
type bytesReaderAt []byte

func (b bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(b)) {
		return 0, errShortRead
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, errShortRead
	}
	return n, nil
}

var errShortRead = &MemberError{Err: ErrBadMember}

// fromArchive walks the members and sorts them into imports and objects.
//
// A member is a short-import one when pe.KindOf says so. Everything else is
// passed through: the three descriptor objects an import library carries are
// ordinary COFF, and a merged library may hold real objects too.
func fromArchive(a *ar.File) (*Lib, error) {
	lib := &Lib{}
	for i, m := range a.Objects() {
		data, err := m.Data()
		if err != nil {
			return nil, &MemberError{Index: i, Name: m.Name, Err: err}
		}
		if pe.KindOf(head(data)) != pe.KindShortImport {
			lib.Objects = append(lib.Objects, data)
			continue
		}
		e, err := decodeEntry(data)
		if err != nil {
			return nil, &MemberError{Index: i, Name: m.Name, Err: err}
		}
		if lib.DLL == "" {
			lib.DLL = e.DLL
		} else if !strings.EqualFold(lib.DLL, e.DLL) {
			lib.Mixed = true
		}
		lib.Entries = append(lib.Entries, e)
	}
	if len(lib.Entries) == 0 {
		return nil, ErrNotImportLib
	}
	return lib, nil
}

func head(data []byte) []byte {
	if len(data) > pe.KindPrefix {
		return data[:pe.KindPrefix]
	}
	return data
}

// decodeEntry reads one short-import member.
//
// The strings after the header are positional and unlabelled: symbol, then
// DLL, then — only under EXPORTAS — the exported name. SizeOfData covers all
// of them, and a member whose strings do not fill it is malformed rather than
// merely padded, because the next member begins where this one ends.
func decodeEntry(data []byte) (Entry, error) {
	c := binio.NewCursor(data)
	var h format.ImportHeader
	if err := h.Decode(c); err != nil {
		return Entry{}, err
	}
	if int(h.SizeOfData) > len(data)-format.ImportHeaderSize {
		return Entry{}, ErrBadMember
	}
	body := binio.NewCursor(data[format.ImportHeaderSize : format.ImportHeaderSize+int(h.SizeOfData)])

	e := Entry{
		Kind:     Kind(h.Type()),
		NameKind: NameKind(h.NameType()),
		Ordinal:  h.OrdinalHint,
		Machine:  h.Machine,
	}
	e.Symbol = body.CStr()
	e.DLL = body.CStr()
	if e.NameKind == NameExportAs {
		e.ExportName = body.CStr()
	}
	if err := body.Err(); err != nil {
		return Entry{}, ErrBadMember
	}
	return e, nil
}

// Machine returns the library's machine type, and whether every member agreed.
//
// Disagreement is not an error: an ARM64EC import library deliberately holds
// both ARM64EC and ARM64 members so one .lib serves a native link, an EC link,
// and a hybrid one.
func (l *Lib) Machine() (pe.Machine, bool) {
	if len(l.Entries) == 0 {
		return pe.MachineUnknown, false
	}
	m := pe.Machine(l.Entries[0].Machine)
	for _, e := range l.Entries[1:] {
		if pe.Machine(e.Machine) != m {
			return m, false
		}
	}
	return m, true
}