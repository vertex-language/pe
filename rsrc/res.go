package rsrc

import (
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
)

// A .res file is concatenated entries: a DWORD-aligned header, then that
// entry's data, then padding to the next DWORD, then the next header. There is
// no count, no index, and no magic — the file ends when the bytes do.
//
// Two things make the walk less obvious than it looks. The header is not a
// fixed size, because the type and name are variable-width and a word of
// padding may follow them; the header states its own length and the walk
// advances by that. And the first entry is a null marker rc.exe writes at the
// head of every file, describing nothing, which a reader that takes it
// literally turns into a type-zero branch of the tree.

// Resource is one entry of a .res file.
type Resource struct {
	Type     format.ResID
	Name     format.ResID
	Language uint16

	// Data is the blob, aliasing the input rather than copying it. A
	// caller that retains it past the input's lifetime should copy.
	Data []byte

	CodePage        uint32
	DataVersion     uint32
	MemoryFlags     uint16
	Version         uint32
	Characteristics uint32
}

// ParseRes reads a .res file.
//
// It returns the resources in file order, which is not the order they will
// appear in the image: the tree sorts them, because the loader binary-searches
// every level. Preserving the input order here anyway costs nothing and makes
// a diff against rc.exe's output readable.
func ParseRes(data []byte) ([]Resource, error) {
	var out []Resource
	c := binio.NewCursor(data)

	for i := 0; c.Len() > 0; i++ {
		// A trailing run shorter than a header is padding, not an
		// entry. Anything else short is a truncated file.
		if c.Len() < 8 {
			if isZero(data[len(data)-c.Len():]) {
				break
			}
			return nil, &ResourceError{Index: i, Offset: int64(c.Off()), Err: ErrBadResFile}
		}

		start := c.Off()
		var h format.ResHeader
		if err := h.Decode(c); err != nil {
			return nil, &ResourceError{Index: i, Offset: int64(start), Err: err}
		}
		if uint64(h.DataSize) > uint64(c.Len()) {
			return nil, &ResourceError{
				Index: i, Offset: int64(start),
				Type: h.Type.String(), Name: h.Name.String(),
				Err: ErrBadResFile,
			}
		}
		body := c.Bytes(int(h.DataSize))
		if err := c.Err(); err != nil {
			return nil, &ResourceError{Index: i, Offset: int64(start), Err: err}
		}
		// Every entry is padded to a DWORD, and the padding belongs to
		// the entry that precedes it rather than to the one that
		// follows. Skipping it here is what keeps the next header
		// aligned without the walk having to track where it started.
		if pad := (format.ResAlign - int(h.DataSize)%format.ResAlign) % format.ResAlign; pad > 0 {
			c.Skip(pad)
		}

		if h.IsNull() {
			continue
		}
		out = append(out, Resource{
			Type:            h.Type,
			Name:            h.Name,
			Language:        h.LanguageId,
			Data:            body,
			DataVersion:     h.DataVersion,
			MemoryFlags:     h.MemoryFlags,
			Version:         h.Version,
			Characteristics: h.Characteristics,
		})

		if c.Off() <= start {
			// A header that does not advance is an infinite loop,
			// and a hostile .res is the obvious way to produce one.
			return nil, &ResourceError{Index: i, Offset: int64(start), Err: ErrBadResFile}
		}
	}

	if err := c.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrEmpty
	}
	return out, nil
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}