package ar

import (
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/vertex-language/pe/internal/binio"
)

// The container is ancient and simple: an eight-byte magic, then a run of
// 60-byte ASCII headers each followed by its member's bytes, each member padded
// to an even offset. Everything interesting is in what the special members
// mean, and those differ between the two layouts this package handles.

const (
	// Magic begins an ordinary archive.
	Magic = "!<arch>\n"
	// ThinMagic begins a thin archive, whose members are paths rather than
	// contents.
	ThinMagic = "!<thin>\n"
	// MagicSize is the length of either.
	MagicSize = 8

	// MemberHeaderSize is one member header.
	MemberHeaderSize = 60

	// MemberAlign is the boundary every member header must start on.
	MemberAlign = 2
	// MemberPadByte is what the gap is filled with. It is a newline rather
	// than a zero because the header is text and the format predates the
	// idea that it might not be read by a human.
	MemberPadByte = '\n'
)

// Field offsets within a member header. Every one is left-justified ASCII,
// space-padded, and none is terminated.
const (
	hdrNameOff, hdrNameLen = 0, 16
	hdrDateOff, hdrDateLen = 16, 12
	hdrUIDOff, hdrUIDLen   = 28, 6
	hdrGIDOff, hdrGIDLen   = 34, 6
	hdrModeOff, hdrModeLen = 40, 8
	hdrSizeOff, hdrSizeLen = 48, 10
	hdrEndOff, hdrEndLen   = 58, 2
)

// hdrTerminator ends every member header and is the only thing in it that is
// not a padded decimal field.
var hdrTerminator = [2]byte{'`', '\n'}

// The reserved member names.
const (
	// LinkerMemberName is the name of *both* MSVC index members, and of the
	// single GNU one. They cannot be told apart by name — only by order.
	LinkerMemberName = "/"

	// LongNamesMemberName holds names too long for the 16-byte field.
	LongNamesMemberName = "//"

	// ECSymbolsMemberName maps ARM64EC symbols. It indexes the *second*
	// linker member's offset table and carries none of its own.
	ECSymbolsMemberName = "/<ECSYMBOLS>/"

	// XFGHashMapMemberName appears in newer Windows SDK libraries. This
	// tree does not interpret it, and passes it through untouched.
	XFGHashMapMemberName = "/<XFGHASHMAP>/"
)

// Kind is the archive layout.
type Kind uint8

const (
	// KindUnknown means the layout was not determined, which for a
	// well-formed archive means it had no linker member at all.
	KindUnknown Kind = iota
	// KindMSVC has two index members, both named "/": a legacy big-endian
	// one and an authoritative little-endian one.
	KindMSVC
	// KindGNU has one big-endian index member named "/". MinGW's .dll.a
	// import libraries have this shape.
	KindGNU
)

func (k Kind) String() string {
	switch k {
	case KindMSVC:
		return "msvc"
	case KindGNU:
		return "gnu"
	}
	return "unknown"
}

// Member is one archive member.
//
// Data is read on demand from the underlying extent, so opening a forty-megabyte
// import library costs the headers and the indices, not the library.
type Member struct {
	// Name is the resolved name, with any long-name escape followed and any
	// trailing slash removed.
	Name string

	// Offset is the file offset of this member's header; DataOffset is
	// where its bytes begin. The index members store the former, which is
	// worth stating because storing the latter would also have worked and
	// is what a reimplementation tends to guess.
	Offset     int64
	DataOffset int64
	Size       int64

	ModTime int64
	UID     int
	GID     int
	Mode    uint32

	// Special reports whether this is a reserved member — an index, the
	// long-name table, or a bracketed extension — rather than content.
	Special bool

	f *File
}

// Data returns the member's contents.
func (m *Member) Data() ([]byte, error) {
	if m.Size == 0 {
		return nil, nil
	}
	return m.f.ext.At(m.DataOffset, m.Size)
}

// Extent returns a bounded window over the member's bytes.
//
// This is the point of the whole arrangement: handing one of these to
// coff.NewFile parses that member without copying it out, and a decode that
// walks off the end of its member hits this bound rather than wandering into
// the next one.
func (m *Member) Extent() (*binio.Extent, error) {
	return m.f.ext.Sub(m.DataOffset, m.Size)
}

// File is an archive open for reading.
type File struct {
	// Kind is the layout inferred from the index members present.
	Kind Kind

	// Thin reports whether members are paths rather than contents.
	Thin bool

	// Members holds every member in file order, reserved ones included.
	// Objects filters them.
	Members []*Member

	// Index is the symbol index this package trusts. For an MSVC archive
	// that is the second linker member; for GNU it is the only one. It is
	// nil if the archive has none.
	Index *Index

	// LegacyIndex is the MSVC first linker member, kept because it is the
	// only index some very old tools read, and because a writer that wants
	// to round-trip an archive needs to know it was there.
	LegacyIndex *Index

	// ECIndex maps ARM64EC symbols, or nil.
	ECIndex *Index

	ext       *binio.Extent
	closer    io.Closer
	longNames []byte
}

// Open reads the archive at path. The returned File holds the descriptor, so
// Close must be called.
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
	a, err := NewFile(ext)
	if err != nil {
		f.Close()
		return nil, err
	}
	a.closer = f
	return a, nil
}

// Close releases the underlying file, if this File owns one.
func (f *File) Close() error {
	if f.closer != nil {
		err := f.closer.Close()
		f.closer = nil
		return err
	}
	return nil
}

// Objects returns the members that are not reserved: the actual content.
func (f *File) Objects() []*Member {
	out := make([]*Member, 0, len(f.Members))
	for _, m := range f.Members {
		if !m.Special {
			out = append(out, m)
		}
	}
	return out
}

// Lookup returns the member defining sym, or nil if the index does not name it.
//
// It reports ErrNoIndex rather than scanning the members. An archive without an
// index is not one a linker can use, and quietly making it work here would hide
// that from the caller who has to ship it.
func (f *File) Lookup(sym string) (*Member, error) {
	if f.Index == nil {
		return nil, ErrNoIndex
	}
	return f.lookupIn(f.Index, sym)
}

// LookupEC returns the member defining sym in the ARM64EC namespace.
func (f *File) LookupEC(sym string) (*Member, error) {
	if f.ECIndex == nil {
		return nil, ErrNoIndex
	}
	return f.lookupIn(f.ECIndex, sym)
}

func (f *File) lookupIn(ix *Index, sym string) (*Member, error) {
	off, ok := ix.Offset(sym)
	if !ok {
		return nil, nil
	}
	for _, m := range f.Members {
		if m.Offset == off {
			return m, nil
		}
	}
	// The index named a position that is not a member header. That is a
	// corrupt index, not a missing symbol, and the two want different
	// reactions from the caller.
	return nil, ErrBadIndex
}

// Symbols returns every symbol in the trusted index, in index order.
func (f *File) Symbols() []string {
	if f.Index == nil {
		return nil
	}
	out := make([]string, len(f.Index.Entries))
	for i, e := range f.Index.Entries {
		out[i] = e.Name
	}
	return out
}

// resolveName turns a raw 16-byte name field into a member name.
//
// The two layouts disagree about the long-name table's terminator — GNU ends
// each entry with "/\n" and MSVC with a NUL — so the lookup accepts either
// rather than branching on a Kind that has not been determined yet at the point
// the first member is read.
func (f *File) resolveName(raw []byte) (string, bool, error) {
	s := strings.TrimRight(string(raw), " ")
	switch {
	case s == "":
		return "", false, ErrBadHeader

	case strings.HasPrefix(s, "#1/"):
		return "", false, ErrBSDArchive

	case s == LinkerMemberName || s == LongNamesMemberName:
		return s, true, nil

	case strings.HasPrefix(s, "/<"):
		// A bracketed name is a known extension family. Unknown members
		// of it pass through rather than being rejected: a tool that
		// assumes every "/"-prefixed name is a decimal offset is exactly
		// what fails on /<XFGHASHMAP>/.
		return s, true, nil

	case strings.HasPrefix(s, "/"):
		off, err := strconv.ParseUint(s[1:], 10, 32)
		if err != nil {
			return "", false, ErrBadHeader
		}
		name, err := f.longName(uint32(off))
		return name, false, err
	}
	return strings.TrimSuffix(s, "/"), false, nil
}

// longName reads an entry from the "//" member.
func (f *File) longName(off uint32) (string, error) {
	if f.longNames == nil {
		return "", ErrNoLongNames
	}
	if int(off) >= len(f.longNames) {
		return "", ErrBadHeader
	}
	rest := f.longNames[off:]
	for i, c := range rest {
		if c == 0 || c == '/' || c == '\n' {
			return string(rest[:i]), nil
		}
	}
	// A name running to the end of the table with no terminator is a
	// truncated table, not a very long name.
	return "", ErrBadHeader
}