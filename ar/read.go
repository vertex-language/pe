package ar

import (
	"strconv"
	"strings"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/internal/binio"
)

// NewFile reads an archive from an extent.
//
// The walk is two passes and has to be. The "//" member resolves long names,
// and MSVC puts it after both index members but before the content — so a
// single pass would resolve names it has not yet read the table for. The first
// pass records raw name fields and positions; the second resolves.
func NewFile(ext *binio.Extent) (*File, error) {
	head, err := ext.Head(MagicSize)
	if err != nil {
		return nil, err
	}
	f := &File{ext: ext}
	switch {
	case string(head) == Magic:
	case string(head) == ThinMagic:
		f.Thin = true
	default:
		return nil, ErrNotArchive
	}

	raw, err := f.walk()
	if err != nil {
		return nil, err
	}
	if err := f.resolve(raw); err != nil {
		return nil, err
	}
	if err := f.readIndices(raw); err != nil {
		return nil, err
	}
	return f, nil
}

// rawMember is a member as read in the first pass, before names mean anything.
type rawMember struct {
	name    [hdrNameLen]byte
	hdrOff  int64
	dataOff int64
	size    int64
	modTime int64
	uid     int
	gid     int
	mode    uint32
}

// walk reads every member header without interpreting names.
func (f *File) walk() ([]rawMember, error) {
	var out []rawMember
	off := int64(MagicSize)
	size := f.ext.Size()

	for off+MemberHeaderSize <= size {
		b, err := f.ext.At(off, MemberHeaderSize)
		if err != nil {
			return nil, &MemberError{Index: len(out), Offset: off, Err: err}
		}
		if b[hdrEndOff] != hdrTerminator[0] || b[hdrEndOff+1] != hdrTerminator[1] {
			return nil, &MemberError{Index: len(out), Offset: off, Err: ErrBadHeader}
		}

		var m rawMember
		copy(m.name[:], b[hdrNameOff:hdrNameOff+hdrNameLen])
		if strings.HasPrefix(string(m.name[:]), "#1/") {
			return nil, &MemberError{Index: len(out), Offset: off, Err: ErrBSDArchive}
		}

		n, err := field(b, hdrSizeOff, hdrSizeLen, 10)
		if err != nil {
			return nil, &MemberError{Index: len(out), Offset: off, Err: ErrBadHeader}
		}
		m.size = int64(n)
		m.hdrOff = off
		m.dataOff = off + MemberHeaderSize
		if m.dataOff+m.size > size {
			return nil, &MemberError{Index: len(out), Offset: off, Err: ErrBadHeader}
		}

		// The remaining fields are advisory. An empty date, uid, or gid
		// is common in deterministic archives and is not a failure.
		if v, err := field(b, hdrDateOff, hdrDateLen, 10); err == nil {
			m.modTime = int64(v)
		}
		if v, err := field(b, hdrUIDOff, hdrUIDLen, 10); err == nil {
			m.uid = int(v)
		}
		if v, err := field(b, hdrGIDOff, hdrGIDLen, 10); err == nil {
			m.gid = int(v)
		}
		if v, err := field(b, hdrModeOff, hdrModeLen, 8); err == nil {
			m.mode = uint32(v)
		}

		out = append(out, m)

		next := m.dataOff + m.size
		if next%MemberAlign != 0 {
			next++
		}
		if next <= off {
			// A header that does not advance is an infinite loop, and
			// a hostile archive is the obvious way to produce one.
			return nil, &MemberError{Index: len(out) - 1, Offset: off, Err: ErrBadHeader}
		}
		off = next
	}
	return out, nil
}

// field parses one space-padded ASCII header field.
func field(b []byte, off, n, base int) (uint64, error) {
	s := strings.TrimSpace(string(b[off : off+n]))
	if s == "" {
		return 0, strconv.ErrSyntax
	}
	return strconv.ParseUint(s, base, 64)
}

// resolve reads the "//" member, then names every member.
func (f *File) resolve(raw []rawMember) error {
	for i := range raw {
		if strings.TrimRight(string(raw[i].name[:]), " ") != LongNamesMemberName {
			continue
		}
		b, err := f.ext.At(raw[i].dataOff, raw[i].size)
		if err != nil {
			return &MemberError{Index: i, Name: LongNamesMemberName, Offset: raw[i].hdrOff, Err: err}
		}
		f.longNames = b
		break
	}

	f.Members = make([]*Member, len(raw))
	for i := range raw {
		name, special, err := f.resolveName(raw[i].name[:])
		if err != nil {
			return &MemberError{
				Index:  i,
				Name:   strings.TrimRight(string(raw[i].name[:]), " "),
				Offset: raw[i].hdrOff,
				Err:    err,
			}
		}
		f.Members[i] = &Member{
			Name:       name,
			Offset:     raw[i].hdrOff,
			DataOffset: raw[i].dataOff,
			Size:       raw[i].size,
			ModTime:    raw[i].modTime,
			UID:        raw[i].uid,
			GID:        raw[i].gid,
			Mode:       raw[i].mode,
			Special:    special,
			f:          f,
		}
	}
	return nil
}

// readIndices decodes the linker members and decides the layout.
//
// The two MSVC index members share the name "/" and are distinguished only by
// being first and second. The reader trusts the second and falls back to the
// first only when there is no second — which is also how it tells an MSVC
// archive from a GNU one, since a GNU archive has exactly one.
func (f *File) readIndices(raw []rawMember) error {
	var linkers []*Member
	var ecMember *Member
	for _, m := range f.Members {
		switch m.Name {
		case LinkerMemberName:
			linkers = append(linkers, m)
		case ECSymbolsMemberName:
			ecMember = m
		}
	}

	switch len(linkers) {
	case 0:
		f.Kind = KindUnknown
		return nil

	case 1:
		// One index member. Its content decides the layout rather than
		// its position: a GNU index is big-endian and an MSVC second
		// member is little-endian, and an MSVC archive missing its
		// second member is a thing that exists.
		f.Kind = KindGNU
		b, err := linkers[0].Data()
		if err != nil {
			return err
		}
		ix, err := decodeFirstIndex(b)
		if err != nil {
			return err
		}
		f.Index, f.LegacyIndex = ix, ix
		return nil

	default:
		f.Kind = KindMSVC
		if b, err := linkers[0].Data(); err == nil {
			// A malformed legacy index is not fatal: nothing in this
			// tree reads it, and the authoritative one follows.
			if ix, err := decodeFirstIndex(b); err == nil {
				f.LegacyIndex = ix
			}
		}
		b, err := linkers[1].Data()
		if err != nil {
			return err
		}
		ix, offsets, err := decodeSecondIndex(b)
		if err != nil {
			return err
		}
		f.Index = ix

		if ecMember != nil {
			eb, err := ecMember.Data()
			if err != nil {
				return err
			}
			// The EC member carries no offset table of its own and
			// indexes the second member's. Decoding it in isolation
			// is not possible, which is why offsets are threaded
			// through rather than each member decoding alone.
			ec, err := decodeECIndex(eb, offsets)
			if err != nil {
				return err
			}
			f.ECIndex = ec
		}
		return nil
	}
}

// MachineOf returns the machine type of a member, for routing it to the EC
// index. It answers false for a member that is not an object of any kind.
//
// This is the whole of ar's knowledge of COFF, and it is borrowed rather than
// implemented: pe.MachineOf reads the field from a header prefix and knows
// where it sits in each object kind.
func (m *Member) MachineOf() (pe.Machine, bool) {
	head, err := m.f.ext.At(m.DataOffset, min64(m.Size, int64(pe.KindPrefix)))
	if err != nil {
		return pe.MachineUnknown, false
	}
	return pe.MachineOf(head)
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}