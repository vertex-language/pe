package ar

import "sort"

// The index members are the only place in this tree that is not little-endian,
// and the only place where two members of the same file disagree about byte
// order. The first linker member is big-endian because it is inherited from
// System V ar; the second is little-endian because Microsoft wrote it.
//
// Three shapes:
//
//	first  — count, then one offset per symbol, then the names. Big-endian,
//	         member order, one entry per symbol.
//	second — member count, an offset table, then a symbol count, then one
//	         16-bit index into that table per symbol, then the names.
//	         Little-endian, sorted by name so the linker can binary-search.
//	EC     — the second member's shape with the offset table removed. It
//	         indexes the second member's table.

// IndexEntry is one symbol and the member that defines it.
type IndexEntry struct {
	Name string
	// Offset is the file offset of the defining member's *header*, not of
	// its data.
	Offset int64
}

// Index is a decoded symbol index.
type Index struct {
	// Entries is in the order the member stored them: file order for a
	// first linker member, sorted by name for the others.
	Entries []IndexEntry

	// Sorted reports whether Entries is in name order, and therefore
	// whether Offset can binary-search.
	Sorted bool
}

// Offset returns the defining member's header offset for sym.
func (ix *Index) Offset(sym string) (int64, bool) {
	if ix == nil {
		return 0, false
	}
	if ix.Sorted {
		i := sort.Search(len(ix.Entries), func(i int) bool {
			return ix.Entries[i].Name >= sym
		})
		if i < len(ix.Entries) && ix.Entries[i].Name == sym {
			return ix.Entries[i].Offset, true
		}
		return 0, false
	}
	for _, e := range ix.Entries {
		if e.Name == sym {
			return e.Offset, true
		}
	}
	return 0, false
}

func be32(b []byte, off int) uint32 {
	return uint32(b[off])<<24 | uint32(b[off+1])<<16 |
		uint32(b[off+2])<<8 | uint32(b[off+3])
}

func le32(b []byte, off int) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 |
		uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

func le16(b []byte, off int) uint16 {
	return uint16(b[off]) | uint16(b[off+1])<<8
}

// names splits a run of NUL-terminated strings, requiring exactly n of them.
//
// A short run is a truncated index. Returning what was there would produce an
// index that resolves some symbols and silently loses the rest, which is worse
// than one that fails.
func names(b []byte, n int) ([]string, error) {
	out := make([]string, 0, n)
	start := 0
	for i := 0; i < len(b) && len(out) < n; i++ {
		if b[i] == 0 {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	if len(out) != n {
		return nil, ErrBadIndex
	}
	return out, nil
}

// decodeFirstIndex reads the big-endian System V index: the MSVC first linker
// member, and the only index a GNU archive has.
func decodeFirstIndex(b []byte) (*Index, error) {
	if len(b) < 4 {
		return nil, ErrBadIndex
	}
	n := int(be32(b, 0))
	if n < 0 || 4+n*4 > len(b) {
		return nil, ErrBadIndex
	}
	ns, err := names(b[4+n*4:], n)
	if err != nil {
		return nil, err
	}
	ix := &Index{Entries: make([]IndexEntry, n)}
	for i := 0; i < n; i++ {
		ix.Entries[i] = IndexEntry{Name: ns[i], Offset: int64(be32(b, 4+i*4))}
	}
	return ix, nil
}

// decodeSecondIndex reads the little-endian MSVC index, returning the decoded
// index and the offset table the EC member will need.
func decodeSecondIndex(b []byte) (*Index, []int64, error) {
	if len(b) < 4 {
		return nil, nil, ErrBadIndex
	}
	nmem := int(le32(b, 0))
	if nmem < 0 || 4+nmem*4+4 > len(b) {
		return nil, nil, ErrBadIndex
	}
	offsets := make([]int64, nmem)
	for i := 0; i < nmem; i++ {
		offsets[i] = int64(le32(b, 4+i*4))
	}
	p := 4 + nmem*4
	nsym := int(le32(b, p))
	p += 4
	if nsym < 0 || p+nsym*2 > len(b) {
		return nil, nil, ErrBadIndex
	}
	idx := make([]uint16, nsym)
	for i := 0; i < nsym; i++ {
		idx[i] = le16(b, p+i*2)
	}
	ns, err := names(b[p+nsym*2:], nsym)
	if err != nil {
		return nil, nil, err
	}
	ix, err := joinIndices(idx, ns, offsets)
	if err != nil {
		return nil, nil, err
	}
	return ix, offsets, nil
}

// decodeECIndex reads the /<ECSYMBOLS>/ member against the second linker
// member's offset table.
func decodeECIndex(b []byte, offsets []int64) (*Index, error) {
	if len(b) < 4 {
		return nil, ErrBadIndex
	}
	nsym := int(le32(b, 0))
	if nsym < 0 || 4+nsym*2 > len(b) {
		return nil, ErrBadIndex
	}
	idx := make([]uint16, nsym)
	for i := 0; i < nsym; i++ {
		idx[i] = le16(b, 4+i*2)
	}
	ns, err := names(b[4+nsym*2:], nsym)
	if err != nil {
		return nil, err
	}
	return joinIndices(idx, ns, offsets)
}

// joinIndices resolves 1-based table indices into member offsets.
//
// The indices are one-based, which is the detail that turns a working reader
// into one that returns the previous member for every symbol.
func joinIndices(idx []uint16, ns []string, offsets []int64) (*Index, error) {
	ix := &Index{Entries: make([]IndexEntry, len(idx)), Sorted: true}
	for i, n := range idx {
		if n == 0 || int(n) > len(offsets) {
			return nil, ErrBadIndex
		}
		ix.Entries[i] = IndexEntry{Name: ns[i], Offset: offsets[n-1]}
	}
	for i := 1; i < len(ix.Entries); i++ {
		if ix.Entries[i-1].Name > ix.Entries[i].Name {
			// Declared sorted by the format, but a producer that got
			// it wrong would make binary search silently miss. Fall
			// back rather than trust it.
			ix.Sorted = false
			break
		}
	}
	return ix, nil
}