package link

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/backend"
	"github.com/vertex-language/pe/image"
	"github.com/vertex-language/pe/internal/format"
)

// The TLS directory is not a table this linker builds. The CRT declares it —
// as _tls_used — with its own initializers already in place, and most of what
// reaches the image comes from that object's relocations rather than from
// here. What is left for the linker is three things: point the TLS data
// directory at the structure, fill any address field the CRT left at zero, and
// account for the base relocations those fields need.
//
// The third is the one this file exists for. Every other stored address in a
// PE image is a 32-bit RVA, which does not change when the image moves. The
// four leading fields of the TLS directory are virtual addresses — the
// specification says so outright for the raw data bounds and it is equally
// true of the index and callback pointers — so each of them needs an entry in
// .reloc, and an image missing them runs correctly at its preferred base and
// crashes the first time ASLR moves it. That failure appears in production and
// not in testing, which is why this is checked rather than assumed.
//
// The subtlety is that a field can only be relocated once. If the CRT's object
// already carries an ADDR64 against _tls_start, the backend recorded a base
// relocation site for it during scan; registering a second site for the same
// field makes the loader add the delta twice, which is a wrong address that no
// tool reports. So this fills — and relocates — only the fields that arrived
// zero and unrelocated, and it verifies that every field that arrived non-zero
// is covered by somebody.
//
// Static TLS is also the one PE feature that does not survive LoadLibrary on
// older systems: a DLL loaded dynamically may find no TLS slot available. That
// is the loader's business and not this tree's, but it is why an image can
// legitimately carry a .tls section with no directory at all.

// tlsUsedSymbol and tlsIndexSymbol are the names the CRT gives the directory
// and the index.
//
// The specification spells them "__tls_used" on x86 and "_tls_used"
// elsewhere. That is one C name, _tls_used, seen through x86's leading
// underscore — which is why this switches on the machine rather than on the
// ABI. MinGW's CRT uses the same names.
func tlsUsedSymbol(m pe.Machine) string {
	if m == pe.MachineI386 {
		return "__tls_used"
	}
	return "_tls_used"
}

func tlsIndexSymbol(m pe.Machine) string {
	if m == pe.MachineI386 {
		return "__tls_index"
	}
	return "_tls_index"
}

// tlsSectionName is the output section the template lands in. The $ suffixes
// the CRT uses — .tls$AAA through .tls$ZZZ — bracket it, and merge has already
// discarded them by the time this runs.
const tlsSectionName = ".tls"

// tlsDirectory is the TLS synthetic.
//
// It owns no chunk, which is why its ChunkSource half reports nothing. The
// structure it fills belongs to an input object; this is a pass over that
// object's bytes wearing a Synthetic's shape, because Prepare and Generate are
// exactly the two moments it needs — one while sizes are settled and the other
// once addresses are final.
type tlsDirectory struct {
	l *Linker

	sym   *image.Symbol
	chunk *image.Chunk
	off   uint32
	width pe.Width

	// fill is the fields the linker will write, and therefore the fields
	// it owes a base relocation. It is settled in Prepare, from the bytes
	// the input actually carries, because .reloc is sized before layout.
	fill map[format.TLSField]bool

	// covered is the fields the input already relocates. A field in here
	// is never written and never re-relocated.
	covered map[format.TLSField]bool

	template *image.Section
}

func (t *tlsDirectory) Size() uint32           { return 0 }
func (t *tlsDirectory) Align() int             { return 1 }
func (t *tlsDirectory) Bytes() ([]byte, error) { return nil, nil }

// Prepare locates the directory, decides which fields the linker will fill,
// and registers a base relocation for each of them.
//
// It reads the input's bytes, which is allowed here and would not be later: a
// chunk's source reads from the object's extent on demand, so the *initial*
// contents are available before layout even though the output buffer is not.
// That is the only way to tell a field the CRT left at zero from one it
// initialized to an address that happens to be small.
func (t *tlsDirectory) Prepare(img *image.Image) error {
	l := t.l
	t.width = l.opt.Target.Width()
	t.fill = make(map[format.TLSField]bool)
	t.covered = make(map[format.TLSField]bool)

	s := l.tabs[0].Lookup(tlsUsedSymbol(l.opt.Target.Machine))
	if s == nil || s.chunk == nil || !s.chunk.Live() {
		// No TLS in this image. That is the common case and not a
		// condition: an image with no thread-locals has no directory,
		// and the data directory entry stays zero.
		return nil
	}
	t.sym, t.chunk, t.off = s.Out, s.chunk, s.off

	size := uint32(format.TLSDirectorySize(t.width))
	if uint64(t.off)+uint64(size) > uint64(t.chunk.Size()) {
		return l.fail(&image.LayoutError{
			Section: t.chunk.Name,
			Reason:  "the TLS directory runs past the end of the chunk defining _tls_used",
		})
	}

	// Which fields does the input already relocate? A VA-classified
	// relocation landing inside the directory owns that field, and the
	// backend has already recorded its base relocation site.
	for _, r := range t.chunk.Relocs() {
		if l.be.Classify(r.Type) != backend.KindVA {
			continue
		}
		if r.Off < t.off || r.Off >= t.off+size {
			continue
		}
		if f, ok := tlsFieldAt(r.Off-t.off, t.width); ok {
			t.covered[f] = true
		}
	}

	data, err := t.chunk.Bytes()
	if err != nil {
		return l.fail(&InputError{Name: t.chunk.Input, Err: err})
	}

	t.template = sectionNamed(img, tlsSectionName)

	// A field the linker fills is one that arrived zero, is not relocated,
	// and has an answer available. Start and End come from the template's
	// extent; Index comes from the CRT's own _tls_index. Callbacks has no
	// answer here — the array is the CRT's, and an image whose CRT left
	// that field zero simply has no callbacks.
	consider := func(f format.TLSField, have bool) {
		if !have || t.covered[f] {
			return
		}
		off, sz, ok := format.TLSFieldOffset(f, t.width)
		if !ok {
			return
		}
		if !isZero(data[t.off+uint32(off) : t.off+uint32(off)+uint32(sz)]) {
			// Initialized to something with no relocation behind
			// it. Overwriting it would discard whatever the CRT
			// meant; leaving it is checked in Generate.
			return
		}
		t.fill[f] = true
	}

	idx := l.tabs[0].Lookup(tlsIndexSymbol(l.opt.Target.Machine))
	consider(format.TLSStart, t.template != nil)
	consider(format.TLSEnd, t.template != nil)
	consider(format.TLSIndex, idx != nil && idx.chunk != nil && idx.chunk.Live())
	consider(format.TLSZeroFill, t.template != nil)

	// The base relocations. Only for the address fields, and only for the
	// ones this pass will write — the rest are the backend's, recorded
	// during scan, and a second site for the same address applies the
	// delta twice.
	kind := pe.BaseRelocDir64
	if t.width == pe.Width32 {
		kind = pe.BaseRelocHighLow
	}
	for f := range t.fill {
		if !f.IsAddress() {
			continue
		}
		off, _, _ := format.TLSFieldOffset(f, t.width)
		l.reqs.NeedBaseReloc(t.chunk, t.off+uint32(off), kind)
		l.reqs.NeedTLSFixup(t.sym)
	}
	return nil
}

// tlsFieldAt maps an offset within the directory back to the field starting
// there. A relocation landing part-way into a field belongs to no field, which
// is a malformed object rather than a case to interpret.
func tlsFieldAt(off uint32, w pe.Width) (format.TLSField, bool) {
	for f := format.TLSStart; f <= format.TLSCharacteristics; f++ {
		if o, _, ok := format.TLSFieldOffset(f, w); ok && uint32(o) == off {
			return f, true
		}
	}
	return 0, false
}

// Generate fills the fields and checks the ones it did not.
//
// It runs frozen, so the template's address is final. It runs before apply,
// which is what makes writing safe: a field this pass writes carries no
// relocation, so nothing will add to it afterwards.
func (t *tlsDirectory) Generate(img *image.Image) error {
	if t.chunk == nil {
		return nil
	}
	l := t.l
	base := l.opt.Base()

	rva, err := t.sym.RVA()
	if err != nil {
		return err
	}
	size := format.TLSDirectorySize(t.width)
	out, err := img.AtRVA(rva, size)
	if err != nil {
		return err
	}

	var start, end pe.RVA
	var zeroFill uint32
	if t.template != nil {
		start, end, zeroFill, err = tlsExtent(t.template)
		if err != nil {
			return err
		}
	}

	put := func(f format.TLSField, v uint64) error {
		if !t.fill[f] {
			return nil
		}
		off, sz, _ := format.TLSFieldOffset(f, t.width)
		if f.IsAddress() {
			v = uint64(pe.RVA(v).VA(base))
		}
		for i := 0; i < sz; i++ {
			out[off+i] = byte(v >> (8 * i))
		}
		return nil
	}

	if err := put(format.TLSStart, uint64(start)); err != nil {
		return err
	}
	if err := put(format.TLSEnd, uint64(end)); err != nil {
		return err
	}
	if t.fill[format.TLSIndex] {
		idx := l.tabs[0].Lookup(tlsIndexSymbol(l.opt.Target.Machine))
		ir, err := idx.Out.RVA()
		if err != nil {
			return err
		}
		if err := put(format.TLSIndex, uint64(ir)); err != nil {
			return err
		}
	}
	if err := put(format.TLSZeroFill, uint64(zeroFill)); err != nil {
		return err
	}

	return t.checkRelocatable(out)
}

// checkRelocatable refuses a VA field that nothing will fix up.
//
// A field this pass filled has a site registered. A field the input relocated
// has one from the backend. Anything else non-zero is an address somebody
// wrote down as a constant, and under /DYNAMICBASE that is an image which runs
// at its preferred base and faults after ASLR — the same failure
// ErrUnrelocatable exists for, arriving from the one place in the format where
// a stored address is a VA.
func (t *tlsDirectory) checkRelocatable(out []byte) error {
	if !t.l.opt.DllChar.Has(pe.DynamicBase) {
		return nil
	}
	for f := format.TLSStart; f <= format.TLSCallbacks; f++ {
		if t.fill[f] || t.covered[f] {
			continue
		}
		off, sz, _ := format.TLSFieldOffset(f, t.width)
		if isZero(out[off : off+sz]) {
			continue
		}
		return &UnrelocatableError{
			Chunk: t.chunk.Name + "." + f.String(),
			Input: t.chunk.Input,
			Off:   t.off + uint32(off),
		}
	}
	return nil
}

// tlsExtent returns the template's bounds and its zero fill.
//
// Start is the section's address. End is the address after the last chunk with
// file content, because the specification defines it as the last byte of
// initialized data — and the zero fill is everything the section occupies past
// that. merge has already ordered content ahead of zero fill, which is what
// makes the split a single boundary rather than a scan.
func tlsExtent(s *image.Section) (start, end pe.RVA, zeroFill uint32, err error) {
	start, err = s.RVA()
	if err != nil {
		return 0, 0, 0, err
	}
	vsize, err := s.VirtualSize()
	if err != nil {
		return 0, 0, 0, err
	}
	end = start
	for _, c := range s.Chunks() {
		if !c.Live() || !c.HasContent() {
			continue
		}
		r, err := c.RVA()
		if err != nil {
			return 0, 0, 0, err
		}
		if e := r.Add(c.Size()); e > end {
			end = e
		}
	}
	return start, end, vsize - uint32(end-start), nil
}

// Dirs returns the TLS data directory entry.
func (t *tlsDirectory) Dirs() []dirEntry {
	if t.chunk == nil {
		return nil
	}
	rva, err := t.sym.RVA()
	if err != nil {
		return nil
	}
	return []dirEntry{{pe.DirTLS, rva, uint32(format.TLSDirectorySize(t.width))}}
}

// sectionNamed returns the output section with this name, or nil.
//
// There is no lookup by name on image.Image, deliberately — /MERGE and
// /SECTION make the mapping from input name to output section a decision
// rather than a fact. The synthetics that need one specific section by name
// are asking about a section they created or the CRT's convention named, which
// is the case the general prohibition is not about.
func sectionNamed(img *image.Image, name string) *image.Section {
	for _, s := range img.Sections() {
		if s.Name == name {
			return s
		}
	}
	return nil
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}