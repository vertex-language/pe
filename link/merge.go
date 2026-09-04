package link

import (
	"sort"
	"strings"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/image"
)

// Merge decides which output section each surviving chunk lands in and in what
// order, folds identical COMDATs, and creates the sections.
//
// The ordering rule is the one that is load-bearing. The linker discards the
// '$' and everything after it when choosing the output section, but the full
// name decides the order within it: contributions with the same object-section
// name are contiguous, and the blocks are sorted lexically. That is what makes
// .CRT$XCA through .CRT$XCZ bracket the C++ initializer array and what puts
// TLS callbacks in .CRT$XLB between them. A linker that sorted by anything
// else — input order, size, symbol name — would produce an image whose CRT
// startup walks a table with no beginning and no end.

// defaultOrder is the output section order when the caller states none.
//
// It is roughly link.exe's, and the parts that matter are that code comes
// first, that read-only data precedes writable data, and that .reloc is last —
// the loader drops it after applying it, and a discardable section at the end
// of the image is one whose pages are never faulted back in.
var defaultOrder = []string{
	".text", ".rdata", ".data", ".pdata", ".xdata",
	".idata", ".didat", ".edata", ".tls", ".rsrc", ".reloc",
}

// merge runs the merge phase.
func (l *Linker) merge() error {
	l.markAddrTaken()
	l.addGNUImportTerminator()
	if err := l.fold(); err != nil {
		return err
	}
	return l.place()
}

// groupOf returns the output section name a chunk lands in, following /MERGE.
//
// The mapping is applied repeatedly because /MERGE:.rdata=.text followed by
// /MERGE:.text=.code has to reach .code. The bound is the number of merge
// requests: a chain longer than that has revisited a name, which is a cycle,
// and a cycle silently resolved by stopping early would put the chunk in
// whichever section the loop happened to be at.
func (l *Linker) groupOf(c *image.Chunk) (string, error) {
	name := c.GroupName()
	for i := 0; i <= len(l.opt.Merges); i++ {
		next := name
		for _, m := range l.opt.Merges {
			if m.From == name {
				next = m.To
				break
			}
		}
		if next == name {
			return name, nil
		}
		name = next
	}
	return "", l.fail(&DirectiveError{
		Name: "MERGE", Value: c.GroupName(),
		Reason: "merge requests form a cycle", Err: ErrDirectiveNotAllowed,
	})
}

// group is one output section's worth of chunks before it becomes a real
// image.Section: a name and everything place decided belongs under it.
type group struct {
	name   string
	chunks []*image.Chunk
}

// place groups the live chunks, sorts each group, and creates the sections.
func (l *Linker) place() error {
	var groups []*group
	byName := make(map[string]*group)

	for _, c := range l.live() {
		name, err := l.groupOf(c)
		if err != nil {
			return err
		}
		g := byName[name]
		if g == nil {
			g = &group{name: name}
			byName[name] = g
			groups = append(groups, g)
		}
		g.chunks = append(g.chunks, c)
	}
	if len(groups) == 0 {
		return l.fail(ErrNoInputs)
	}

	sortGroups(groups, l.opt.SectionOrder)

	for _, g := range groups {
		sortChunks(g.chunks)

		if groupSize(g) == 0 {
			// A section header describing no bytes and no address
			// space is one the Windows loader refuses the whole
			// image over — MiCreateImageFileMap rejects a section
			// whose virtual size and raw size are both zero, and
			// the process never starts, with "not a valid Win32
			// application" as the only explanation offered.
			//
			// The MSVC CRT ships several: .gsspr and .gssep arrive
			// as empty sections in every object that includes the
			// stack-guard headers, so this is not a corner case but
			// the ordinary path. link.exe drops them too.
			//
			// The chunks go with it. They occupy nothing, so there
			// is nothing to place elsewhere, and a chunk left live
			// with no section is one contents asks for the address
			// of and does not get.
			for _, c := range g.chunks {
				c.Discarded = true
			}
			continue
		}

		name, err := l.sectionName(g.name)
		if err != nil {
			return err
		}
		kind, prot := l.attrs(g.chunks, g.name)

		sec, err := l.img.AddSection(name, kind, prot)
		if err != nil {
			return l.fail(err)
		}
		for _, c := range g.chunks {
			if err := sec.Add(c); err != nil {
				return l.fail(err)
			}
		}
	}
	return nil
}

// sortGroups orders the output sections: the caller's order first, then the
// conventional one, then anything left over in the order it appeared.
func sortGroups(groups []*group, explicit []string) {
	rank := make(map[string]int)
	for i, n := range explicit {
		rank[n] = i
	}
	base := len(explicit)
	for i, n := range defaultOrder {
		if _, ok := rank[n]; !ok {
			rank[n] = base + i
		}
	}
	unknown := base + len(defaultOrder)

	sort.SliceStable(groups, func(i, j int) bool {
		ri, oki := rank[groups[i].name]
		rj, okj := rank[groups[j].name]
		if !oki {
			ri = unknown
		}
		if !okj {
			rj = unknown
		}
		return ri < rj
	})
}

// sortChunks orders the contributions within one output section.
//
// The primary key is the full input section name, '$' included, so
// .CRT$XCA sorts before .CRT$XCU sorts before .CRT$XCZ and the initializer
// array has the brackets the CRT walks between. Chunks that tie on name are
// ordered by chunkRank; two that also tie there keep input order, which is
// what makes two runs of this linker over the same inputs produce the same
// bytes.
func sortChunks(chunks []*image.Chunk) {
	sort.SliceStable(chunks, func(i, j int) bool {
		a, b := chunks[i], chunks[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return chunkRank(a) < chunkRank(b)
	})
}

// chunkRank orders chunks that share one input section name.
//
// The default rule is not cosmetic. SizeOfRawData describes a *prefix* of a
// section rather than a subset of it, so a chunk with file content cannot
// follow one without: the loader would either not read it or read the
// zeroes as content. image.assignSection refuses that placement, and giving
// content rank 0 is where it is avoided.
//
// .idata$4 and .idata$5 need a finer rule than content-vs-not, because a
// dlltool-generated import group puts three different roles under the same
// two names and discovery order cannot tell them apart: the head object's
// own entry is a zero-size placeholder whose only job is to define the
// symbol the descriptor's OriginalFirstThunk/FirstThunk point at — it must
// rank first, or that symbol resolves to the wrong address entirely, not
// merely a reordered table. The tail object's entry is the zero-filled
// terminator the loader's walk stops on — it must rank last, or the walk
// stops before every real entry has been seen. Nothing here can rely on the
// order these were pulled into the link: the head object forces its DLL's
// tail object in directly, so the terminator is often resolved before the
// per-symbol objects supplying the real entries it must follow, while a
// real entry is only pulled in when the symbol it defines is referenced.
// What does distinguish the three is content: the head's placeholder is the
// only one with zero size, and of the two that remain, a terminator carries
// no relocation (there is nothing left for it to point at) and its raw
// bytes are entirely zero, where a real entry always fails at least one of
// those — a named import relocates against .idata$6, and an ordinal import
// has no relocation but encodes the ordinal with the high bit set, so its
// bytes are not zero.
func chunkRank(c *image.Chunk) int {
	switch c.Name {
	case ".idata$4", ".idata$5", ".didat$4", ".didat$5":
		switch {
		case c.Size() == 0:
			return 0
		case isGNUImportTerminator(c):
			return 2
		default:
			return 1
		}
	}
	if c.HasContent() {
		return 0
	}
	return 1
}

// isGNUImportTerminator reports whether c is dlltool's zero-filled
// .idata$4/.idata$5 terminator entry rather than a real thunk slot. See
// chunkRank for why content, not discovery order, is what has to decide
// this.
func isGNUImportTerminator(c *image.Chunk) bool {
	if len(c.Relocs()) != 0 {
		return false
	}
	data, err := c.Bytes()
	if err != nil {
		return false
	}
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

// sectionName resolves an output section's name against the eight-byte field.
//
// An image has no string table — the specification says so outright — so the
// "/N" escape an object file uses does not exist here. link.exe truncates and
// lld emits a non-standard string table for discardable sections and warns;
// this tree errors, because a silently renamed section is one nobody can find
// again, and truncating is available under Options.TruncateNames for a build
// that would rather match link.exe.
func (l *Linker) sectionName(name string) (string, error) {
	if len(name) <= 8 {
		return name, nil
	}
	if !l.opt.TruncateNames {
		return "", l.fail(&image.LayoutError{
			Section: name,
			Reason:  "name longer than eight bytes and /TRUNCATENAMES is off",
		})
	}
	return name[:8], nil
}

// attrs computes an output section's characteristics from its contributions.
//
// The content flags are a union and the memory flags are a union, and then a
// /SECTION override replaces the memory half outright. Only the memory half is
// overridable: what a section contains is decided by what was put in it, and
// letting a directive change that would change what the section is rather than
// how it may be touched.
//
// The alignment nibble is not here at all. It is an object-file property with
// no meaning in an image, where every section is aligned to SectionAlignment.
func (l *Linker) attrs(chunks []*image.Chunk, group string) (pe.SecKind, pe.SecProt) {
	var kind pe.SecKind
	var prot pe.SecProt
	for _, c := range chunks {
		info := l.info[c]
		if info == nil {
			continue
		}
		kind |= info.sec.Kind()
		prot |= info.sec.Prot()
	}

	// The LNK_* bits are object-file bookkeeping and must not reach an
	// image. LNK_COMDAT in particular would tell the loader nothing and
	// tell a reader something false.
	kind &^= pe.SecLnkOther | pe.SecLnkInfo | pe.SecLnkRemove |
		pe.SecLnkComdat | pe.SecLnkNRelocOvfl | pe.SecTypeNoPad

	if prot == 0 {
		// A synthesized group with no input sections behind it. Derive
		// something defensible from what it holds rather than emitting a
		// section the loader maps with no access at all.
		switch {
		case kind.Has(pe.SecCode):
			prot = pe.SecExecute | pe.SecRead
		case kind.Has(pe.SecUninitData):
			prot = pe.SecRead | pe.SecWrite
		default:
			prot = pe.SecRead
		}
	}

	for _, ov := range l.opt.Sections {
		if ov.Name == group {
			prot = ov.Prot
		}
	}
	return kind, prot
}

// fold performs identical COMDAT folding.
//
// It is a fixpoint rather than a pass, and the reason is worth stating: two
// functions that differ only in which of two identical callees they call
// become identical themselves once those callees are folded. link.exe exposes
// this as an iteration count and defaults it to one; this runs to convergence,
// because stopping early leaves a result that depends on how the input
// happened to be ordered.
//
// The algorithm is the standard one. Chunks are partitioned into classes by
// everything that does not depend on another chunk's identity — bytes,
// relocation offsets, relocation types — and then each class is refined by the
// classes of the chunks its relocations target, until no class splits.
func (l *Linker) fold() error {
	if l.opt.OptICF == ICFNone {
		return nil
	}

	var cands []*image.Chunk
	for _, c := range l.live() {
		if l.foldable(c) {
			cands = append(cands, c)
		}
	}
	if len(cands) < 2 {
		return nil
	}

	class := make(map[*image.Chunk]int, len(cands))
	for _, c := range cands {
		key, err := l.shapeKey(c)
		if err != nil {
			return err
		}
		class[c] = 0
		_ = key
	}

	// Initial partition by shape.
	shapes := make(map[string]int)
	for _, c := range cands {
		key, err := l.shapeKey(c)
		if err != nil {
			return err
		}
		id, ok := shapes[key]
		if !ok {
			id = len(shapes) + 1
			shapes[key] = id
		}
		class[c] = id
	}

	// A stable number for every chunk, for the identity case below. The
	// order is l.chunks', which is creation order and so is the same on
	// every run over the same inputs.
	ident := make(map[*image.Chunk]int, len(l.chunks))
	for i, c := range l.chunks {
		ident[c] = i + 1
	}

	// Refine until stable. Each round re-keys every candidate on its own
	// class plus the classes of its relocation targets; a class that splits
	// produces new ids and another round.
	for round := 0; round < len(cands)+1; round++ {
		next := make(map[string]int)
		changed := false
		updated := make(map[*image.Chunk]int, len(cands))

		for _, c := range cands {
			var b strings.Builder
			writeInt(&b, class[c])
			for _, r := range c.Relocs() {
				b.WriteByte('|')
				if r.Sym == nil {
					writeInt(&b, int(r.Disp))
					continue
				}
				t := r.Sym.Chunk()
				if t == nil {
					b.WriteString(r.Sym.Name)
					continue
				}
				if id, ok := class[t]; ok {
					b.WriteByte('c')
					writeInt(&b, id)
				} else {
					// A target outside the candidate set is its
					// own identity: two chunks calling different
					// unfoldable functions are not the same
					// chunk. Identity is the chunk itself and not
					// its name — every common block this linker
					// creates is a distinct chunk called ".bss"
					// from the same object, and telling two of
					// those apart by name is telling every global
					// variable in the program apart by nothing.
					b.WriteByte('k')
					writeInt(&b, ident[t])
				}
				// And where in that chunk, which is the rest of the
				// identity and not a detail. Two accessors that
				// return the addresses of two globals in one .data
				// section are byte-identical, relocate at the same
				// offset with the same type, and name the same
				// chunk — the only thing that distinguishes
				// __p___argc from __p___argv is the eight bytes
				// between the variables they point at. Folding them
				// leaves the CRT calling one function for both and
				// handing main its argv where its argc should be.
				b.WriteByte('+')
				writeInt(&b, int(r.Sym.Offset()))
			}
			key := b.String()
			id, ok := next[key]
			if !ok {
				id = len(next) + 1
				next[key] = id
			}
			updated[c] = id
			if id != class[c] {
				changed = true
			}
		}
		class = updated
		if !changed {
			break
		}
	}

	// Fold. The first candidate in each class is the representative, which
	// keeps the choice deterministic: l.live() preserves creation order, so
	// the winner is the one that entered the link first.
	rep := make(map[int]*image.Chunk)
	for _, c := range cands {
		id := class[c]
		r, ok := rep[id]
		if !ok {
			rep[id] = c
			continue
		}
		if r == c {
			continue
		}
		c.Discarded = true
		l.redirect(c, r)
	}
	return nil
}

// foldable reports whether a chunk may be folded.
//
// Three conditions, and each removes a way for folding to change behaviour.
// The chunk must be a COMDAT, because a non-COMDAT section is not a
// self-contained unit the compiler agreed could be duplicated. It must be
// read-only, since folding two writable objects makes a write through one
// visible through the other. And under ICFSafe its address must not have been
// taken.
//
// The address test is the relocation type: a call and an address reference use
// different relocation types, so a chunk reached only by branches and
// displacements is never named by a pointer and folding it cannot make two
// function pointers compare equal. ICFAll skips the test, which is the
// documented link.exe behaviour and is not safe — it is what breaks C++ code
// relying on function-pointer identity, and CUDA kernel dispatch, which needs
// each stub to have a distinct address.
func (l *Linker) foldable(c *image.Chunk) bool {
	info := l.info[c]
	if info == nil || !info.comdat {
		return false
	}
	if info.sec.Prot().Has(pe.SecWrite) {
		return false
	}
	if l.opt.OptICF == ICFSafe && info.addrTaken {
		return false
	}
	return true
}

// shapeKey is everything about a chunk that does not depend on another
// chunk's identity: its size, its characteristics, its bytes, and the shape of
// its relocation list.
//
// Contents are compared rather than hashed. A hash would be faster and would
// mean two chunks that collide are folded into one, which is a wrong program
// produced silently — the one failure mode this tree will not trade
// performance for.
func (l *Linker) shapeKey(c *image.Chunk) (string, error) {
	info := l.info[c]
	var b strings.Builder
	writeInt(&b, int(c.Size()))
	b.WriteByte('|')
	writeInt(&b, int(info.sec.Characteristics()))
	b.WriteByte('|')
	writeInt(&b, c.Align())
	b.WriteByte('|')

	data, err := c.Bytes()
	if err != nil {
		return "", l.fail(&InputError{Name: c.Input, Err: err})
	}
	b.Write(data)

	for _, r := range c.Relocs() {
		b.WriteByte('|')
		writeInt(&b, int(r.Off))
		b.WriteByte(':')
		writeInt(&b, int(r.Type))
	}
	return b.String(), nil
}

// redirect points every symbol defined in a folded chunk at its
// representative.
//
// The image symbol table replaces on Define, and pointer identity is stable,
// so every relocation already holding one of these symbols follows without
// being rewritten. That is the property that makes folding cheap and the
// reason a relocation carries a *image.Symbol rather than a name.
//
// Every symbol, static ones included. A folded chunk is usually reached by an
// external name, but not always: MSVC puts a function's local read-only data
// in a COMDAT of its own and names it with a static symbol, and two objects
// that agree byte for byte on such a chunk are exactly what folding is for.
// Leaving the statics behind points them at a chunk that is no longer in any
// section, which surfaces as an address asked for before layout assigned one —
// at apply, thousands of chunks away from the fold that caused it.
//
// The name Define is given is the image symbol's own, not the Sym's: a static
// is interned under a key that distinguishes it from every other object's
// symbol of the same name, and Define keyed on the bare name would define a
// global that nothing asked for.
func (l *Linker) redirect(from, to *image.Chunk) {
	for _, tab := range l.tabs {
		for _, s := range tab.allSyms() {
			if s.chunk != from {
				continue
			}
			s.chunk = to
			tab.view.Symbols.Define(s.Out.Name, to, s.off)
		}
	}
	l.deps[to] = append(l.deps[to], l.deps[from]...)
}

func writeInt(b *strings.Builder, v int) {
	if v == 0 {
		b.WriteByte('0')
		return
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var d [20]byte
	i := len(d)
	for v > 0 {
		i--
		d[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		b.WriteByte('-')
	}
	b.Write(d[i:])
}
// groupSize is how many bytes of address space a group's chunks occupy,
// alignment padding included. Zero only when every chunk in it is empty.
func groupSize(g *group) uint32 {
	var n uint32
	for _, c := range g.chunks {
		if a := uint32(c.Align()); a > 1 {
			n = (n + a - 1) &^ (a - 1)
		}
		n += c.Size()
	}
	return n
}
