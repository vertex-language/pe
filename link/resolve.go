package link

import (
	"bytes"
	"strconv"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/ar"
	"github.com/vertex-language/pe/coff"
	"github.com/vertex-language/pe/image"
	"github.com/vertex-language/pe/implib"
)

// Resolution decides, for every name the inputs mention, which definition
// wins. It is where the archive fixpoint runs, where COMDAT elections happen,
// and where an input section becomes a chunk.
//
// The precedence lattice:
//
//	undefined < lazy < import < weak external < common < COMDAT < definition
//
// Each rung beats every rung below it and a tie within a rung is either a
// merge (two commons take the larger) or a diagnostic (two definitions are a
// duplicate). The lattice is a function rather than a pile of comparisons
// because every one of these transitions is silent when it goes the wrong
// way: a lazy that overrides a definition drops the definition, and an import
// that overrides a local one binds a call through a DLL that was never
// supposed to be loaded.

// SymKind is what a name resolved to.
type SymKind uint8

const (
	// SymUndefined is a name referenced with no definition yet. It is the
	// zero value, so a name that has only ever been mentioned reads as
	// undefined rather than as anything else.
	SymUndefined SymKind = iota

	// SymLazy is a name an archive index claims, whose member has not been
	// extracted. Referencing it is what pulls the member in.
	SymLazy

	// SymImport is a name a DLL provides. It defines __imp_$sym always,
	// and $sym as well when the import is code.
	SymImport

	// SymWeakExternal is an unresolved weak external: a name whose
	// alternate is used only if nothing else ever defines it. It is
	// evaluated after every archive has been searched.
	SymWeakExternal

	// SymCommon is a tentative definition — an undefined external whose
	// Value is a size request rather than an address. Two commons merge by
	// taking the larger; a real definition displaces both.
	SymCommon

	// SymComdat is a definition in a COMDAT section, which may still lose
	// an election to another object's copy.
	SymComdat

	// SymDefined is a definition in an ordinary section.
	SymDefined

	// SymAbsolute is a definition whose value is a constant. It ranks with
	// SymDefined: it is a definition, it just has no address.
	SymAbsolute

	// SymFixed is a definition the linker supplies at an address of its
	// own, belonging to no input chunk. __ImageBase is the one. It ranks
	// with SymDefined for the same reason SymAbsolute does.
	SymFixed
)

// rank returns the lattice position. SymAbsolute shares SymDefined's rank
// because the difference between them is what the value means, not how
// strongly it is held.
func (k SymKind) rank() int {
	switch k {
	case SymLazy:
		return 1
	case SymImport:
		return 2
	case SymWeakExternal:
		return 3
	case SymCommon:
		return 4
	case SymComdat:
		return 5
	case SymDefined, SymAbsolute, SymFixed:
		return 6
	}
	return 0
}

func (k SymKind) String() string {
	switch k {
	case SymLazy:
		return "lazy"
	case SymImport:
		return "import"
	case SymWeakExternal:
		return "weak"
	case SymCommon:
		return "common"
	case SymComdat:
		return "comdat"
	case SymDefined:
		return "defined"
	case SymAbsolute:
		return "absolute"
	case SymFixed:
		return "fixed"
	}
	return "undefined"
}

// Sym is one name during resolution.
//
// Out is the image symbol this name will bind to, and it is interned the
// moment the name is first mentioned — before anything knows what will define
// it. That is what lets a relocation hold an *image.Symbol from the start:
// the pointer never changes, only what it points at is filled in. Storing a
// name in the relocation and looking it up at apply would mean a map lookup
// per relocation and a second place for the answer to differ.
type Sym struct {
	Name string
	Kind SymKind

	// Out is this name's entry in the view's output symbol table.
	Out *image.Symbol

	// Obj is the object that supplied the winning definition, for
	// diagnostics and for the duplicate-definition message.
	Obj *Object

	chunk *image.Chunk
	off   uint32

	// value is an absolute symbol's constant, and a common block's
	// requested size.
	value uint64
	align int

	// comdat is the election terms, set only for SymComdat.
	comdat *comdatSym

	// lazy names the archive member that would define this, for SymLazy.
	lazy lazyRef

	// imp names the import that defines this, for SymImport.
	imp *Import

	// refs is the objects that referenced this name without defining it,
	// which is the whole of an undefined symbol's diagnostic.
	refs []string

	// used records that some contributing section relocates against this
	// name. It is the difference between a name a program needs and one
	// an object merely declared: an undefined external that no relocation
	// reaches is a declaration, and declaring something without using it
	// is not an error in any language that reaches a linker.
	//
	// The MSVC CRT relies on this. checkcfg.obj declares
	// _guard_check_icall_$fo$ undefined and never relocates against it —
	// it is a slot for a feature the linker fills in when the build asked
	// for it — so a linker that reported every undefined external could
	// not link the C runtime at all.
	used bool
}

// lazyRef is an archive member an index claims defines a name.
type lazyRef struct {
	lib *Library
	mem *ar.Member
}

// Import is one DLL an image imports from, and the entries it supplies.
//
// The IAT and the name tables are built during synth. Here an import is only
// a record that a name comes from somewhere else, plus enough to build those
// tables later: the DLL, the ordinal or hint, and whether the import is code.
type Import struct {
	DLL     string
	Entries []implib.Entry

	// Thunks tracks which entries were referenced by their unprefixed name
	// and so need a thunk jumping through the slot. Slot liveness and
	// thunk liveness are separate, which is why this is not simply "every
	// code import".
	Thunks map[string]bool
}

// symtab is one view's namespace.
//
// An ARM64X image has two and they are genuinely separate: the same name may
// resolve to a native definition and an EC one, which is exactly what ARM64EC
// mangling exists to express. Sharing one table between the views would make
// the first object to define a name decide for both.
type symtab struct {
	view   *image.View
	byName map[string]*Sym
	order  []*Sym

	// locals holds per-object static symbols, keyed so they cannot collide
	// with a global name. A COFF name can never contain a NUL — the string
	// table's terminator forbids it, and strtab.Builder rejects one — so a
	// NUL in the key is a separator no input can forge.
	//
	// They live in the same table because a relocation against a static
	// symbol needs an *image.Symbol like any other, and this tree writes no
	// symbol table into the image, so the decorated name is never emitted.
	locals map[string]*Sym
}

func newSymtab(v *image.View) *symtab {
	return &symtab{
		view:   v,
		byName: make(map[string]*Sym),
		locals: make(map[string]*Sym),
	}
}

// intern returns the Sym for a name, creating an undefined one if the name is
// new. It never downgrades an existing entry.
func (t *symtab) intern(name string) *Sym {
	if s, ok := t.byName[name]; ok {
		return s
	}
	s := &Sym{Name: name, Out: t.view.Symbols.Undefined(name)}
	t.byName[name] = s
	t.order = append(t.order, s)
	return s
}

// Lookup returns the Sym for a name, or nil.
func (t *symtab) Lookup(name string) *Sym { return t.byName[name] }

// Symbols returns every global name in the order it was first mentioned.
func (t *symtab) Symbols() []*Sym { return t.order }

// allSyms is every name in the table, static ones included.
//
// Symbols is the global namespace and is what almost everything wants. This is
// for the two passes that care about a definition's storage rather than its
// name — folding and any other rewrite of where a chunk's contents ended up —
// because a static symbol names a place in a chunk just as an external one
// does, and a rewrite that skips it leaves it pointing at the old place.
func (t *symtab) allSyms() []*Sym {
	out := make([]*Sym, 0, len(t.order)+len(t.locals))
	out = append(out, t.order...)
	for _, s := range t.locals {
		out = append(out, s)
	}
	return out
}

// local returns the Sym for an object's static symbol.
func (t *symtab) local(o *Object, sym *coff.Symbol) *Sym {
	key := localKey(o, sym)
	if s, ok := t.locals[key]; ok {
		return s
	}
	s := &Sym{Name: sym.Name, Out: t.view.Symbols.Undefined(key)}
	t.locals[key] = s
	return s
}

// localKey identifies one static symbol, by its slot in its own object's
// symbol table rather than by its name.
//
// A static name is not unique within an object. MSVC numbers its internal
// labels per function and starts over at each one, so a single CRT object
// holds dozens of symbols called $LN4, one per COMDAT function and each in its
// own section. Keying on the name collapses them into one, and the survivor is
// whichever happened to be defined last — after which every .pdata record in
// the object relocates against that one function, and the records belonging to
// functions that lost their COMDAT election ask for the address of a section
// that is not in the image.
//
// The slot is unique by construction and is what a relocation names anyway, so
// nothing is lost by keying on it; the name stays on the Sym, where the
// diagnostics read it.
func localKey(o *Object, sym *coff.Symbol) string {
	return o.Name + "\x00#" + strconv.Itoa(sym.Slot)
}

// sectionSource adapts a coff.Section to image.ChunkSource.
//
// Bytes runs once, after Freeze, so nothing is cached: the section's data is
// read from the input's extent at the moment the output buffer wants it,
// which is what keeps a forty-megabyte object from being resident for the
// whole link.
//
// A BSS section does not use this. It becomes an image.Zeroed instead, so
// that the "does this occupy file space" question is answered by the type
// rather than by a nil check on the bytes.
type sectionSource struct {
	sec *coff.Section
}

func (s sectionSource) Size() uint32 { return s.sec.Size }
func (s sectionSource) Align() int   { return s.sec.Align() }

func (s sectionSource) Bytes() ([]byte, error) {
	b, err := s.sec.Data()
	if err != nil {
		return nil, err
	}
	if uint32(len(b)) != s.sec.Size {
		// A section header whose SizeOfRawData disagrees with the bytes
		// behind it. The chunk was sized from the header, so returning
		// the short read would leave the tail of the chunk holding
		// whatever the output buffer was initialized with.
		return nil, coff.ErrCorrupt
	}
	return b, nil
}

// resolve runs the resolution phase.
//
// The loop is the archive fixpoint. Referencing an undefined name may pull a
// member out of an archive, which adds an object, which contributes symbols
// that may reference more names. It terminates because extraction is
// monotonic — a member is fetched once and never returned — rather than
// because of any bound on iterations.
//
// Archives are seeded first so that a reference from anywhere finds any
// archive, which is what makes re-searching work and what makes command-line
// order stop deciding the answer. This is lld's model rather than link.exe's,
// and they differ in one case: link.exe searches the library a member came
// from before any other, so when two libraries define the same name and the
// reference arose inside one of them, link.exe prefers that one and this
// prefers whichever was seeded first. The rotation is recorded in Library's
// index and origin for the day it matters.
func (l *Linker) resolve() error {
	l.tabs = make([]*symtab, len(l.img.Views()))
	for i, v := range l.img.Views() {
		l.tabs[i] = newSymtab(v)
	}

	l.defineImageBase()

	for _, lib := range l.libs {
		if err := l.seedLazy(lib); err != nil {
			return err
		}
	}

	// Objects grow as members are fetched, so the slice is read by index
	// and its length re-checked rather than ranged over.
	for i := 0; i < len(l.objects); i++ {
		if err := l.addObject(l.objects[i]); err != nil {
			return err
		}
	}

	// Which CRT startup this image wants is decided by what the command
	// line's objects define, so it is decided here — after they are in the
	// table, and before addRoots fetches an entry point on a guess.
	l.inferEntry()

	if err := l.addRoots(); err != nil {
		return err
	}
	for i := 0; i < len(l.objects); i++ {
		if l.objects[i].resolved {
			continue
		}
		if err := l.addObject(l.objects[i]); err != nil {
			return err
		}
	}

	// Weak externals and alternate names go last, after every archive has
	// been searched: an alternate taken early makes command-line order
	// decide an answer the format says nothing else should have decided.
	if err := l.resolveWeak(); err != nil {
		return err
	}
	if err := l.applyAssociative(); err != nil {
		return err
	}
	return l.convertRelocs()
}

// defineImageBase supplies __ImageBase, the address of the image's first
// byte.
//
// Every PE linker defines it and the Microsoft CRT reaches for it constantly:
// `&__ImageBase` is the module's HINSTANCE without a call to the loader, and
// it is what an image-relative table is relative to. It names the PE headers,
// which are in no section and therefore in no chunk, so it is a SymFixed at
// RVA zero rather than a definition inside anything.
//
// Before the objects, so that an object defining it as well is a duplicate
// rather than a silent override — the two would disagree about where the image
// starts, and the linker is the one that knows.
func (l *Linker) defineImageBase() {
	for _, tab := range l.tabs {
		s := tab.intern("__ImageBase")
		s.Kind = SymFixed
		tab.view.Symbols.Fixed("__ImageBase", 0)
	}
}

// tabFor returns the symbol table an object's machine routes to.
//
// Routing is by machine and there is no per-input override, because an
// object's machine already says which view it belongs to and accepting a
// second answer only creates a way for the two to disagree. This is where the
// machine check deferred from ingest happens, and it names the input, which
// the machine alone cannot.
func (l *Linker) tabFor(o *Object) (*symtab, error) {
	if o.Machine == pe.MachineUnknown {
		// A machine-agnostic object belongs to every machine, so it
		// belongs to the primary view. It has no code to place in the
		// wrong one: an object that named a machine would have been
		// routed by it, and one that names none carries only the kind
		// of content — debug records, directives — that is the same
		// whichever view it lands in.
		return l.tabs[0], nil
	}
	v, ok := l.img.ViewFor(o.Machine)
	if !ok {
		return nil, &ViewError{
			Input:   o.Name,
			Machine: o.Machine.String(),
			Target:  l.opt.Target.String(),
		}
	}
	for _, t := range l.tabs {
		if t.view == v {
			return t, nil
		}
	}
	return nil, &ViewError{Input: o.Name, Machine: o.Machine.String(),
		Target: l.opt.Target.String()}
}

// seedLazy records every name an archive's index claims, without reading a
// single member.
//
// A name already known is not overwritten: a lazy loses to everything except
// an undefined reference, and the first archive to claim a name is the one
// that will supply it. That ordering is the whole of this linker's library
// precedence, and it is command-line order because the libraries were opened
// in command-line order.
func (l *Linker) seedLazy(lib *Library) error {
	if lib.File.Index == nil {
		// An archive with no linker member cannot be searched by symbol.
		// It is not usable as a library, and quietly scanning its
		// members instead would hide that from whoever has to ship it.
		return l.fail(&InputError{Name: lib.Name, Err: ar.ErrNoIndex})
	}
	for _, tab := range l.tabs {
		for i := range lib.File.Index.Entries {
			e := &lib.File.Index.Entries[i]
			s := tab.intern(e.Name)
			if s.Kind != SymUndefined {
				continue
			}
			m := memberAt(lib, e.Offset)
			if m == nil {
				return l.fail(&InputError{Name: lib.Name, Err: ar.ErrBadIndex})
			}
			s.Kind, s.lazy = SymLazy, lazyRef{lib: lib, mem: m}
		}
	}
	return nil
}

func memberAt(lib *Library, off int64) *ar.Member {
	for _, m := range lib.File.Members {
		if m.Offset == off {
			return m
		}
	}
	return nil
}

// addObject brings one object's chunks and symbols into the link.
//
// Chunks come first because a symbol is defined as an offset within one, and
// the COMDAT election has to run before any symbol of a losing section is
// defined — a loser's symbols must never reach the table, or the election has
// merely chosen which copy of the bytes to keep while the names still
// collide.
func (l *Linker) addObject(o *Object) error {
	if o.resolved {
		return nil
	}
	o.resolved = true

	tab, err := l.tabFor(o)
	if err != nil {
		return l.fail(err)
	}
	o.tab = tab

	if err := l.makeChunks(o); err != nil {
		return err
	}
	if err := l.elect(o); err != nil {
		return err
	}
	return l.addSymbols(o)
}

// makeChunks turns every contributing section into a chunk.
//
// Four kinds of section do not contribute. LNK_INFO is a comment or a
// directive — .drectve has already been read and consumed. LNK_REMOVE says
// outright that the section does not reach the image. And .debug$S and
// .debug$T round-trip as opaque bytes in coff and are dropped here, because
// everything a debugger needs is in a PDB this tree does not write.
//
// The fourth is a section that is neither code nor data and asks for no
// memory protection: it holds no bytes the image could carry and names no
// pages the loader could map. The MSVC CRT is full of them —
// _guard_check_icall_$fo_rvas$ and its neighbours are LNK_COMDAT and nothing
// else — and they are link-time metadata for a feature this tree does not
// implement, so the answer is to drop them rather than to invent an output
// section whose name does not fit the eight-byte field.
func (l *Linker) makeChunks(o *Object) error {
	o.chunks = make([]*image.Chunk, len(o.File.Sections))
	for i, sec := range o.File.Sections {
		if !contributes(sec) {
			continue
		}
		var src image.ChunkSource
		if sec.BSS() {
			src = &image.Zeroed{Length: sec.Size, Alignment: sec.Align()}
		} else {
			src = sectionSource{sec: sec}
		}
		c := image.NewChunk(sec.Name, o.Name, src)
		// Reachable is deliberately not set. It is sweep's to set, and a
		// chunk that is live before sweep has run is one /OPT:REF can
		// never remove.
		o.chunks[i] = c
		l.chunks = append(l.chunks, c)
	}
	return nil
}

func contributes(sec *coff.Section) bool {
	k := sec.Kind()
	if k.Has(pe.SecLnkInfo) || k.Has(pe.SecLnkRemove) {
		return false
	}
	if len(sec.Name) >= 7 && sec.Name[:7] == ".debug$" {
		return false
	}
	if !k.Has(pe.SecCode) && !k.Has(pe.SecInitData) && !k.Has(pe.SecUninitData) &&
		sec.Prot()&(pe.SecExecute|pe.SecRead|pe.SecWrite) == 0 {
		return false
	}
	return true
}

// addSymbols brings one object's symbols into its view's table.
func (l *Linker) addSymbols(o *Object) error {
	syms, err := o.File.Symbols()
	if err != nil {
		return l.fail(&InputError{Name: o.Name, Err: err})
	}

	for _, sym := range syms {
		switch {
		case sym.Class == pe.ClassStatic || sym.Class == pe.ClassLabel:
			l.defineLocal(o, sym)
			continue
		case sym.Class == pe.ClassFile ||
			sym.Class == pe.ClassFunction ||
			sym.Class == pe.ClassEndOfFunction ||
			sym.Class == pe.ClassBlock:
			// Debug bookkeeping with no linkage. .file and the
			// .bf/.ef pairs are these.
			continue
		case sym.Class == pe.ClassSection:
			// A section symbol names a $-group that lives in another
			// object — the import descriptor's .idata$4 and .idata$5
			// references are these. It is a reference, not a
			// definition.
			l.reference(o, sym.Name)
			continue
		case sym.Class == pe.ClassWeakExternal:
			if err := l.addWeak(o, sym); err != nil {
				return err
			}
			continue
		case sym.Class != pe.ClassExternal:
			continue
		}

		size, isCommon := sym.Common()

		switch {
		case sym.Absolute():
			if err := l.define(o, sym.Name, SymAbsolute, nil, 0, uint64(sym.Value)); err != nil {
				return err
			}
		case isCommon:
			if err := l.addCommon(o, sym.Name, size); err != nil {
				return err
			}
		case sym.Undefined():
			if err := l.reference(o, sym.Name); err != nil {
				return err
			}
		case sym.Defined():
			c := o.chunks[sym.Section-1]
			if c == nil || c.Discarded {
				// The section does not contribute, or it lost an
				// election. Either way the name is not defined
				// here — and defining it would resurrect exactly
				// the duplicate the election exists to remove.
				continue
			}
			kind := SymDefined
			if o.File.Sections[sym.Section-1].IsComdat() {
				kind = SymComdat
			}
			if err := l.define(o, sym.Name, kind, c, sym.Value, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

// defineLocal binds a static symbol, which never enters the global namespace.
func (l *Linker) defineLocal(o *Object, sym *coff.Symbol) {
	s := o.tab.local(o, sym)
	if !sym.Defined() {
		return
	}
	c := o.chunks[sym.Section-1]
	if c == nil {
		return
	}
	s.Kind, s.Obj, s.chunk, s.off = SymDefined, o, c, sym.Value
	o.tab.view.Symbols.Define(localKey(o, sym), c, sym.Value)
}

// define records a definition, applying the lattice.
func (l *Linker) define(o *Object, name string, kind SymKind, c *image.Chunk, off uint32, value uint64) error {
	s := o.tab.intern(name)

	if kind.rank() < s.Kind.rank() {
		// A weaker definition arriving after a stronger one. A common
		// under a definition is the ordinary case and is silent; the
		// others cannot happen from a well-formed input and are equally
		// silent, because the stronger answer is already correct.
		return nil
	}
	if s.Kind.rank() == kind.rank() && s.Kind != SymUndefined {
		if err := l.duplicate(o, s, kind, c); err != nil {
			return l.fail(err)
		}
		return nil
	}

	s.Kind, s.Obj, s.chunk, s.off, s.value = kind, o, c, off, value
	switch kind {
	case SymAbsolute:
		o.tab.view.Symbols.Absolute(name, value)
	default:
		o.tab.view.Symbols.Define(name, c, off)
	}
	return nil
}

// duplicate decides what two same-rank definitions of a name mean.
//
// Two COMDAT definitions are not a duplicate: the election in comdat.go has
// already chosen, and a section that lost never reaches here. Two ordinary
// definitions are, and so is a COMDAT against an ordinary one — a section
// flagged COMDAT and one that is not are not interchangeable, whatever their
// contents.
func (l *Linker) duplicate(o *Object, s *Sym, kind SymKind, c *image.Chunk) error {
	if kind == SymComdat && s.Kind == SymComdat {
		return nil
	}
	first := "<unknown>"
	if s.Obj != nil {
		first = s.Obj.Name
	}
	return &DuplicateError{Name: s.Name, First: first, Second: o.Name}
}

// addCommon records a tentative definition.
//
// A common is an undefined external whose Value is a size to allocate rather
// than an address — what an uninitialized file-scope C variable compiles to.
// Two commons merge by taking the larger, which is the rule everywhere
// commons are merged and the reason this is not simply a definition.
//
// The chunk is created here rather than at merge because /OPT:REF should be
// able to drop a common nobody references, and it can only do that if the
// common is a chunk like any other.
func (l *Linker) addCommon(o *Object, name string, size uint32) error {
	s := o.tab.intern(name)
	if s.Kind.rank() > SymCommon.rank() {
		return nil // a real definition already won
	}
	if s.Kind == SymCommon && uint64(size) <= s.value {
		return nil
	}

	align := commonAlign(size)
	if a, ok := l.opt.AlignComm[name]; ok && a > align {
		align = a
	}
	c := image.NewChunk(".bss", o.Name, &image.Zeroed{Length: size, Alignment: align})
	l.chunks = append(l.chunks, c)

	s.Kind, s.Obj, s.chunk, s.off = SymCommon, o, c, 0
	s.value, s.align = uint64(size), align
	o.tab.view.Symbols.Define(name, c, 0)
	return nil
}

// commonAlign is the natural alignment for a common block of a given size:
// the largest power of two not exceeding it, capped at the pointer size.
//
// The specification says nothing about this — a common carries a size and
// nothing else — so the rule is a convention, and /ALIGNCOMM exists precisely
// because the convention is sometimes not enough.
func commonAlign(size uint32) int {
	switch {
	case size >= 16:
		return 16
	case size >= 8:
		return 8
	case size >= 4:
		return 4
	case size >= 2:
		return 2
	}
	return 1
}

// reference records an undefined reference, fetching an archive member if one
// claims the name.
//
// This is the fixpoint's edge. Everything else in resolution is bookkeeping;
// this is the step that can make the input set grow.
func (l *Linker) reference(o *Object, name string) error {
	s := o.tab.intern(name)
	if s.Obj != o {
		s.refs = append(s.refs, o.Name)
	}
	if s.Kind != SymLazy {
		return nil
	}
	return l.fetchLazy(o.tab, s)
}

// fetchLazy extracts the member a lazy symbol names.
//
// The symbol is taken out of the lazy state before the member is read, so a
// member that references the name that pulled it in — which a thunk in an
// import library does — does not try to fetch itself.
func (l *Linker) fetchLazy(tab *symtab, s *Sym) error {
	ref := s.lazy
	s.Kind, s.lazy = SymUndefined, lazyRef{}

	data, err := ref.mem.Data()
	if err != nil {
		return l.fail(&InputError{Name: ref.lib.Name, Err: err})
	}
	if pe.KindOf(head(data)) == pe.KindShortImport {
		return l.addImport(tab, ref.lib, data)
	}
	if _, err := l.Fetch(ref.lib, ref.mem); err != nil {
		return l.fail(err)
	}
	return nil
}

func head(data []byte) []byte {
	if len(data) > pe.KindPrefix {
		return data[:pe.KindPrefix]
	}
	return data
}

// addImport defines the symbols a short-import member supplies.
//
// The asymmetry between code and data is the whole reason implib.Kind exists.
// A data import defines __imp_$sym and nothing else: the compiler must have
// been told with __declspec(dllimport) to go through the slot, and a
// reference to the unprefixed name is an error rather than something the
// linker can paper over. A code import also defines $sym, as a thunk jumping
// through the slot — the PE equivalent of a PLT entry — so that code compiled
// without dllimport still links.
//
// Note that some published summaries say a data import aliases $sym to
// __imp_$sym. It does not; link.exe reports an error for the unprefixed data
// reference, and the MinGW runtime pseudo-relocation machinery exists because
// that error is inconvenient.
func (l *Linker) addImport(tab *symtab, lib *Library, data []byte) error {
	e, err := decodeImport(data)
	if err != nil {
		return l.fail(&InputError{Name: lib.Name, Err: err})
	}

	imp := l.imports[e.DLL]
	if imp == nil {
		imp = &Import{DLL: e.DLL, Thunks: make(map[string]bool)}
		l.imports[e.DLL] = imp
		l.importOrder = append(l.importOrder, imp)
	}
	imp.Entries = append(imp.Entries, e)

	slot := tab.intern("__imp_" + e.Symbol)
	if slot.Kind.rank() <= SymImport.rank() {
		slot.Kind, slot.imp = SymImport, imp
	}
	if e.Kind != implib.KindCode {
		return nil
	}
	// The unprefixed name is defined too, but the thunk behind it is only
	// built if something actually references it. Recording the definition
	// and the liveness separately is what keeps a program that uses only
	// dllimport from carrying a thunk per import.
	thunk := tab.intern(e.Symbol)
	if thunk.Kind.rank() <= SymImport.rank() {
		thunk.Kind, thunk.imp = SymImport, imp
	}
	return nil
}

// decodeImport reads one short-import member. It is implib's format and
// implib's meaning; this is the one place link needs a single entry rather
// than a whole library, which is why it goes through Read on one member
// rather than through implib.Lib.
func decodeImport(data []byte) (implib.Entry, error) {
	lib, err := implib.Read(wrapMember(data))
	if err != nil {
		return implib.Entry{}, err
	}
	if len(lib.Entries) != 1 {
		return implib.Entry{}, implib.ErrBadMember
	}
	return lib.Entries[0], nil
}

// wrapMember builds a minimal one-member archive around a single member's
// raw bytes.
//
// implib.Read takes a whole import library, not one member: it goes through
// ar.NewFile to walk the archive's objects, which is what lets it also
// tolerate an import descriptor split across several members. A caller here
// already has exactly one member — extracted from the real archive by
// resolve's own fixpoint — so the only way to hand it to Read is to give it
// back the archive shell Read expects around it.
func wrapMember(data []byte) []byte {
	var buf bytes.Buffer
	w := ar.NewWriter(&buf, ar.Options{Deterministic: true})
	w.Add(ar.Input{Name: "member", Data: data})
	if err := w.Close(); err != nil {
		// Add and Close only fail on a write error to buf, which cannot
		// happen against a bytes.Buffer. A failure here would mean this
		// helper is unusable, not that the caller's data is bad.
		panic("link: wrapMember: " + err.Error())
	}
	return buf.Bytes()
}

// addRoots references the names the link must resolve whatever else happens:
// the entry point, every /INCLUDE, and both halves of every /ALTERNATENAME.
//
// They are references rather than definitions, so each one can pull an archive
// member in — which is the point. A program whose entry point lives in the CRT
// has nothing else that mentions it.
func (l *Linker) addRoots() error {
	tab := l.tabs[0]
	root := func(name string) error {
		if name == "" {
			return nil
		}
		s := tab.intern(name)
		if s.Kind != SymLazy {
			return nil
		}
		return l.fetchLazy(tab, s)
	}

	if l.opt.Kind != OutputDLL || l.opt.EntryName() != "" {
		if err := root(l.opt.EntryName()); err != nil {
			return err
		}
	}
	for _, name := range l.opt.Includes {
		if err := root(name); err != nil {
			return err
		}
	}
	for _, e := range l.opt.Exports {
		if err := root(e.Name); err != nil {
			return err
		}
	}
	return nil
}

// convertRelocs turns every input relocation into an output one.
//
// The symbol index becomes an *image.Symbol, the offset is already within the
// chunk because a chunk is a whole input section, and the order is preserved
// exactly — a PAIR is associated with the entry before it by adjacency and
// nothing else, so sorting these for any reason, including determinism,
// destroys the only thing that pairs them.
//
// A PAIR's index field is not an index. Resolving it would look up an
// arbitrary symbol and relocate against whatever it happened to name, which
// is why the type is asked first and the field is carried as a displacement
// when the answer is yes.
func (l *Linker) convertRelocs() error {
	for _, o := range l.objects {
		syms, err := o.File.Symbols()
		if err != nil {
			return l.fail(&InputError{Name: o.Name, Err: err})
		}
		slots := make(map[uint32]*coff.Symbol, len(syms))
		for _, s := range syms {
			slots[uint32(s.Slot)] = s
		}

		for i, sec := range o.File.Sections {
			c := o.chunks[i]
			if c == nil || c.Discarded {
				continue
			}
			rs, err := sec.Relocs()
			if err != nil {
				return l.fail(&InputError{Name: o.Name, Err: err})
			}
			out := make([]image.Reloc, 0, len(rs))
			for _, r := range rs {
				if r.IsPair(o.Machine) {
					out = append(out, image.Reloc{
						Off: r.Address, Type: r.Type, Disp: r.SymIndex,
					})
					continue
				}
				sym, ok := slots[r.SymIndex]
				if !ok {
					// The index named a slot holding an
					// auxiliary record, or one past the end.
					return l.fail(&InputError{Name: o.Name, Err: coff.ErrCorrupt})
				}
				out = append(out, image.Reloc{
					Off:  r.Address,
					Type: r.Type,
					Sym:  l.outSym(o, sym),
				})
			}
			c.SetRelocs(out)
		}
	}
	return nil
}

// outSym returns the image symbol a relocation's target resolves to.
func (l *Linker) outSym(o *Object, sym *coff.Symbol) *image.Symbol {
	if sym.Class == pe.ClassStatic || sym.Class == pe.ClassLabel {
		s := o.tab.local(o, sym)
		s.used = true
		return s.Out
	}
	s := o.tab.intern(sym.Name)
	s.used = true
	return s.Out
}

// check reports every name that reached the end of resolution with no
// definition.
//
// It collects them all rather than failing on the first. A link with one
// undefined symbol usually has thirty, they usually share a cause, and
// reporting them one build at a time is the slowest possible way to find it.
//
// The __imp_ hint is the one that earns its place. A reference to foo that
// would have resolved as __imp_foo means the declaration was missing
// __declspec(dllimport), which is the most common undefined symbol in a
// Windows link and the one whose cause is least visible in the name.
func (l *Linker) check() error {
	var undef []*UndefinedError
	for _, tab := range l.tabs {
		for _, s := range tab.order {
			switch s.Kind {
			case SymUndefined, SymLazy:
			default:
				continue
			}
			if len(s.refs) == 0 || !s.used {
				// Mentioned by an archive index, by a root that
				// nothing needed, or by a declaration no
				// relocation ever reached. Not an error: see
				// Sym.used.
				continue
			}
			e := &UndefinedError{Name: s.Name, Refs: s.refs}
			if imp := tab.Lookup("__imp_" + s.Name); imp != nil && imp.Kind == SymImport {
				e.Imp = true
			}
			undef = append(undef, e)
		}
	}
	if len(undef) == 0 {
		return nil
	}
	return l.fail(undef[0])
}

// inferEntry picks the CRT startup matching the entry point the program
// itself defines, and the subsystem that goes with it.
//
// The CRT supplies four, and which one an image wants is not on the command
// line: the program says it by which function it wrote. link.exe reads a
// program defining WinMain as a GUI program and links WinMainCRTStartup
// into it, one defining wmain as a console program wanting
// wmainCRTStartup, and so on. A linker that always reaches for
// mainCRTStartup tells a Windows program it has no main — which is a symbol
// that program never mentioned and cannot be expected to recognize.
//
// It runs after the command line's objects are in the table and before
// addRoots, which is the moment both facts are available: what the program
// defines, and nothing yet fetched on a guess about it.
//
// An explicit /ENTRY or /SUBSYSTEM wins, since both say the caller has
// already decided. So does any output but an executable — a DLL's entry is
// DllMainCRTStartup whatever else it defines — and so does MinGW, whose
// startup names are its own.
func (l *Linker) inferEntry() {
	if l.opt.Entry != "" || l.opt.Subsystem != pe.SubsystemUnknown {
		return
	}
	if l.opt.Kind != OutputEXE || l.opt.Target.ABI != pe.ABIMSVC {
		return
	}
	tab := l.tabs[0]
	for _, e := range []struct {
		name, start string
		sub         pe.Subsystem
	}{
		{"main", "mainCRTStartup", pe.SubsystemConsole},
		{"wmain", "wmainCRTStartup", pe.SubsystemConsole},
		{"WinMain", "WinMainCRTStartup", pe.SubsystemGUI},
		{"wWinMain", "wWinMainCRTStartup", pe.SubsystemGUI},
	} {
		if s := tab.Lookup(e.name); s != nil && (s.Kind == SymDefined || s.Kind == SymComdat) {
			l.opt.Entry = e.start
			l.opt.Subsystem = e.sub
			return
		}
	}
}
