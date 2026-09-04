package coff

import (
	"io"
	"strings"

	"github.com/vertex-language/pe"
)

// Writer builds a relocatable COFF object.
//
// It is a separate type family from File on purpose: a decoder that can also
// be mutated is a decoder whose invariants hold only by convention. Nothing
// here reads an object, and nothing in File writes one.
//
// Errors latch, as everywhere else in this tree. The first failure is kept and
// every later call is a no-op, so a build sequence is a straight run of calls
// with one check at Close. The alternative — a returned error on Section,
// Symbol, Reloc, and Directive alike — is four checks nobody writes.
type Writer struct {
	w   io.Writer
	opt Options

	secs []*SectionBuilder
	syms []*SymbolRef

	directives []Directive
	file       string
	hasFile    bool

	err    error
	closed bool
}

// Options configures a Writer.
//
// Target at its zero value is an error, not a default. An object silently
// written for x86 because nobody said otherwise is a link failure three steps
// downstream with nothing pointing back here.
type Options struct {
	// Target decides the machine written to the header. It is the target's
	// Machine, not its ImageMachine: ARM64EC and ARM64X are object-only
	// machine types and an object is exactly where they belong.
	Target pe.Target

	// BigObj decides the header family.
	BigObj BigObjMode

	// TimeDateStamp is written verbatim. Zero is the deterministic choice
	// and this tree's default; link.exe's /Brepro writes 0xffffffff.
	TimeDateStamp uint32

	// Characteristics is the COFF file header's flag field. Most of its
	// bits are image-only and meaningless here. A non-zero value forbids
	// promotion to bigobj, whose header has no such field.
	Characteristics pe.FileChar
}

// SectionHeader describes a section to create. Align is in bytes, never the
// nibble; the log2-plus-one form exists only inside pe.EncodeAlign.
type SectionHeader struct {
	Name  string
	Kind  pe.SecKind
	Prot  pe.SecProt
	Align int
}

// SectionBuilder is a section under construction.
//
// It is the write-side counterpart of Section, and the two are deliberately
// distinct types: a Section knows where its bytes are in a file, a
// SectionBuilder owns bytes that are not in a file yet.
type SectionBuilder struct {
	// Name is the full name including any $ suffix. The suffix is written
	// out unchanged — it is what decides ordering at merge, and the
	// .CRT$XCA through .CRT$XCZ bracketing depends on it surviving.
	Name string

	w     *Writer
	index int // zero-based; the section *number* is index+1

	kind  pe.SecKind
	prot  pe.SecProt
	align int

	data   []byte
	bss    uint32
	relocs []relocEntry

	comdat    bool
	selection pe.Selection
	leader    *SymbolRef
	assoc     *SectionBuilder

	// def is the section-definition symbol, created with the section so it
	// can be given the first slot bearing this section's number.
	def *SymbolRef
}

// SymbolDef describes a symbol to define.
type SymbolDef struct {
	Name string

	// Section is the defining section, or nil for a symbol that defines no
	// storage here — an undefined external, an absolute, or a debug symbol.
	Section *SectionBuilder

	// Value is the offset within Section for a defined symbol, the constant
	// for an absolute one, and the requested size for a common block.
	Value uint32

	Class pe.StorageClass
	Type  pe.SymType

	// Absolute makes the symbol IMAGE_SYM_ABSOLUTE: Value is a constant
	// rather than an address. Section must be nil.
	Absolute bool

	// Debug makes the symbol IMAGE_SYM_DEBUG, which corresponds to no
	// section. Section must be nil.
	Debug bool
}

// SymbolRef is a handle to a symbol in a Writer's table.
//
// It is opaque because the thing it stands for is a physical slot, and the
// slot is not known until Close has ordered the table. Relocations and
// associative COMDATs reference slots, so handing out an integer before that
// ordering would hand out a number that is about to change.
type SymbolRef struct {
	w   *Writer
	def SymbolDef

	sect pe.SectionNumber
	aux  []auxRecord

	// slot is assigned by Close and is meaningless before it.
	slot int
	// nslots is 1 plus the auxiliary slots this symbol occupies.
	nslots int

	// isSectionDef marks the automatic definition record, which must lead
	// the symbols carrying its section's number.
	isSectionDef bool
	emitted      bool
}

// auxRecord is one auxiliary record attached to a symbol, in the writer's
// own terms. It becomes a format type at the wire edge.
type auxRecord struct {
	kind pe.AuxKind

	weakTag  *SymbolRef
	weakKind pe.WeakKind

	fileName string

	sectionDef *SectionBuilder
}

// NewWriter returns a Writer that will emit to w on Close.
//
// Nothing is written until Close. The object's header carries the symbol table
// pointer and the section table carries every file offset, so the layout has
// to be complete before the first byte can be correct.
func NewWriter(w io.Writer, opt Options) *Writer {
	ww := &Writer{w: w, opt: opt}
	if err := opt.Target.Validate(); err != nil {
		ww.Fail(err)
	}
	return ww
}

// Err returns the first error latched, or nil.
func (w *Writer) Err() error { return w.err }

// Fail latches err if no error is latched yet.
func (w *Writer) Fail(err error) {
	if w.err == nil && err != nil {
		w.err = err
	}
}

// fail latches and reports whether the Writer is now unusable.
func (w *Writer) fail(err error) bool {
	w.Fail(err)
	return w.err != nil
}

// checkSection validates that s belongs to this Writer and the Writer is open.
func (w *Writer) checkSection(s *SectionBuilder) error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return ErrClosed
	}
	if s == nil || s.w != w {
		return ErrBadRelocation
	}
	return nil
}

// Section creates a section and returns a handle for writing to it.
//
// Sections are written in creation order, and the section number a symbol
// references is that order plus one. There is no lookup by name because /Gy
// makes .text$mn appear hundreds of times in one object and a by-name accessor
// would return an arbitrary one of them.
func (w *Writer) Section(h SectionHeader) *SectionBuilder {
	if w.err != nil || w.closed {
		w.Fail(ErrClosed)
		return &SectionBuilder{w: w, index: -1}
	}
	if h.Align == 0 {
		h.Align = pe.DefaultAlign
	}
	if _, err := pe.EncodeAlign(h.Align); err != nil {
		w.Fail(err)
		return &SectionBuilder{w: w, index: -1}
	}
	s := &SectionBuilder{
		Name:  h.Name,
		w:     w,
		index: len(w.secs),
		kind:  h.Kind,
		prot:  h.Prot,
		align: h.Align,
	}
	w.secs = append(w.secs, s)

	// The definition record is created with the section rather than at
	// Close, so that its slot is assignable before any user symbol that
	// names this section — which is the ordering COMDAT election requires.
	s.def = &SymbolRef{
		w:            w,
		def:          SymbolDef{Name: h.Name, Class: pe.ClassStatic, Type: pe.SymNull},
		sect:         pe.SectionNumber(s.index + 1),
		isSectionDef: true,
		aux:          []auxRecord{{kind: pe.AuxSectionDef, sectionDef: s}},
	}
	return s
}

// Number returns the one-based section number, as symbols reference it.
func (s *SectionBuilder) Number() int32 { return int32(s.index) + 1 }

// Write appends bytes to the section. It satisfies io.Writer.
//
// Writing to an uninitialized-data section is an error rather than a silent
// promotion: a .bss with contents is a section whose SizeOfRawData and
// PointerToRawData disagree about whether it exists.
func (s *SectionBuilder) Write(p []byte) (int, error) {
	if s.w.err != nil {
		return 0, s.w.err
	}
	if s.w.closed {
		s.w.Fail(ErrClosed)
		return 0, s.w.err
	}
	if s.kind.Has(pe.SecUninitData) {
		s.w.Fail(ErrBadSymbol)
		return 0, s.w.err
	}
	s.data = append(s.data, p...)
	return len(p), nil
}

// Reserve sets the size of an uninitialized-data section.
//
// A BSS section has a size and no bytes: SizeOfRawData states the size and
// PointerToRawData is zero. This is the only way to give one a size, because
// Write refuses to put contents in a section that by definition has none.
func (s *SectionBuilder) Reserve(n uint32) {
	if s.w.err != nil || s.w.closed {
		s.w.Fail(ErrClosed)
		return
	}
	if !s.kind.Has(pe.SecUninitData) {
		s.w.Fail(ErrBadSymbol)
		return
	}
	s.bss = n
}

// Size returns the section's size in bytes.
func (s *SectionBuilder) Size() uint32 {
	if s.kind.Has(pe.SecUninitData) {
		return s.bss
	}
	return uint32(len(s.data))
}

// Symbol defines a symbol and returns a handle to it.
//
// Storage class must be set explicitly. IMAGE_SYM_CLASS_NULL is a defined
// value, so a zero Class cannot be distinguished from an unset one, and this
// tree refuses rather than guessing which was meant.
func (w *Writer) Symbol(d SymbolDef) *SymbolRef {
	if w.err != nil || w.closed {
		w.Fail(ErrClosed)
		return &SymbolRef{w: w}
	}
	s := &SymbolRef{w: w, def: d}
	if err := w.classify(s); err != nil {
		w.Fail(err)
		return s
	}
	w.syms = append(w.syms, s)
	return s
}

// classify resolves a definition's section number and rejects the
// combinations that cannot mean anything.
func (w *Writer) classify(s *SymbolRef) error {
	d := s.def
	if d.Class == pe.ClassNull {
		return ErrBadSymbol
	}
	if d.Absolute && d.Debug {
		return ErrBadSymbol
	}
	switch {
	case d.Section != nil:
		if d.Absolute || d.Debug {
			return ErrBadSymbol
		}
		if d.Section.w != w || d.Section.index < 0 {
			return ErrBadSymbol
		}
		s.sect = pe.SectionNumber(d.Section.index + 1)
	case d.Absolute:
		s.sect = pe.SectionAbsolute
	case d.Debug:
		s.sect = pe.SectionDebug
	default:
		// Undefined. A non-zero Value here is a common-block request:
		// the size to allocate, not an address. That is legal and is
		// what an uninitialized file-scope C variable compiles to.
		s.sect = pe.SectionUndefined
	}
	return nil
}

// WeakSymbol defines a weak external and the alternate it falls back to.
//
// Kind distinguishes the three search behaviours from the ARM64EC
// anti-dependency alias, which shares the WEAK_EXTERNAL storage class and
// means something different in kind rather than in degree. Collapsing them to
// a bool is how an ARM64EC alias becomes an ordinary weak reference.
func (w *Writer) WeakSymbol(name string, alternate *SymbolRef, kind pe.WeakKind) *SymbolRef {
	if w.err != nil || w.closed {
		w.Fail(ErrClosed)
		return &SymbolRef{w: w}
	}
	if alternate == nil || alternate.w != w {
		w.Fail(ErrBadSymbol)
		return &SymbolRef{w: w}
	}
	s := &SymbolRef{
		w:    w,
		def:  SymbolDef{Name: name, Class: pe.ClassWeakExternal},
		sect: pe.SectionUndefined,
		aux:  []auxRecord{{kind: pe.AuxWeakExternal, weakTag: alternate, weakKind: kind}},
	}
	w.syms = append(w.syms, s)
	return s
}

// FileSymbol records the source file name as a .file symbol.
//
// Its name occupies every auxiliary slot the symbol declares rather than one,
// so a long path spans several. The slot count is computed at Close, since it
// depends on the record width the header family chooses.
func (w *Writer) FileSymbol(path string) {
	if w.err != nil || w.closed {
		w.Fail(ErrClosed)
		return
	}
	w.file, w.hasFile = path, true
}

// SetComdat makes a section COMDAT and names the symbol duplicates are
// elected on.
//
// The leader must be defined in this section. The specification's layout is
// positional — the section definition record first, the COMDAT symbol second —
// so Close orders the table rather than trusting creation order, and a leader
// belonging to another section would produce an object whose first two symbols
// say two different things.
func (w *Writer) SetComdat(s *SectionBuilder, sel pe.Selection, leader *SymbolRef) {
	if w.fail(w.checkSection(s)) {
		return
	}
	if !sel.Valid() || sel.Associative() {
		// Associative goes through SetAssociative, which is the only
		// call that can name the section this one lives or dies with.
		w.Fail(ErrBadSymbol)
		return
	}
	if leader == nil || leader.w != w || leader.def.Section != s {
		w.Fail(ErrNoComdatLeader)
		return
	}
	s.comdat, s.selection, s.leader = true, sel, leader
	s.kind |= pe.SecLnkComdat
}

// SetAssociative makes a section an associative COMDAT of another.
//
// This is how .pdata and .xdata stay attached to the function they describe,
// and how a discarded function takes its unwind data with it. The associated
// section must itself be COMDAT; a chain that never terminates is an infinite
// loop in every consumer downstream, so Close checks for cycles before writing
// rather than leaving it for the reader to discover.
func (w *Writer) SetAssociative(s *SectionBuilder, assoc *SectionBuilder, leader *SymbolRef) {
	if w.fail(w.checkSection(s)) {
		return
	}
	if w.fail(w.checkSection(assoc)) {
		return
	}
	if leader == nil || leader.w != w || leader.def.Section != s {
		w.Fail(ErrNoComdatLeader)
		return
	}
	s.comdat, s.selection, s.leader, s.assoc = true, pe.SelectAssociative, leader, assoc
	s.kind |= pe.SecLnkComdat
}

// Directive records a linker option for the .drectve section.
//
// The section is synthesized at Close if anything was recorded. Name is
// normalized to upper case to match what the reader produces; Value keeps its
// case, because library, symbol, and export names are case-sensitive to
// everything that consumes them.
func (w *Writer) Directive(name, value string) {
	if w.err != nil || w.closed {
		w.Fail(ErrClosed)
		return
	}
	name = strings.ToUpper(strings.TrimLeft(name, "/-"))
	if name == "" {
		w.Fail(ErrBadDirective)
		return
	}
	w.directives = append(w.directives, Directive{Name: name, Value: value})
}