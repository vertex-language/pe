package link

import (
	"sort"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/image"
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
)

// The load configuration is the CRT's structure and the linker fills it — but
// almost never by writing into it. The CRT declares _load_config_used with its
// fields already initialized to the addresses of symbols the linker is
// expected to define:
//
//	__guard_fids_table      the sorted CFG target table
//	__guard_fids_count      its entry count, as an absolute
//	__guard_flags           the GuardFlags word, as an absolute
//	__guard_longjmp_table   / __guard_longjmp_count
//	__guard_iat_table       / __guard_iat_count
//	__guard_eh_cont_table   / __guard_eh_cont_count
//	__safe_se_handler_table / __safe_se_handler_count   (x86 SafeSEH)
//
// So the linker builds the tables, defines those names, and the object's own
// relocations carry the answers into the structure. That indirection is why
// this pass writes bytes into the load config in exactly one place — the
// ARM64X dynamic relocation table's offset and section, which have no symbol
// convention — and why everything else here is table construction.
//
// Two of the counts are *absolute* symbols: their value is the count, not an
// address. An ADDR64 against an absolute symbol has to write the constant
// rather than base+RVA, and image.Symbol.RVA deliberately refuses an absolute
// so that the mistake cannot be made silently. This is the first thing in the
// tree to produce one, and the backends' Apply must gain the case.
//
// The sorts are not cosmetic and they are not deferred. The GFIDS table must
// be sorted by RVA or the image will not load at all — the loader validates
// it — and the same is true of the longjmp table. But unlike .pdata these
// tables are the linker's own bytes, built from symbol addresses that are
// final the moment the image freezes, so they are sorted in Generate. .pdata
// cannot be, because its records are input bytes that apply has not relocated
// yet. That asymmetry is the whole reason one of these passes is a Synthetic
// and the other is a Finalizer.

// loadConfigSymbol is the CRT's name for the directory. As with _tls_used the
// spelling difference is x86's leading underscore on a single C name.
func loadConfigSymbol(m pe.Machine) string {
	if m == pe.MachineI386 {
		return "__load_config_used"
	}
	return "_load_config_used"
}

// guardKind identifies one of the four guard tables.
//
// They are four tables and not one list with a tag, because the load config
// names each separately and a target in the wrong one is either a call the
// loader will reject or a longjmp target treated as an indirect call site.
type guardKind int

const (
	guardFIDS guardKind = iota // .gfids$y — valid indirect call targets
	guardIAT                   // .giats$y — address-taken import entries
	guardLongJmp               // .gljmp$y — valid longjmp targets
	guardEHCont                // .gehcont$y — valid EH continuation targets
)

// guardSpec describes one table: the input section its targets come from, the
// symbols the CRT's load config references, and whether the table carries the
// per-entry metadata byte.
type guardSpec struct {
	kind      guardKind
	section   string
	table     string
	count     string
	withFlags bool
}

var guardSpecs = []guardSpec{
	{guardFIDS, ".gfids", "__guard_fids_table", "__guard_fids_count", true},
	{guardIAT, ".giats", "__guard_iat_table", "__guard_iat_count", false},
	{guardLongJmp, ".gljmp", "__guard_longjmp_table", "__guard_longjmp_count", false},
	{guardEHCont, ".gehcont", "__guard_eh_cont_table", "__guard_eh_cont_count", false},
}

// guardTable is one built table.
type guardTable struct {
	spec    guardSpec
	targets []*image.Symbol
	stride  uint32
	chunk   *image.Chunk
	size    uint32
}

func (g *guardTable) Size() uint32           { return g.size }
func (g *guardTable) Align() int             { return 4 }
func (g *guardTable) Bytes() ([]byte, error) { return make([]byte, g.size), nil }

// loadConfig is the load configuration synthetic.
type loadConfig struct {
	l *Linker

	sym   *image.Symbol
	chunk *image.Chunk
	off   uint32
	width pe.Width

	declared uint32
	tables   []*guardTable
	flags    pe.GuardFlags

	// metaBytes is the per-entry metadata width the GFIDS table uses,
	// beyond the four bytes of RVA. It is zero unless something is
	// suppressed, and it is written into GuardFlags' top nibble rather
	// than assumed by the reader — which is what lets a consumer walk a
	// table format it does not understand.
	metaBytes int
}

func (lc *loadConfig) Size() uint32           { return 0 }
func (lc *loadConfig) Align() int             { return 1 }
func (lc *loadConfig) Bytes() ([]byte, error) { return nil, nil }

// Prepare finds the directory, builds the guard tables, and defines the
// symbols the CRT's structure references.
func (lc *loadConfig) Prepare(img *image.Image) error {
	l := lc.l
	lc.width = l.opt.Target.Width()

	s := l.tabs[0].Lookup(loadConfigSymbol(l.opt.Target.Machine))
	if s == nil || s.chunk == nil || !s.chunk.Live() {
		if l.opt.Guard != GuardNone {
			// /GUARD:CF with no load config is a request the image
			// cannot express: every CFG field lives in this
			// structure, so there is nowhere to put the answer.
			return l.fail(&UndefinedError{
				Name: loadConfigSymbol(l.opt.Target.Machine),
				Refs: []string{"/GUARD:CF"},
			})
		}
		return nil
	}
	lc.sym, lc.chunk, lc.off = s.Out, s.chunk, s.off

	data, err := lc.chunk.Bytes()
	if err != nil {
		return l.fail(&InputError{Name: lc.chunk.Input, Err: err})
	}
	if uint64(lc.off) > uint64(len(data)) {
		return l.fail(&InputError{Name: lc.chunk.Input, Err: image.ErrOutOfBounds})
	}
	view, err := format.NewLoadConfigView(data[lc.off:], lc.width)
	if err != nil {
		return l.fail(&InputError{Name: lc.chunk.Input, Err: err})
	}
	lc.declared = view.DeclaredSize()

	if l.opt.Guard == GuardNone {
		// Nothing to build. The directory is still emitted: the
		// structure carries the security cookie and the global flags
		// whether or not CFG is on.
		return nil
	}
	if err := lc.checkVersion(view); err != nil {
		return l.fail(err)
	}
	if err := lc.build(img); err != nil {
		return err
	}
	return lc.define()
}

// checkVersion refuses a load config too short to describe what was asked for.
//
// The structure states its own length, and a field past it is not a field —
// the bytes there belong to whatever the CRT put after the struct. So a
// /GUARD:CF link against a CRT that predates GuardFlags fails here, naming the
// input, rather than producing an image that advertises CFG in its
// DllCharacteristics and carries no table to back it.
func (lc *loadConfig) checkVersion(v *format.LoadConfigView) error {
	need := []struct {
		f    format.LoadConfigField
		what string
	}{
		{format.LCGuardFlags, "GuardFlags"},
		{format.LCGuardCFFunctionTable, "GuardCFFunctionTable"},
		{format.LCGuardCFFunctionCount, "GuardCFFunctionCount"},
	}
	if lc.l.opt.Guard == GuardEHCont {
		need = append(need,
			struct {
				f    format.LoadConfigField
				what string
			}{format.LCGuardEHContinuationTable, "GuardEHContinuationTable"},
			struct {
				f    format.LoadConfigField
				what string
			}{format.LCGuardEHContinuationCount, "GuardEHContinuationCount"})
	}
	for _, n := range need {
		if !v.Has(n.f) {
			return &InputError{
				Name: lc.chunk.Input,
				Err: &image.LayoutError{
					Section: lc.chunk.Name,
					Reason: "load configuration declares " +
						itoa(int(lc.declared)) + " bytes, too few to hold " + n.what,
				},
			}
		}
	}
	return nil
}

// build collects each table's targets and reserves a chunk for it.
//
// The targets are named by relocations rather than by bytes. A guard section
// holds a run of RVAs, and an RVA in an object file *is* a relocation — the
// bytes themselves are zero — so reading them would read nothing. scan already
// walked these sections for liveness; this walk repeats it because Reqs has
// one bucket and the load config needs four, and which of the four a target
// belongs to is decided by the section it came from.
func (lc *loadConfig) build(img *image.Image) error {
	l := lc.l

	byKind := make(map[guardKind]map[*image.Symbol]bool)
	order := make(map[guardKind][]*image.Symbol)
	for _, sp := range guardSpecs {
		byKind[sp.kind] = make(map[*image.Symbol]bool)
	}

	for _, c := range l.chunks {
		if !c.Live() {
			continue
		}
		kind, ok := guardKindOf(c.GroupName())
		if !ok {
			continue
		}
		for _, r := range c.Relocs() {
			if r.Sym == nil || byKind[kind][r.Sym] {
				continue
			}
			byKind[kind][r.Sym] = true
			order[kind] = append(order[kind], r.Sym)
		}
	}

	// The EH continuation table is only built under /GUARD:EHCONT. Under
	// plain /GUARD:CF the .gehcont sections still contribute their bytes;
	// what changes is whether the load config describes them, and
	// describing a table the image does not otherwise support is worse
	// than omitting it.
	stride := uint32(4 + lc.metaBytes)

	var sec *image.Section
	for _, sp := range guardSpecs {
		if sp.kind == guardEHCont && l.opt.Guard != GuardEHCont {
			continue
		}
		targets := order[sp.kind]
		if len(targets) == 0 {
			continue
		}
		g := &guardTable{spec: sp, targets: targets, stride: 4}
		if sp.withFlags {
			g.stride = stride
		}
		g.size = uint32(len(targets)) * g.stride

		if sec == nil {
			var err error
			// The tables are read-only data. They must be: the
			// loader validates the GFIDS table at map time and a
			// writable copy is a control-flow guard something can
			// edit.
			sec, err = l.section(".rdata", pe.SecInitData, pe.SecRead)
			if err != nil {
				return err
			}
		}
		g.chunk = image.NewChunk(".rdata", "<link>", g)
		g.chunk.Reachable = true
		if err := sec.Add(g.chunk); err != nil {
			return l.fail(err)
		}
		l.chunks = append(l.chunks, g.chunk)
		lc.tables = append(lc.tables, g)
	}
	return nil
}

func guardKindOf(group string) (guardKind, bool) {
	for _, sp := range guardSpecs {
		if sp.section == group {
			return sp.kind, true
		}
	}
	return 0, false
}

// define creates the symbols the CRT's load config initializers reference.
//
// Each table gets two: the table itself, defined at offset zero of its chunk,
// and its count, defined as an *absolute* — a symbol whose value is a number
// rather than an address. The CRT writes `(ULONGLONG)__guard_fids_count` and
// means the value, which is why the two kinds cannot be collapsed and why
// image.Symbol.RVA refuses an absolute rather than converting one.
//
// __guard_flags is the same shape: a constant the linker computes and the CRT
// copies into GuardFlags.
func (lc *loadConfig) define() error {
	l := lc.l
	tab := l.tabs[0]

	defineAt := func(name string, c *image.Chunk, off uint32) {
		tab.view.Symbols.Define(name, c, off)
		if s := tab.Lookup(name); s != nil {
			s.chunk, s.off, s.Kind = c, off, SymDefined
		}
	}
	defineAbs := func(name string, v uint64) {
		tab.view.Symbols.Absolute(name, v)
		if s := tab.Lookup(name); s != nil {
			s.chunk, s.value, s.Kind = nil, v, SymAbsolute
		}
	}

	lc.flags = pe.GuardCFInstrumented
	for _, g := range lc.tables {
		defineAt(g.spec.table, g.chunk, 0)
		defineAbs(g.spec.count, uint64(len(g.targets)))
		switch g.spec.kind {
		case guardFIDS:
			lc.flags |= pe.GuardCFFunctionTablePresent
		case guardLongJmp:
			lc.flags |= pe.GuardCFLongjumpTablePresent
		case guardEHCont:
			lc.flags |= pe.GuardEHContinuationTablePresent
		case guardIAT:
			lc.flags |= pe.GuardProtectDelayloadIAT
		}
	}

	// The stride nibble is a number wearing a flag's clothing, and it goes
	// in through the method that knows that rather than by shifting here.
	f, ok := lc.flags.WithGFIDSMetadataBytes(lc.metaBytes)
	if !ok {
		return l.fail(&image.LayoutError{
			Section: ".rdata",
			Reason:  "guard table metadata width does not fit the GuardFlags nibble",
		})
	}
	lc.flags = f
	defineAbs("__guard_flags", uint64(uint32(lc.flags)))
	return nil
}

// Generate sorts each table and writes it.
//
// The sort is a load requirement, not a tidiness one: the loader validates the
// GFIDS table's ordering and refuses an image whose table is out of order. It
// happens here rather than in a finalizer because these are the linker's own
// bytes over symbol addresses that Freeze made final — nothing later changes
// them, unlike .pdata, whose records apply has not yet relocated.
func (lc *loadConfig) Generate(img *image.Image) error {
	if lc.chunk == nil {
		return nil
	}
	for _, g := range lc.tables {
		rvas := make([]pe.RVA, 0, len(g.targets))
		for _, s := range g.targets {
			r, err := s.RVA()
			if err != nil {
				// A guard target with no address: an absolute
				// symbol, or one whose chunk was swept out from
				// under the table. Either is a linker bug, and
				// an unsorted zero at the head of the table is
				// an image the loader rejects.
				return lc.l.fail(&InputError{Name: g.spec.section, Err: err})
			}
			rvas = append(rvas, r)
		}
		sort.Slice(rvas, func(i, j int) bool { return rvas[i] < rvas[j] })

		b := binio.NewBufSize(int(g.size))
		for _, r := range rvas {
			b.U32(uint32(r))
			for k := 0; k < int(g.stride)-4; k++ {
				// The metadata byte. Zero is "an ordinary
				// target": neither suppressed nor export
				// suppressed.
				b.U8(0)
			}
		}
		data, err := b.Data()
		if err != nil {
			return err
		}
		rva, err := g.chunk.RVA()
		if err != nil {
			return err
		}
		if err := writeAt(img, rva, g.size, data); err != nil {
			return err
		}
	}
	return nil
}

// Dirs returns the load configuration data directory entry.
//
// The size is the structure's own declared Size and not this tree's idea of
// how long a load config is. The loader reads the field to decide which
// members exist, and a directory size that disagrees with it describes a
// structure neither party has.
func (lc *loadConfig) Dirs() []dirEntry {
	if lc.chunk == nil {
		return nil
	}
	rva, err := lc.sym.RVA()
	if err != nil {
		return nil
	}
	return []dirEntry{{pe.DirLoadConfig, rva, lc.declared}}
}

// safeSEH is x86's SafeSEH, which is the same mechanism one generation
// earlier: .sxdata holds the symbol-table indices of the registered handlers
// and the linker turns them into a sorted RVA table named by SEHandlerTable
// and SEHandlerCount.
//
// It is not implemented. The indices in .sxdata are physical symbol slots in
// the object that carried them, so resolving one needs that object's table —
// which this pass no longer has by the time it runs, and which is the reason
// the collection belongs in resolve rather than here. An @feat.00 symbol whose
// SafeSEH bit is set with no .sxdata section means zero registered handlers,
// which is meaningfully different from never having opted in, and any
// implementation has to keep the two apart.
func (lc *loadConfig) safeSEH() error { return ErrUnimplemented }