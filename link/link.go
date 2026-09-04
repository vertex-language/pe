package link

import (
	"io"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/backend"
	"github.com/vertex-language/pe/image"
)

// Linker accumulates inputs and options and produces one image.
//
// Errors latch, as everywhere else in this tree. The first failure is kept and
// every later call is a no-op, so a build sequence is a straight run of calls
// with one check at Link. The alternative — a returned error on every setter —
// is thirty checks nobody writes.
//
// A Linker runs once. Nothing here is reusable, because the image it produces
// owns the chunks the inputs contributed and rewinding that would mean
// re-reading every object anyway.
type Linker struct {
	opt Options
	be  backend.Backend
	img *image.Image

	// The input set. Both grow during resolution: an archive member
	// becomes an object, and that object's directives can name a library.
	objects []*Object
	libs    []*Library
	res     []*Resources

	// pending is libraries a directive named that have not been opened.
	pending []string
	// libSeen keys on the normalized library name, so the same library
	// arriving from the command line and from a directive is opened once.
	libSeen map[string]bool
	// mismatch is the /FAILIFMISMATCH table, keyed on the pragma's name.
	mismatch map[string]mismatch

	// tabs is one symbol table per view. An ARM64X image has two and they
	// are genuinely separate namespaces; everything else has one, and
	// tabs[0] is the native view in both cases.
	tabs []*symtab

	// chunks is every placeable contribution in creation order, live and
	// dead alike. Order is preserved because it is the order contributions
	// arrived, which is the order merge sorts within — and because a map
	// iteration anywhere in this pipeline would make the output file
	// differ between runs of a linker whose whole point is that it does
	// not.
	chunks []*image.Chunk

	// info, deps, and symOf are what link knows that image does not: which
	// COFF section a chunk came from, which chunks must outlive which, and
	// how an output symbol was resolved. They are keyed on the thing they
	// describe rather than stored in it, because image deliberately has no
	// idea what a COMDAT or an import is.
	info  map[*image.Chunk]*chunkInfo
	deps  map[*image.Chunk][]*image.Chunk
	symOf map[*image.Symbol]*Sym

	imports     map[string]*Import
	importOrder []*Import
	weaks       []weakRef

	thunks   []thunkRef
	thunkFor map[thunkKey]*Sym

	// reqs is what the backend and scan decided the link will need. It is
	// filled while the image is open, so everything in it is a size or a
	// count and nothing in it is an address.
	reqs *backend.Reqs

	// The synthesized tables. They are held as two lists rather than as
	// eight fields because nothing outside synth and fill needs to name
	// one: image.Prepare runs the first list in order, and fill collects
	// data directory entries from the second. Adding a table is a line in
	// each.
	synths []image.Synthetic
	dirs   []dirProvider

	// The three exceptions, which other passes reach for by name.
	// arm64x needs the load configuration for the two fields that have no
	// symbol convention; Link needs arm64x itself, because the dynamic
	// relocations are written between emit and the checksum and no
	// interface expresses that position.
	loadcfg *loadConfig
	unwind  *unwind
	dvrt    *arm64x
	debug   *debugDir

	manifestDeps []string
	warnings     []string

	closers []io.Closer

	err  error
	done bool
}

// New returns a Linker for a target.
//
// The backend is resolved here rather than at Link, so a target with no
// registered backend fails before forty megabytes of input have been read. The
// usual cause is a missing blank import of the backend package, which is what
// *backend.NoBackendError says.
func New(t pe.Target) (*Linker, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	be, err := backend.For(t)
	if err != nil {
		return nil, err
	}
	return &Linker{
		opt:      Options{Target: t, OptICF: ICFSafe},
		be:       be,
		libSeen:  make(map[string]bool),
		mismatch: make(map[string]mismatch),
		imports:  make(map[string]*Import),
	}, nil
}

// NewWith returns a Linker configured from a complete Options value, for a
// caller that would rather build one than call thirty setters.
func NewWith(opt Options) (*Linker, error) {
	l, err := New(opt.Target)
	if err != nil {
		return nil, err
	}
	target := l.opt.Target
	l.opt = opt
	l.opt.Target = target
	return l, nil
}

// Options returns a copy of the current configuration, for a caller that wants
// to see what the defaults resolved to.
func (l *Linker) Options() Options { return l.opt }

// Target returns the target this link is for.
func (l *Linker) Target() pe.Target { return l.opt.Target }

// Backend returns the machine backend this link will use.
func (l *Linker) Backend() backend.Backend { return l.be }

// Image returns the image under construction, or nil before Link has built
// one. It exists for diagnostics and for a caller assembling an image by hand;
// nothing in a normal link needs it.
func (l *Linker) Image() *image.Image { return l.img }

// Reqs returns what scan recorded, for a caller that wants to see what the
// link decided it needed.
func (l *Linker) Reqs() *backend.Reqs { return l.reqs }

// Err returns the first error latched, or nil.
func (l *Linker) Err() error { return l.err }

// Fail latches err if no error is latched yet.
func (l *Linker) Fail(err error) {
	if l.err == nil && err != nil {
		l.err = err
	}
}

// fail latches and returns the latched error, so a caller can write
// `return l.fail(err)`.
func (l *Linker) fail(err error) error {
	l.Fail(err)
	return l.err
}

// warn records a condition that does not stop the link.
//
// There is no logging here and no writer to configure. This package returns an
// image rather than writing one, so a warning is a value the caller collects
// and decides about — which is also what makes Options.Strict a real switch
// rather than a verbosity setting: the same condition either lands here or
// stops the link.
func (l *Linker) warn(msg string) { l.warnings = append(l.warnings, msg) }

// Warnings returns the conditions the link accepted, in the order they arose.
func (l *Linker) Warnings() []string { return l.warnings }

// set applies a configuration change unless the Linker is already unusable.
//
// Every setter goes through it, which is what makes a setter called after Link
// an error rather than a change with no effect — the second being the kind of
// mistake that produces a correct-looking build and a wrong file.
func (l *Linker) set(f func()) {
	if l.err != nil {
		return
	}
	if l.done {
		l.Fail(ErrLinked)
		return
	}
	f()
}

// Close releases every file the Linker opened.
//
// Section data is read on demand from the underlying extents, so the
// descriptors stay open for the life of the link. A caller that keeps a Linker
// past Link should Close it; one that discards the image's bytes and the
// Linker together may skip it, at the cost of holding descriptors until the
// process exits.
func (l *Linker) Close() error {
	var first error
	for _, c := range l.closers {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	l.closers = nil
	return first
}

// Link runs the whole pipeline and returns the finished image.
//
// The sequence is fixed and each step's inputs are final only after the one
// before it. Three of the orderings are not obvious and are worth stating,
// because getting any of them wrong produces a file rather than an error.
//
// scan runs before synth. The backend walks img.Sections() to record what the
// link will need, so the input-derived sections have to exist — which means
// merge has run — and the synthesized tables must not exist yet, because their
// sizes are what scan is being asked about.
//
// order runs after synth and before layout. The section set is final once the
// tables have been placed, and Seal is what stops anything else being added
// while addresses are being assigned.
//
// contents runs before apply. A relocation adds to the field it patches —
// COFF carries no addend, so the addend is whatever the compiler left in the
// bytes — and a pass that relocated before writing would add to whatever the
// output buffer happened to hold.
func (l *Linker) Link() (*image.Image, error) {
	if l.done {
		return nil, ErrLinked
	}
	l.done = true
	if l.err != nil {
		return nil, l.err
	}

	steps := []struct {
		name string
		run  func() error
	}{
		// Establish the input set: read what the caller named, replay
		// every .drectve, and open the libraries those name.
		{"ingest", l.ingest},
		// Build the output model. Everything after this point places
		// things in it.
		{"model", l.model},
		// Decide which definition wins for every name, run the archive
		// fixpoint and the COMDAT elections, and turn input sections
		// into chunks.
		{"resolve", l.resolve},
		// Report every name that reached the end of resolution with no
		// definition, all of them rather than the first.
		{"check", l.check},
		// Build the dependency graph sweep walks, and cut .pdata into
		// per-function records.
		{"split", l.split},
		// /OPT:REF, at chunk granularity, from the entry point and the
		// roots.
		{"sweep", l.sweep},
		// $-group ordering, /MERGE, /OPT:ICF, and the creation of the
		// output sections.
		{"merge", l.merge},
		// Ask the backend what the link needs, and answer the questions
		// it cannot: which imports need slots and which need thunks.
		{"scan", l.scan},
		// .idata, .edata, .reloc, .rsrc, .tls, the load config, and the
		// dynamic relocations, registered as chunks and sized.
		{"synth", l.synth},
		// Validate the section set and Seal.
		{"order", l.order},
		// The fixpoint: every RVA and file offset, thunk growth, then
		// Freeze and bind.
		{"layout", l.layout},
		// Write every live chunk and generate the synthetics.
		{"contents", l.contents},
		// Patch every relocation.
		{"apply", l.apply},
		// Sort the exception table and fill the data directories.
		{"fill", l.fill},
		// The DOS stub, the PE signature, and the three headers.
		{"emit", l.emit},
	}

	if err := l.checkOptions(); err != nil {
		return nil, l.fail(err)
	}
	for _, s := range steps {
		if err := s.run(); err != nil {
			return nil, l.fail(err)
		}
	}

	// The dynamic relocations overwrite header words, so they cannot be
	// written until emit has produced the headers — and the checksum
	// covers the file, so it cannot be computed until they have. Neither
	// position is expressible as a finalizer, which is why these two are
	// statements rather than registrations.
	if l.dvrt != nil {
		if err := l.dvrt.Write(); err != nil {
			return nil, l.fail(err)
		}
	}
	if err := l.debug.patchRepro(l.img); err != nil {
		return nil, l.fail(err)
	}
	if err := (&checksumFinalizer{l: l}).Finalize(l.img); err != nil {
		return nil, l.fail(err)
	}
	return l.img, nil
}

// model builds the output image from the options.
//
// It is a step of its own rather than part of New because image.Config
// validates the alignments against the format's constraints, and an impossible
// combination should fail after the options are complete and before anything
// has been read — not at construction, when the caller has not finished
// configuring, and not at emit, when it has already cost a full link.
func (l *Linker) model() error {
	img, err := image.New(l.opt.config())
	if err != nil {
		return l.fail(err)
	}
	l.img = img
	return nil
}

// synth registers the synthesized tables and settles their sizes.
//
// Registration order is load-bearing in three places, and none of them is
// visible from the types.
//
// tls registers before basereloc. The TLS directory's address fields are the
// one place in an image where a stored address is a virtual address, so the
// linker owes a base relocation for each field it fills — and it records those
// sites during its own Prepare, which must therefore run before
// baseRelocs.Prepare reads the list as finished.
//
// loadcfg registers before basereloc for the same reason in a different shape:
// it defines the guard table symbols, and the CRT's relocations against them
// are what scan already recorded.
//
// arm64x registers last, because it reserves space in the .reloc section that
// basereloc created and the dynamic relocation table sits after the base
// relocation blocks.
func (l *Linker) synth() error {
	if len(l.opt.DelayLoads) > 0 {
		// format.DelayDescriptor and DirDelayImport exist, and loadcfg and
		// arm64x both already have code that accounts for a delay-load
		// table's existence — but nothing here builds one for an MS-style
		// request. SetDelayLoad takes the request and l.opt.DelayLoads
		// carries it all the way to here with no other code ever reading
		// it, which without this check is indistinguishable from the DLL
		// actually being delay-loaded until the image is run and the CRT
		// dispatch stub that was never linked in turns out not to exist.
		//
		// This does not affect a delay-loaded DLL brought in by linking a
		// GNU delay-import archive (dlltool -y) instead: that path never
		// touches l.opt.DelayLoads at all, because its .didat$2 through
		// .didat$7 sections are ordinary object content merged by the
		// same $-group pipeline as every other import, not something
		// SetDelayLoad requests.
		return l.fail(&InputError{Name: l.opt.DelayLoads[0], Err: ErrUnimplemented})
	}
	if l.opt.DelayUnload {
		// DelayUnload only means something as a field of the MS-format
		// delay-load descriptor the branch above does not build — the
		// GNU path's descriptor comes from dlltool's own object bytes,
		// which this tree never rewrites. So SetDelayUnload(true) with no
		// SetDelayLoad call at all would otherwise silently do nothing,
		// the same failure mode the check above exists to catch.
		return l.fail(ErrUnimplemented)
	}

	l.loadcfg = &loadConfig{l: l}
	l.dvrt = &arm64x{l: l}
	l.debug = &debugDir{l: l}

	add := func(s image.Synthetic) {
		l.synths = append(l.synths, s)
		if d, ok := s.(dirProvider); ok {
			l.dirs = append(l.dirs, d)
		}
	}
	add(&imports{l: l})
	add(&exports{l: l})
	add(&tlsDirectory{l: l})
	add(l.loadcfg)
	add(&baseRelocs{l: l})
	add(l.dvrt)
	// resources.Prepare no-ops when there is nothing to embed — no .res
	// input and no /MANIFEST:EMBED — the same way imports and exports do
	// when the link has none of either.
	add(&resources{l: l})
	add(l.debug)

	for _, s := range l.synths {
		if err := l.img.AddSynthetic(s); err != nil {
			return l.fail(err)
		}
	}

	// The exception table is a finalizer rather than a synthetic: its
	// records are input bytes whose first word apply has not yet
	// relocated, so a sort performed at Generate would sort a table of
	// zeroes. It still owns a data directory, so it joins the second list.
	l.unwind = &unwind{l: l}
	if err := l.img.AddFinalizer(l.unwind); err != nil {
		return l.fail(err)
	}
	l.dirs = append(l.dirs, l.unwind)

	return l.img.Prepare()
}

// checkOptions rejects the combinations that cannot produce a working image,
// before any of them has cost anything.
//
// The Control Flow Guard rule is the one worth stating: CFG's dispatch tables
// hold RVAs the loader fixes up, so it depends on the image being relocatable.
// /GUARD:CF with ASLR off is not a flag that does less — it is a flag that
// produces an image whose guard tables are wrong the moment anything moves.
func (l *Linker) checkOptions() error {
	if err := l.opt.Target.Validate(); err != nil {
		return err
	}
	if l.opt.Guard != GuardNone && !l.opt.DllChar.Has(pe.DynamicBase) {
		return ErrGuardWithoutDynamicBase
	}
	if l.opt.Guard != GuardNone && l.opt.DllChar.Has(pe.GuardCF) == false {
		// The characteristic is what tells the loader to enforce what
		// the load config describes. Building the tables without it
		// produces an image that pays for CFG and does not get it.
		l.warn("/GUARD:CF without IMAGE_DLLCHARACTERISTICS_GUARD_CF; " +
			"the guard tables will be built and not enforced")
	}
	if l.opt.Manifest != ManifestNone && len(l.opt.ManifestData) == 0 {
		return &DirectiveError{Name: "MANIFEST", Reason: "no manifest supplied",
			Err: ErrDirectiveNotAllowed}
	}
	if l.opt.OptICF == ICFAll {
		// Documented link.exe behaviour and not safe: folding by bytes
		// alone makes two distinct function pointers compare equal.
		// The caller asked for it explicitly, so this is a note rather
		// than a refusal.
		l.warn("/OPT:ICF:ALL folds address-taken functions; " +
			"function-pointer identity is not preserved")
	}
	return nil
}