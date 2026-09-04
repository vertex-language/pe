package link

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/ar"
	"github.com/vertex-language/pe/coff"
	"github.com/vertex-language/pe/image"
	"github.com/vertex-language/pe/internal/binio"
)

// Ingest establishes the input set. It reads the files the caller named, sorts
// them by what they turn out to be, replays the .drectve sections of every
// object, and opens the libraries those directives name.
//
// It does *not* extract archive members. An archive is opened and its index
// read; which members are pulled is resolve's business, decided by what is
// still undefined. That is also why the fixpoint here is small and the one in
// resolve is not: extracting a member yields a new object, which yields new
// directives, which may name a new library — so resolve re-enters
// applyDirectives for every member it fetches.
//
// LINK does not use file extensions to decide what a file is; it examines each
// one. Neither does this. A .lib holding no short-import members is a static
// library, a .obj that is really an archive is an archive, and the name on
// disk is never consulted.

// Origin is where an input came from, which decides the order libraries are
// searched in.
//
// The three values are the specification's three tiers: libraries named on the
// command line are searched first, then those named by /DEFAULTLIB, then those
// named by a directive inside an object. Collapsing them loses the ordering
// that decides which of two libraries defining the same symbol wins.
type Origin uint8

const (
	// FromCommandLine is a file the caller added directly.
	FromCommandLine Origin = iota
	// FromDefaultLib is a library named by Linker.DefaultLib.
	FromDefaultLib
	// FromDirective is a library named by a /DEFAULTLIB inside a .drectve.
	FromDirective
)

func (o Origin) String() string {
	switch o {
	case FromDefaultLib:
		return "defaultlib"
	case FromDirective:
		return "directive"
	}
	return "command line"
}

// Object is one COFF object participating in the link.
//
// Name is what diagnostics use. For an archive member it is the archive and
// the member together — "libcmt.lib(chkstk.obj)" — because a member name alone
// appears in twenty libraries and says nothing about which.
type Object struct {
	Name    string
	Path    string
	Machine pe.Machine
	Origin  Origin

	// Lib is the library this object was extracted from, or nil for one the
	// caller added directly.
	Lib *Library

	// File is the decoded object. It stays open: section data is read on
	// demand from the underlying extent, which is what keeps a
	// forty-megabyte object cheap.
	File *coff.File

	index      int
	directives bool // whether applyDirectives has run for this object

	// resolved marks that addObject has already brought this object's chunks
	// and symbols into the link, so the archive fixpoint's repeated walk over
	// l.objects does not redo it.
	resolved bool

	// tab is this object's view of the symbol table, bound once addObject
	// resolves the machine-specific view it belongs to.
	tab *symtab

	// chunks holds one *image.Chunk per contributing section, indexed the
	// same as File.Sections; a non-contributing section (LNK_REMOVE, a
	// COMDAT that lost its election, .debug$S/.debug$T) leaves its slot nil.
	chunks []*image.Chunk
}

func (o *Object) String() string { return o.Name }

// Library is one archive available to the link.
//
// Members are not read here. The index is, because that is what answers
// "does this archive define the name I am missing" without touching the
// members at all.
type Library struct {
	Name   string
	Path   string
	Origin Origin
	File   *ar.File

	index   int
	fetched map[int64]*Object // by member header offset
}

func (l *Library) String() string { return l.Name }

// Resources is a .res file added to the link. It is carried as bytes: rsrc
// parses it and builds the .rsrc tree, and that happens during synth rather
// than here.
type Resources struct {
	Name string
	Data []byte
}

// SetLibPath sets the directories searched for a library named without one.
//
// There is no default search path and no LIB environment variable. A build
// that resolves its libraries from ambient state is a build that works on one
// machine, and the whole point of a linker with no scripts is that the caller
// says what it wants.
func (l *Linker) SetLibPath(paths ...string) {
	l.set(func() { l.opt.LibPaths = append([]string(nil), paths...) })
}

// DefaultLib records a library to search after those added directly. It is
// /DEFAULTLIB, and a name already excluded by NoDefaultLib is dropped here
// rather than opened and ignored.
func (l *Linker) DefaultLib(name string) {
	l.set(func() { l.opt.DefaultLibs = append(l.opt.DefaultLibs, name) })
}

// NoDefaultLib excludes a library from the default set. An empty name excludes
// every default library, which is /NODEFAULTLIB with no argument.
func (l *Linker) NoDefaultLib(name string) {
	l.set(func() {
		if name == "" {
			l.opt.NoDefaultLibAll = true
			return
		}
		l.opt.NoDefaultLibs = append(l.opt.NoDefaultLibs, name)
	})
}

// OpenFile adds the file at path, whatever it turns out to be.
//
// The kind is inferred from the contents. An image is refused outright: this
// package produces images and does not consume them, and a caller who passed
// one meant to pass the object or the import library beside it.
func (l *Linker) OpenFile(path string) error {
	if l.err != nil {
		return l.err
	}
	f, err := os.Open(path)
	if err != nil {
		return l.fail(&InputError{Name: path, Err: err})
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return l.fail(&InputError{Name: path, Err: err})
	}
	ext, err := binio.NewExtent(f, fi.Size())
	if err != nil {
		f.Close()
		return l.fail(&InputError{Name: path, Err: err})
	}
	l.closers = append(l.closers, f)

	name := filepath.Base(path)
	if err := l.addExtent(name, path, ext, FromCommandLine); err != nil {
		return err
	}
	return nil
}

// AddObject adds an object already in memory, with no file round trip. The
// object writer's output is this linker's input directly.
func (l *Linker) AddObject(name string, data []byte) error {
	return l.addBytes(name, data, FromCommandLine)
}

// AddArchive adds an archive already in memory.
func (l *Linker) AddArchive(name string, data []byte) error {
	return l.addBytes(name, data, FromCommandLine)
}

// AddResources adds a compiled resource file. rsrc parses it and builds the
// .rsrc tree during synth; here it is only recorded.
func (l *Linker) AddResources(data []byte) error {
	if l.err != nil {
		return l.err
	}
	l.res = append(l.res, &Resources{Name: "<resources>", Data: data})
	return nil
}

func (l *Linker) addBytes(name string, data []byte, origin Origin) error {
	if l.err != nil {
		return l.err
	}
	ext, err := binio.NewExtent(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return l.fail(&InputError{Name: name, Err: err})
	}
	return l.addExtent(name, "", ext, origin)
}

// addExtent classifies one input and files it away.
//
// sniffLen is more than KindOf needs for an object, because confirming an
// image means reaching the PE signature at whatever offset the stub records.
// Reading a little extra once is cheaper than mistaking an image for something
// this package will then try to parse as COFF.
const sniffLen = pe.ImagePrefix

func (l *Linker) addExtent(name, path string, ext *binio.Extent, origin Origin) error {
	head, err := ext.Head(sniffLen)
	if err != nil {
		return l.fail(&InputError{Name: name, Err: err})
	}

	switch k := pe.KindOf(head); k {
	case pe.KindObject, pe.KindBigObj:
		f, err := coff.NewFile(ext)
		if err != nil {
			return l.fail(&InputError{Name: name, Err: err})
		}
		l.registerObject(&Object{
			Name:    name,
			Path:    path,
			Machine: f.Machine,
			Origin:  origin,
			File:    f,
		})
		return nil

	case pe.KindArchive:
		a, err := ar.NewFile(ext)
		if err != nil {
			return l.fail(&InputError{Name: name, Err: err})
		}
		l.addLibrary(&Library{
			Name:    name,
			Path:    path,
			Origin:  origin,
			File:    a,
			fetched: make(map[int64]*Object),
		})
		return nil

	case pe.KindRes:
		data, err := ext.Head(ext.Size())
		if err != nil {
			return l.fail(&InputError{Name: name, Err: err})
		}
		l.res = append(l.res, &Resources{Name: name, Data: data})
		return nil

	case pe.KindImage:
		return l.fail(&InputError{Name: name, Err: pe.ErrImageFile})

	case pe.KindShortImport:
		// A bare short-import member outside an archive. It describes
		// one import and nothing links against it directly; the import
		// library it belongs to is what the caller meant to pass.
		return l.fail(&InputError{Name: name, Err: coff.ErrShortImport})

	case pe.KindLTCG:
		return l.fail(&InputError{Name: name, Err: coff.ErrLTCGObject})
	}
	return l.fail(&InputError{Name: name, Err: pe.ErrNotCOFF})
}

// registerObject records a newly-opened object in input order. It is pure
// bookkeeping — bringing the object's chunks and symbols into the link is
// addObject's job, in resolve.go, which runs later over l.objects.
func (l *Linker) registerObject(o *Object) {
	o.index = len(l.objects)
	l.objects = append(l.objects, o)
}

func (l *Linker) addLibrary(lib *Library) {
	lib.index = len(l.libs)
	l.libs = append(l.libs, lib)
	l.libSeen[libKey(lib.Name)] = true
}

// Objects returns the objects in the link, in the order they entered it.
func (l *Linker) Objects() []*Object { return l.objects }

// Libraries returns the archives available to the link, in search order.
func (l *Linker) Libraries() []*Library { return l.libs }

// ingest runs the input phase: replay directives, open the libraries they and
// the options name.
//
// The loop is by index and re-reads the slice length rather than ranging over
// a snapshot, because an object's directives can name a library and a library
// can — during resolve, not here — yield objects. It terminates because both
// additions are monotonic and each object's directives are replayed once.
func (l *Linker) ingest() error {
	if len(l.objects) == 0 && len(l.libs) == 0 {
		return ErrNoInputs
	}

	for i := 0; i < len(l.objects); i++ {
		if err := l.applyDirectives(l.objects[i]); err != nil {
			return err
		}
	}

	// Options-level default libraries are opened after the command line's
	// own inputs and before anything a directive named, which is the
	// documented search order.
	for _, name := range l.opt.DefaultLibs {
		if err := l.openLibrary(name, FromDefaultLib); err != nil {
			return err
		}
	}
	for i := 0; i < len(l.pending); i++ {
		if err := l.openLibrary(l.pending[i], FromDirective); err != nil {
			return err
		}
	}
	l.pending = nil
	return nil
}

// needLibrary records a library a directive asked for.
//
// The exclusion is checked here, where the name arrives, rather than where the
// file is opened. /NODEFAULTLIB:foo overrides /DEFAULTLIB:foo wherever the
// second one came from — and honouring it only for the command line is a real
// bug in a shipping linker, where a /DEFAULTLIB buried in a library's own
// .drectve pulls in a second C runtime that the caller explicitly excluded.
func (l *Linker) needLibrary(name string) {
	if name == "" || l.opt.Excluded(name) {
		return
	}
	if l.libSeen[libKey(name)] {
		return
	}
	// Mark it now rather than at open, so two directives naming the same
	// library queue it once.
	l.libSeen[libKey(name)] = true
	l.pending = append(l.pending, name)
}

// openLibrary resolves a library name against the search path and adds it.
func (l *Linker) openLibrary(name string, origin Origin) error {
	if l.opt.Excluded(name) {
		return nil
	}
	path, err := l.findLibrary(name)
	if err != nil {
		return l.fail(&InputError{Name: name, Err: err})
	}
	f, e := os.Open(path)
	if e != nil {
		return l.fail(&InputError{Name: name, Err: e})
	}
	fi, e := f.Stat()
	if e != nil {
		f.Close()
		return l.fail(&InputError{Name: name, Err: e})
	}
	ext, e := binio.NewExtent(f, fi.Size())
	if e != nil {
		f.Close()
		return l.fail(&InputError{Name: name, Err: e})
	}
	l.closers = append(l.closers, f)

	// libSeen was set when the name was queued; addLibrary sets it again,
	// which is harmless and keeps the direct callers of addLibrary honest.
	return l.addExtent(filepath.Base(path), path, ext, origin)
}

// findLibrary locates a library on the search path.
//
// A name carrying a directory separator is used as given. Otherwise every
// configured path is tried, with ".lib" appended when the name has no
// extension — which is what makes a /DEFAULTLIB:msvcrt directive find
// msvcrt.lib, since the directive never carries the extension.
func (l *Linker) findLibrary(name string) (string, error) {
	cands := []string{name}
	if filepath.Ext(name) == "" {
		cands = append(cands, name+".lib")
	}

	if strings.ContainsAny(name, `/\`) {
		for _, c := range cands {
			if fileExists(c) {
				return c, nil
			}
		}
		return "", ErrLibNotFound
	}

	for _, dir := range l.opt.LibPaths {
		for _, c := range cands {
			p := filepath.Join(dir, c)
			if fileExists(p) {
				return p, nil
			}
		}
	}
	return "", ErrLibNotFound
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// Fetch extracts a member of a library as an object, or returns the one
// already extracted.
//
// Extraction is idempotent and keyed on the member's header offset, because
// two symbols in the index routinely name the same member and pulling it twice
// would produce two objects defining everything it defines.
//
// This is resolve's entry point into ingest, and the reason ingest's own loop
// is written the way it is: the object this returns carries directives that
// have not been replayed, and replaying them can name a library that has not
// been opened.
func (l *Linker) Fetch(lib *Library, m *ar.Member) (*Object, error) {
	if o, ok := lib.fetched[m.Offset]; ok {
		return o, nil
	}
	name := lib.Name + "(" + m.Name + ")"

	ext, err := m.Extent()
	if err != nil {
		return nil, &InputError{Name: name, Err: err}
	}
	head, err := ext.Head(sniffLen)
	if err != nil {
		return nil, &InputError{Name: name, Err: err}
	}
	if k := pe.KindOf(head); !k.IsObject() {
		// A short-import member is an import description rather than an
		// object, and implib turns it into symbols without ever
		// producing a coff.File. Reaching here with one means resolve
		// asked for the wrong thing — and reaching here with anything
		// else means the member is not a member this linker knows, which
		// is a different fact and says so.
		err := error(pe.ErrNotCOFF)
		if k == pe.KindShortImport {
			err = coff.ErrShortImport
		}
		return nil, &InputError{Name: name, Err: err}
	}

	f, err := coff.NewFile(ext)
	if err != nil {
		return nil, &InputError{Name: name, Err: err}
	}
	o := &Object{
		Name:    name,
		Path:    lib.Path,
		Machine: f.Machine,
		Origin:  lib.Origin,
		Lib:     lib,
		File:    f,
	}
	lib.fetched[m.Offset] = o
	l.registerObject(o)

	if err := l.applyDirectives(o); err != nil {
		return nil, err
	}
	// A directive in the member may have named a library nothing has
	// opened yet. Opening it here rather than deferring keeps the archive
	// fixpoint's input set complete at the moment it is re-searched.
	for len(l.pending) > 0 {
		name := l.pending[0]
		l.pending = l.pending[1:]
		if err := l.openLibrary(name, FromDirective); err != nil {
			return nil, err
		}
	}
	return o, nil
}