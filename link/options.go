package link

import (
	"strconv"
	"strings"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/image"
)

// link.exe never had linker scripts and neither does this. Everything a script
// would express is a field here or a setter on Linker.
//
// The Has* flags exist for the same reason they exist in def: zero is a legal
// value for every numeric field. An image base of zero is not "unset", it is a
// request the loader will refuse, and a stack reserve of zero is the same.
// Without the flags an emitter cannot tell a caller who said nothing from one
// who said zero, and the defaults would silently override explicit values.

// OutputKind is what the link produces. It decides the default entry point,
// the default image base, and whether the DLL characteristic is set.
type OutputKind uint8

const (
	// OutputEXE is an executable. It is the zero value because it is what a
	// link with no output kind stated means everywhere else.
	OutputEXE OutputKind = iota
	// OutputDLL is a dynamic-link library: IMAGE_FILE_DLL, a different
	// default base, and an entry point that may legitimately be absent.
	OutputDLL
	// OutputSYS is a driver. It is an EXE shape with the SYSTEM
	// characteristic and the native subsystem.
	OutputSYS
)

func (k OutputKind) String() string {
	switch k {
	case OutputDLL:
		return "dll"
	case OutputSYS:
		return "sys"
	}
	return "exe"
}

// ICFMode is the identical COMDAT folding level.
type ICFMode uint8

const (
	// ICFNone folds nothing.
	ICFNone ICFMode = iota
	// ICFSafe folds only chunks with no address-taken symbol. It is the
	// default, because ICFAll makes two distinct function pointers compare
	// equal and that breaks C++ code relying on function-pointer identity.
	ICFSafe
	// ICFAll folds every chunk whose bytes and relocations match. This is
	// the documented link.exe behaviour and it is not safe; it is offered
	// because a build that has audited for it gets real size back.
	ICFAll
)

func (m ICFMode) String() string {
	switch m {
	case ICFSafe:
		return "safe"
	case ICFAll:
		return "all"
	}
	return "none"
}

// GuardMode is the Control Flow Guard level.
type GuardMode uint8

const (
	GuardNone GuardMode = iota
	// GuardCF builds the GFIDS and longjmp tables and sets the load
	// config's flags. It requires /DYNAMICBASE: CFG depends on the loader
	// relocating the image, so the combination with DynamicBase cleared is
	// ErrGuardWithoutDynamicBase rather than a flag that quietly does
	// nothing.
	GuardCF
	// GuardEHCont adds the EH continuation table, from .gehcont$y.
	GuardEHCont
)

// ManifestMode is what happens to the application manifest.
type ManifestMode uint8

const (
	ManifestNone ManifestMode = iota
	// ManifestEmbed places the manifest in .rsrc as RT_MANIFEST.
	ManifestEmbed
	// ManifestExternal writes it beside the image. link reserves the name
	// and does not write the file; that is the caller's, since this package
	// returns an image rather than touching the filesystem.
	ManifestExternal
)

// Merge is one /MERGE:from=to request.
type Merge struct{ From, To string }

// SectionOverride is one /SECTION:name,attrs request: an explicit protection
// for an output section, replacing whatever its contributions implied.
type SectionOverride struct {
	Name string
	Prot pe.SecProt
}

// AlternateName is one /ALTERNATENAME:from=to request: if From is still
// undefined when every archive has been searched, it resolves to To.
//
// It is evaluated with the weak externals and for the same reason — an
// alternate that is taken eagerly makes command-line order decide the answer.
type AlternateName struct{ From, To string }

// Options is everything the link needs that is not an input.
//
// Target at its zero value is an error rather than a default. A link silently
// performed for x86 because nobody said otherwise fails three steps later with
// nothing pointing back here.
type Options struct {
	Target pe.Target
	Kind   OutputKind

	// Subsystem and its version. An unset subsystem takes the default for
	// the target's OS: console for Windows, EFI application for UEFI.
	Subsystem        pe.Subsystem
	SubsystemVersion pe.Version

	// Entry is the entry point symbol. An empty one takes the default for
	// the ABI and output kind — see DefaultEntry, which is a best effort
	// and not a guarantee.
	Entry string

	// ImageBase is the preferred load address, a multiple of 64K. Unset
	// takes the conventional default for the width and output kind.
	ImageBase    pe.VA
	HasImageBase bool

	// SectionAlignment and FileAlignment. Unset takes 0x1000 and 0x200 for
	// Windows, and 0x20 for both under UEFI — which is the flat-image mode,
	// in which a section's file offset must equal its RVA.
	SectionAlignment    uint32
	FileAlignment       uint32
	HasSectionAlignment bool
	HasFileAlignment    bool

	StackReserve, StackCommit uint64
	HeapReserve, HeapCommit   uint64
	HasStack, HasHeap         bool

	DllChar   pe.DllChar
	FileChar  pe.FileChar
	OSVersion pe.Version
	ImageVer  pe.Version

	// TimeStamp is written verbatim into the COFF header. Zero is the
	// deterministic choice and this tree's default; link.exe's /Brepro
	// writes 0xffffffff.
	TimeStamp uint32

	// Stub is the MS-DOS stub, replacing the minimal one. Its length feeds
	// SizeOfHeaders, which feeds the first section's RVA — which is why
	// /STUB changes every address in the image.
	Stub []byte

	// NumDataDirs is how many data directories the optional header carries.
	// Zero means the conventional sixteen.
	NumDataDirs int

	OptRef  bool
	OptICF  ICFMode
	Guard   GuardMode

	// SafeSEH requests x86's SafeSEH table. There is no setter yet: see
	// loadConfig.safeSEH in loadcfg.go.
	SafeSEH bool

	// DelayUnload controls whether the delay-load descriptors carry the
	// copy of the original IAT that __FUnloadDelayLoadedDLL2 restores. It
	// exists because the copy is what makes unloading work at all, and it
	// costs a table nobody who never unloads will read.
	DelayUnload bool

	// Strict turns warnings this tree considers dangerous into errors. The
	// ARM64X missing-__chpe_metadata case is the one that matters: an image
	// without it links and does not dispatch correctly.
	Strict bool

	// TruncateNames truncates image section names longer than eight bytes
	// instead of failing. An image has no string table, so the escape an
	// object would use does not exist; link.exe truncates and this tree
	// errors, because a silently renamed section is one nobody can find
	// again.
	TruncateNames bool

	// LibPaths are searched, in order, for a library named without a path.
	// There is no implicit path and no LIB environment variable: a build
	// that depends on ambient state is one that works on one machine.
	LibPaths []string

	// DefaultLibs and NoDefaultLibs accumulate /DEFAULTLIB and
	// /NODEFAULTLIB. NoDefaultLibAll is /NODEFAULTLIB with no argument,
	// which overrides every default library rather than one.
	//
	// A name in NoDefaultLibs beats the same name in DefaultLibs, and beats
	// a /DEFAULTLIB arriving later from inside a .drectve. Honouring the
	// exclusion only at the command line is how a link ends up with two
	// C runtimes and a page of duplicate symbols.
	DefaultLibs     []string
	NoDefaultLibs   []string
	NoDefaultLibAll bool

	Includes       []string
	AlternateNames []AlternateName
	Merges         []Merge
	Sections       []SectionOverride
	SectionOrder   []string
	Exports        []pe.Export
	DelayLoads     []string
	AlignComm      map[string]int

	Manifest     ManifestMode
	ManifestData []byte

	// ModuleName is the name a DLL reports as its own in the export
	// directory. It need not match the output filename — see outputName.
	ModuleName string

	// PDBPath is the path a debugger looks for symbols at, embedded in the
	// CodeView debug directory entry. This package never writes a PDB —
	// unset, the entry still names one, matching what every current
	// toolchain does even when nothing at that path exists yet.
	PDBPath string

	// CETCompat sets IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT. It asserts
	// that the image's indirect branches only ever target instructions
	// that begin a valid Intel CET shadow-stack frame — a claim about the
	// object code, not something this linker can verify from the outside.
	// Setting it on ordinary code is not a no-op: the loader turns on
	// shadow-stack enforcement for the process on the strength of this bit
	// alone.
	CETCompat bool
}

// Conventional image bases. An EXE and a DLL differ because a DLL is the one
// that will routinely be rebased, and the values are what link.exe uses.
const (
	DefaultBaseEXE32 = 0x0000_0000_0040_0000
	DefaultBaseEXE64 = 0x0000_0001_4000_0000
	DefaultBaseDLL32 = 0x0000_0000_1000_0000
	DefaultBaseDLL64 = 0x0000_0001_8000_0000
)

// Default alignments. The UEFI pair is equal and below a page, which is what
// image.Config.Flat reports on and what forces a section's file offset to
// equal its RVA.
const (
	DefaultSectionAlign = 0x1000
	DefaultFileAlign    = 0x200
	DefaultFlatAlign    = 0x20
)

// Base returns the image base this link will use.
func (o *Options) Base() pe.VA {
	if o.HasImageBase {
		return o.ImageBase
	}
	if o.Target.Width() == pe.Width64 {
		if o.Kind == OutputDLL {
			return DefaultBaseDLL64
		}
		return DefaultBaseEXE64
	}
	if o.Kind == OutputDLL {
		return DefaultBaseDLL32
	}
	return DefaultBaseEXE32
}

// Alignments returns the section and file alignments this link will use.
func (o *Options) Alignments() (section, file uint32) {
	section, file = DefaultSectionAlign, DefaultFileAlign
	if o.Target.OS == pe.OSUEFI {
		section, file = DefaultFlatAlign, DefaultFlatAlign
	}
	if o.HasSectionAlignment {
		section = o.SectionAlignment
	}
	if o.HasFileAlignment {
		file = o.FileAlignment
	}
	return section, file
}

// Sub returns the subsystem this link will use.
func (o *Options) Sub() pe.Subsystem {
	if o.Subsystem != pe.SubsystemUnknown {
		return o.Subsystem
	}
	if o.Target.OS == pe.OSUEFI {
		return pe.SubsystemEFIApplication
	}
	if o.Kind == OutputSYS {
		return pe.SubsystemNative
	}
	return pe.SubsystemConsole
}

// DefaultEntry returns the entry point symbol for the ABI, output kind, and
// subsystem, or "" when there is no sensible default.
//
// This is a best effort and deliberately not a guarantee. The real entry point
// is whatever the CRT supplies, the CRT is chosen by a /DEFAULTLIB nobody
// wrote down, and the two ABIs disagree about the decoration. A link whose
// entry cannot be resolved fails with ErrNoEntry and the answer is /ENTRY.
func (o *Options) DefaultEntry() string {
	i386 := o.Target.Machine == pe.MachineI386
	switch {
	case o.Kind == OutputDLL:
		if o.Target.ABI == pe.ABIMinGW {
			if i386 {
				// The decoration is __stdcall's: twelve bytes of
				// arguments, which is DllMain's signature.
				return "_DllMainCRTStartup@12"
			}
			return "DllMainCRTStartup"
		}
		return "_DllMainCRTStartup"
	case o.Target.OS == pe.OSUEFI:
		// EFI has no CRT startup; the image entry is the application's
		// own, and the convention is not universal enough to guess.
		return ""
	case o.Sub() == pe.SubsystemGUI:
		if i386 && o.Target.ABI == pe.ABIMinGW {
			return "_WinMainCRTStartup"
		}
		return "WinMainCRTStartup"
	}
	if i386 && o.Target.ABI == pe.ABIMinGW {
		return "_mainCRTStartup"
	}
	return "mainCRTStartup"
}

// EntryName returns the configured entry point, or the default.
func (o *Options) EntryName() string {
	if o.Entry != "" {
		return o.Entry
	}
	return o.DefaultEntry()
}

// Excluded reports whether a library name is covered by /NODEFAULTLIB.
//
// The comparison folds case and ignores a missing .lib extension, because a
// /DEFAULTLIB directive writes "msvcrt" and a command line writes
// "msvcrt.lib" and they mean the same library. Comparing them literally is how
// an exclusion silently fails to exclude.
func (o *Options) Excluded(name string) bool {
	if o.NoDefaultLibAll {
		return true
	}
	want := libKey(name)
	for _, n := range o.NoDefaultLibs {
		if libKey(n) == want {
			return true
		}
	}
	return false
}

// libKey normalizes a library name for comparison: lower case, no directory,
// no .lib extension.
func libKey(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.ToLower(name)
	return strings.TrimSuffix(name, ".lib")
}

// config projects the options into the image's configuration.
//
// This is the one place the two describe the same thing, and it runs once at
// the start of Link. image.Config validates the alignments against the
// format's constraints, so an impossible combination fails here rather than
// producing a file the loader rejects.
func (o *Options) config() image.Config {
	section, file := o.Alignments()
	ndirs := o.NumDataDirs
	if ndirs == 0 {
		ndirs = pe.NumDataDirs
	}
	stub := uint32(len(o.Stub))
	if stub == 0 {
		stub = minimalStubSize
	}
	return image.Config{
		Target:           o.Target,
		ImageBase:        o.Base(),
		SectionAlignment: section,
		FileAlignment:    file,
		StubSize:         stub,
		NumDataDirs:      ndirs,
	}
}

// minimalStubSize is the stub emit writes when the caller supplies none: the
// 64-byte header with a do-nothing program. It is legal and several real
// toolchains emit one.
const minimalStubSize = 0x40

// The setters below are the whole of this linker's configuration surface.
// Each latches on a Linker that has already run, so a caller cannot quietly
// configure something after the fact and wonder why it had no effect.

func (l *Linker) SetOutputKind(k OutputKind) { l.set(func() { l.opt.Kind = k }) }
func (l *Linker) SetEntry(sym string)        { l.set(func() { l.opt.Entry = sym }) }
func (l *Linker) SetTimestamp(t uint32)      { l.set(func() { l.opt.TimeStamp = t }) }
func (l *Linker) SetStub(b []byte)           { l.set(func() { l.opt.Stub = b }) }
func (l *Linker) SetStrict(v bool)           { l.set(func() { l.opt.Strict = v }) }
func (l *Linker) SetOptRef(v bool)           { l.set(func() { l.opt.OptRef = v }) }
func (l *Linker) SetOptICF(m ICFMode)        { l.set(func() { l.opt.OptICF = m }) }
func (l *Linker) SetGuard(m GuardMode)       { l.set(func() { l.opt.Guard = m }) }
func (l *Linker) SetDelayUnload(v bool)      { l.set(func() { l.opt.DelayUnload = v }) }
func (l *Linker) SetTruncateNames(v bool)    { l.set(func() { l.opt.TruncateNames = v }) }
func (l *Linker) SetPDBPath(path string)     { l.set(func() { l.opt.PDBPath = path }) }
func (l *Linker) SetCETCompat(v bool)        { l.set(func() { l.opt.CETCompat = v }) }

func (l *Linker) SetSubsystem(s pe.Subsystem) { l.set(func() { l.opt.Subsystem = s }) }

// SetModuleName sets the name a DLL reports as its own in the export
// directory table, e.g. "mymath.dll". Unset, it defaults to "unnamed.dll".
func (l *Linker) SetModuleName(name string) { l.set(func() { l.opt.ModuleName = name }) }

func (l *Linker) SetSubsystemVersion(v pe.Version) {
	l.set(func() { l.opt.SubsystemVersion = v })
}

func (l *Linker) SetImageBase(base pe.VA) {
	l.set(func() { l.opt.ImageBase, l.opt.HasImageBase = base, true })
}

func (l *Linker) SetSectionAlignment(n uint32) {
	l.set(func() { l.opt.SectionAlignment, l.opt.HasSectionAlignment = n, true })
}

func (l *Linker) SetFileAlignment(n uint32) {
	l.set(func() { l.opt.FileAlignment, l.opt.HasFileAlignment = n, true })
}

func (l *Linker) SetStack(reserve, commit uint64) {
	l.set(func() { l.opt.StackReserve, l.opt.StackCommit, l.opt.HasStack = reserve, commit, true })
}

func (l *Linker) SetHeap(reserve, commit uint64) {
	l.set(func() { l.opt.HeapReserve, l.opt.HeapCommit, l.opt.HasHeap = reserve, commit, true })
}

func (l *Linker) SetDllCharacteristics(c pe.DllChar) { l.set(func() { l.opt.DllChar = c }) }

// SetSectionProt overrides an output section's memory protection, which is
// /SECTION's whole job. The content flags are not settable: they come from the
// contributions and changing them would change what the section is.
func (l *Linker) SetSectionProt(name string, prot pe.SecProt) {
	l.set(func() { l.opt.Sections = append(l.opt.Sections, SectionOverride{name, prot}) })
}

// MergeSections folds one output section into another.
//
// It is not only a size knob. With the loader's 96-section limit, a build with
// many /SECTION-named regions can fail to link without merges, which is why
// ErrTooManyImageSections names the sections it would merge if asked.
func (l *Linker) MergeSections(from, to string) {
	l.set(func() { l.opt.Merges = append(l.opt.Merges, Merge{from, to}) })
}

func (l *Linker) SetSectionOrder(order []string) {
	l.set(func() { l.opt.SectionOrder = append([]string(nil), order...) })
}

// Include forces a symbol to be resolved and kept, which is what makes it a
// sweep root as well as a resolution one.
func (l *Linker) Include(sym string) {
	l.set(func() { l.opt.Includes = append(l.opt.Includes, sym) })
}

// AlternateName records a fallback definition for a name that is never
// otherwise defined. It is evaluated last, with the weak externals.
func (l *Linker) AlternateName(from, to string) {
	l.set(func() { l.opt.AlternateNames = append(l.opt.AlternateNames, AlternateName{from, to}) })
}

func (l *Linker) SetDelayLoad(dll string) {
	l.set(func() { l.opt.DelayLoads = append(l.opt.DelayLoads, dll) })
}

func (l *Linker) SetManifest(m ManifestMode, data []byte) {
	l.set(func() { l.opt.Manifest, l.opt.ManifestData = m, data })
}

// Export records an export. /EXPORT, a .def, and __declspec(dllexport) — which
// arrives as a .drectve directive — all feed this one list.
func (l *Linker) Export(e pe.Export) {
	l.set(func() { l.opt.Exports = append(l.opt.Exports, e) })
}

// AlignComm raises the alignment of a common block. The largest request wins,
// which is the rule everywhere else common blocks are merged.
func (l *Linker) AlignComm(sym string, align int) {
	l.set(func() {
		if l.opt.AlignComm == nil {
			l.opt.AlignComm = make(map[string]int)
		}
		if align > l.opt.AlignComm[sym] {
			l.opt.AlignComm[sym] = align
		}
	})
}

// parseNumbers reads "reserve[,commit]" as /STACK and /HEAP spell it.
//
// The base is inferred from each literal, so 0x100000 and 1048576 both work —
// which matters because a directive written by hand uses hex and one written
// by a build system uses decimal, in the same link.
func parseNumbers(s string) (reserve, commit uint64, err error) {
	first, rest, hasCommit := strings.Cut(s, ",")
	reserve, err = strconv.ParseUint(strings.TrimSpace(first), 0, 64)
	if err != nil {
		return 0, 0, err
	}
	if hasCommit {
		commit, err = strconv.ParseUint(strings.TrimSpace(rest), 0, 64)
		if err != nil {
			return 0, 0, err
		}
	}
	return reserve, commit, nil
}

// subsystemNames maps the spellings /SUBSYSTEM accepts to their values.
var subsystemNames = map[string]pe.Subsystem{
	"CONSOLE":                 pe.SubsystemConsole,
	"WINDOWS":                 pe.SubsystemGUI,
	"NATIVE":                  pe.SubsystemNative,
	"POSIX":                   pe.SubsystemPosixConsole,
	"WINDOWSCE":               pe.SubsystemWindowsCEGUI,
	"EFI_APPLICATION":         pe.SubsystemEFIApplication,
	"EFI_BOOT_SERVICE_DRIVER": pe.SubsystemEFIBootDriver,
	"EFI_RUNTIME_DRIVER":      pe.SubsystemEFIRuntimeDriver,
	"EFI_ROM":                 pe.SubsystemEFIROM,
	"BOOT_APPLICATION":        pe.SubsystemWindowsBootApp,
}

// parseSubsystem reads "NAME[,major[.minor]]".
//
// The version half is not decoration: it sets MajorSubsystemVersion, which is
// how an image declares the lowest Windows it will load on, and a link that
// drops it produces a binary that refuses to start on the version it was
// built for.
func parseSubsystem(s string) (pe.Subsystem, pe.Version, bool, error) {
	name, ver, hasVer := strings.Cut(s, ",")
	sub, ok := subsystemNames[strings.ToUpper(strings.TrimSpace(name))]
	if !ok {
		return pe.SubsystemUnknown, pe.Version{}, false, ErrBadSubsystem
	}
	if !hasVer {
		return sub, pe.Version{}, false, nil
	}
	v, err := pe.ParseVersion(strings.TrimSpace(ver))
	if err != nil {
		return pe.SubsystemUnknown, pe.Version{}, false, err
	}
	return sub, v, true, nil
}
// Default versions and sizes for a Windows image, matching link.exe.
//
// The subsystem version is not decoration and not a nicety: the loader reads
// MajorSubsystemVersion to decide whether it knows how to run the image, and
// an image claiming 0.0 is refused outright with "not a valid Win32
// application" — before a single byte of it is mapped. 6.0 is Vista, which is
// what link.exe writes for x64 and below anything still supported.
//
// The stack and heap sizes are the same kind of fact. A thread whose stack
// reserve is zero has no stack, and the CRT startup that would have reported
// the problem is the code that cannot run without one.
const (
	DefaultOSVersionMajor        = 6
	DefaultSubsystemVersionMajor = 6
	DefaultStackReserve          = 0x100000
	DefaultStackCommit           = 0x1000
	DefaultHeapReserve           = 0x100000
	DefaultHeapCommit            = 0x1000
)

// SubVersion returns the subsystem version this link will write.
//
// UEFI keeps the zero: a firmware image is loaded by firmware, which does not
// consult it, and link.exe writes 0.0 there for exactly that reason.
func (o *Options) SubVersion() pe.Version {
	if o.SubsystemVersion != (pe.Version{}) || o.Target.OS == pe.OSUEFI {
		return o.SubsystemVersion
	}
	return pe.Version{Major: DefaultSubsystemVersionMajor}
}

// OSVer returns the operating system version this link will write.
func (o *Options) OSVer() pe.Version {
	if o.OSVersion != (pe.Version{}) || o.Target.OS == pe.OSUEFI {
		return o.OSVersion
	}
	return pe.Version{Major: DefaultOSVersionMajor}
}

// Stack returns the stack reserve and commit this link will write.
func (o *Options) Stack() (reserve, commit uint64) {
	if o.HasStack || o.Target.OS == pe.OSUEFI {
		return o.StackReserve, o.StackCommit
	}
	return DefaultStackReserve, DefaultStackCommit
}

// Heap returns the heap reserve and commit this link will write.
func (o *Options) Heap() (reserve, commit uint64) {
	if o.HasHeap || o.Target.OS == pe.OSUEFI {
		return o.HeapReserve, o.HeapCommit
	}
	return DefaultHeapReserve, DefaultHeapCommit
}
