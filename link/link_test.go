package link_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/coff"
	"github.com/vertex-language/pe/implib"
	"github.com/vertex-language/pe/link"

	_ "github.com/vertex-language/pe/x64"
)

func target(t *testing.T) pe.Target {
	t.Helper()
	tgt, err := pe.ParseTarget("x86_64-pc-windows-msvc")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	return tgt
}

// buildObject writes a minimal AMD64 object defining "entry": mov eax,42; ret.
func buildObject(t *testing.T, tgt pe.Target) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := coff.NewWriter(&buf, coff.Options{Target: tgt})
	text := w.Section(coff.SectionHeader{
		Name: ".text", Kind: pe.SecCode, Prot: pe.SecExecute | pe.SecRead, Align: 16,
	})
	text.Write([]byte{0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3}) // mov eax, 42; ret
	w.Symbol(coff.SymbolDef{
		Name: "entry", Section: text, Value: 0,
		Class: pe.ClassExternal, Type: pe.PackSymType(pe.BaseNull, pe.DerivedFunction),
	})
	if err := w.Close(); err != nil {
		t.Fatalf("coff.Writer.Close: %v", err)
	}
	return buf.Bytes()
}

// TestLinkExecutable exercises the whole pipeline end to end: an object with
// no imports at all, linked to a console EXE. It is the regression test for
// the wiring bugs the pipeline had before it was ever run once: duplicate
// method declarations that kept the package from building, an Object with no
// chunks/tab/resolved fields, a wrapMember call with nothing behind it, and a
// sortGroups signature that could not accept what merge built.
func TestLinkExecutable(t *testing.T) {
	tgt := target(t)
	l, err := link.New(tgt)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()

	if err := l.AddObject("t.obj", buildObject(t, tgt)); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	l.SetSubsystem(pe.SubsystemConsole)
	l.SetEntry("entry")
	l.SetOutputKind(link.OutputEXE)

	img, err := l.Link()
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	out, err := img.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("Bytes returned nothing")
	}

	checkWithPefile(t, out, func(info pefileInfo) {
		if !info.ChecksumOK {
			t.Errorf("checksum mismatch: stored %s, computed %s", info.Checksum, info.ComputedChecksum)
		}
		if info.Machine != "0x8664" {
			t.Errorf("Machine = %s, want 0x8664 (AMD64)", info.Machine)
		}
		if info.Subsystem != 3 {
			t.Errorf("Subsystem = %d, want 3 (console)", info.Subsystem)
		}
	})
}

// TestLinkWithDebugDirectory checks the debug data directory this package
// always writes: a CodeView record naming a PDB and a repro hash, verified
// against the independent pefile library rather than this package's own
// notion of what it wrote.
func TestLinkWithDebugDirectory(t *testing.T) {
	tgt := target(t)
	l, err := link.New(tgt)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()

	if err := l.AddObject("t.obj", buildObject(t, tgt)); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	l.SetSubsystem(pe.SubsystemConsole)
	l.SetEntry("entry")
	l.SetOutputKind(link.OutputEXE)
	l.SetPDBPath("out.pdb")

	img, err := l.Link()
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	out, err := img.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	checkWithPefile(t, out, func(info pefileInfo) {
		if len(info.DebugEntries) != 2 {
			t.Fatalf("DebugEntries = %v, want 2 (CodeView, Repro)", info.DebugEntries)
		}
		if info.DebugEntries[0].Type != 2 {
			t.Errorf("DebugEntries[0].Type = %d, want 2 (CODEVIEW)", info.DebugEntries[0].Type)
		}
		if info.DebugEntries[1].Type != 16 {
			t.Errorf("DebugEntries[1].Type = %d, want 16 (REPRO)", info.DebugEntries[1].Type)
		}
		if info.CVSignature != "0x53445352" {
			t.Errorf("CVSignature = %s, want 0x53445352 (RSDS)", info.CVSignature)
		}
		if info.PDBPath != "out.pdb" {
			t.Errorf("PDBPath = %q, want %q", info.PDBPath, "out.pdb")
		}
		if info.ExDllCharacteristics != -1 {
			t.Errorf("ExDllCharacteristics present without SetCETCompat: %#x", info.ExDllCharacteristics)
		}
	})
}

// TestLinkWithCETCompat checks that SetCETCompat adds a third debug
// directory entry carrying IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT.
func TestLinkWithCETCompat(t *testing.T) {
	tgt := target(t)
	l, err := link.New(tgt)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()

	if err := l.AddObject("t.obj", buildObject(t, tgt)); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	l.SetSubsystem(pe.SubsystemConsole)
	l.SetEntry("entry")
	l.SetOutputKind(link.OutputEXE)
	l.SetCETCompat(true)

	img, err := l.Link()
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	out, err := img.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	checkWithPefile(t, out, func(info pefileInfo) {
		if len(info.DebugEntries) != 3 {
			t.Fatalf("DebugEntries = %v, want 3 (CodeView, Repro, ExDllCharacteristics)", info.DebugEntries)
		}
		if info.DebugEntries[2].Type != 20 {
			t.Errorf("DebugEntries[2].Type = %d, want 20 (EX_DLLCHARACTERISTICS)", info.DebugEntries[2].Type)
		}
		if info.ExDllCharacteristics != 1 {
			t.Errorf("ExDllCharacteristics = %#x, want 0x1 (CET_COMPAT)", info.ExDllCharacteristics)
		}
	})
}

// TestBadSubsystemDirective checks that a /SUBSYSTEM directive naming
// something unrecognized fails with ErrBadSubsystem rather than
// ErrUnimplemented — the two mean different things (a typo in the input
// versus a linker feature this tree does not have), and a caller matching
// one with errors.Is should not get the other.
func TestBadSubsystemDirective(t *testing.T) {
	tgt := target(t)
	var buf bytes.Buffer
	w := coff.NewWriter(&buf, coff.Options{Target: tgt})
	text := w.Section(coff.SectionHeader{
		Name: ".text", Kind: pe.SecCode, Prot: pe.SecExecute | pe.SecRead, Align: 16,
	})
	text.Write([]byte{0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3})
	w.Symbol(coff.SymbolDef{
		Name: "entry", Section: text, Value: 0,
		Class: pe.ClassExternal, Type: pe.PackSymType(pe.BaseNull, pe.DerivedFunction),
	})
	w.Directive("SUBSYSTEM", "BOGUS")
	if err := w.Close(); err != nil {
		t.Fatalf("coff.Writer.Close: %v", err)
	}

	l, err := link.New(tgt)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()
	if err := l.AddObject("t.obj", buf.Bytes()); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	l.SetEntry("entry")
	l.SetOutputKind(link.OutputEXE)

	_, err = l.Link()
	if !errors.Is(err, link.ErrBadSubsystem) {
		t.Errorf("Link with /SUBSYSTEM:BOGUS: err = %v, want ErrBadSubsystem", err)
	}
	if errors.Is(err, link.ErrUnimplemented) {
		t.Errorf("Link with /SUBSYSTEM:BOGUS: err also matches ErrUnimplemented, want only ErrBadSubsystem")
	}
}

// TestSetDelayLoadFailsRatherThanSilentlyDoingNothing checks that requesting
// a delay-loaded DLL fails the link instead of silently producing an image
// with no delay-load table at all. SetDelayLoad is a real, reachable public
// method; nothing downstream of it ever reads l.opt.DelayLoads, which
// without this guard is indistinguishable from success until the image runs
// and the delay-load thunk that was never linked in doesn't exist.
func TestSetDelayLoadFailsRatherThanSilentlyDoingNothing(t *testing.T) {
	tgt := target(t)
	l, err := link.New(tgt)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()

	if err := l.AddObject("t.obj", buildObject(t, tgt)); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	l.SetSubsystem(pe.SubsystemConsole)
	l.SetEntry("entry")
	l.SetOutputKind(link.OutputEXE)
	l.SetDelayLoad("plugin.dll")

	if _, err := l.Link(); err == nil {
		t.Fatal("Link succeeded with a delay-load requested; want an error until delay-load generation exists")
	}
}

// TestSetDelayUnloadFailsRatherThanSilentlyDoingNothing checks the same
// silent-no-op failure mode as TestSetDelayLoadFailsRatherThanSilentlyDoingNothing,
// but for SetDelayUnload called on its own: DelayUnload only means anything as
// a field of the MS-format delay-load descriptor synth() does not build, and
// a GNU delay-import archive's descriptor comes from dlltool's own object
// bytes rather than anything this field could reach.
func TestSetDelayUnloadFailsRatherThanSilentlyDoingNothing(t *testing.T) {
	tgt := target(t)
	l, err := link.New(tgt)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()

	if err := l.AddObject("t.obj", buildObject(t, tgt)); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	l.SetSubsystem(pe.SubsystemConsole)
	l.SetEntry("entry")
	l.SetOutputKind(link.OutputEXE)
	l.SetDelayUnload(true)

	if _, err := l.Link(); err == nil {
		t.Fatal("Link succeeded with SetDelayUnload(true) and no delay-loaded DLL; want an error")
	}
}

// TestLinkWithMSImportLibrary links an object that calls through an imported
// data symbol (__imp_ExitProcess) against an import library this package's
// own implib.Write produces, and checks the resulting import directory is
// not just present but actually resolves the right DLL and symbol — the
// regression test for two real bugs the pipeline had: the import and IAT
// data directories were never registered (im.Dirs returned nil because
// nothing populated im.rest/im.iat under this exact path), and
// decodeImport's call to implib.Read needed a whole archive, not the single
// member resolve had in hand, which is what wrapMember exists for.
func TestLinkWithMSImportLibrary(t *testing.T) {
	tgt := target(t)

	var buf bytes.Buffer
	w := coff.NewWriter(&buf, coff.Options{Target: tgt})
	text := w.Section(coff.SectionHeader{
		Name: ".text", Kind: pe.SecCode, Prot: pe.SecExecute | pe.SecRead, Align: 16,
	})
	// mov ecx, 42 ; call qword ptr [rip+__imp_ExitProcess]
	text.Write([]byte{
		0xB9, 0x2A, 0x00, 0x00, 0x00,
		0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
	})
	w.Symbol(coff.SymbolDef{
		Name: "entry", Section: text, Value: 0,
		Class: pe.ClassExternal, Type: pe.PackSymType(pe.BaseNull, pe.DerivedFunction),
	})
	impSym := w.Symbol(coff.SymbolDef{Name: "__imp_ExitProcess", Class: pe.ClassExternal})
	w.Reloc(text, coff.RelocSpec{Address: 7, Sym: impSym, Type: uint16(pe.IMAGE_REL_AMD64_REL32)})
	if err := w.Close(); err != nil {
		t.Fatalf("coff.Writer.Close: %v", err)
	}

	var lib bytes.Buffer
	if err := implib.Write(&lib, implib.Options{Target: tgt, DLL: "KERNEL32.dll"},
		[]pe.Export{{Name: "ExitProcess"}}); err != nil {
		t.Fatalf("implib.Write: %v", err)
	}

	l, err := link.New(tgt)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()
	if err := l.AddObject("t.obj", buf.Bytes()); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	if err := l.AddArchive("kernel32.lib", lib.Bytes()); err != nil {
		t.Fatalf("AddArchive: %v", err)
	}
	l.SetSubsystem(pe.SubsystemConsole)
	l.SetEntry("entry")
	l.SetOutputKind(link.OutputEXE)

	img, err := l.Link()
	if err != nil {
		t.Fatalf("Link: %v", err)
	}

	rva, size, err := img.Dirs.Dir(pe.DirImport)
	if err != nil {
		t.Fatalf("Dirs.Dir(DirImport): %v", err)
	}
	if rva == 0 || size == 0 {
		t.Fatal("the import directory was never registered")
	}
	iatRVA, iatSize, err := img.Dirs.Dir(pe.DirIAT)
	if err != nil {
		t.Fatalf("Dirs.Dir(DirIAT): %v", err)
	}
	if iatRVA == 0 || iatSize == 0 {
		t.Fatal("the IAT directory was never registered")
	}

	out, err := img.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	checkWithPefile(t, out, func(info pefileInfo) {
		if !info.ChecksumOK {
			t.Errorf("checksum mismatch: stored %s, computed %s", info.Checksum, info.ComputedChecksum)
		}
		if len(info.Imports) != 1 {
			t.Fatalf("got %d import entries, want 1: %+v", len(info.Imports), info.Imports)
		}
		imp := info.Imports[0]
		if imp.DLL != "KERNEL32.dll" {
			t.Errorf("import DLL = %q, want KERNEL32.dll", imp.DLL)
		}
		if len(imp.Names) != 1 || imp.Names[0] != "ExitProcess" {
			t.Errorf("imported names = %v, want [ExitProcess]", imp.Names)
		}
	})
}

// TestLinkWithGNUImportLibrary links against a real dlltool-generated
// multi-symbol .dll.a — three exports, so the import group has a head
// object, three per-symbol objects, and a tail object, all pulled in by
// resolution rather than declared in archive order.
//
// It is the regression test for the .idata$4/.idata$5 ordering bug: dlltool's
// head object forces its tail into the link as soon as the head itself is
// referenced, which used to place the zero terminator ahead of one or more
// real thunk slots in the merged section — a loader walking the table then
// stopped at the premature zero and never saw every import that followed it.
// pefile parses the whole table the same way a loader walks it, so a run
// that used to silently drop Sub and Mul now fails here instead of only at
// load time on real Windows.
func TestLinkWithGNUImportLibrary(t *testing.T) {
	gcc, err := exec.LookPath("x86_64-w64-mingw32-gcc")
	if err != nil {
		t.Skip("x86_64-w64-mingw32-gcc not found on PATH")
	}
	dlltool, err := exec.LookPath("x86_64-w64-mingw32-dlltool")
	if err != nil {
		t.Skip("x86_64-w64-mingw32-dlltool not found on PATH")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found on PATH")
	}
	if err := exec.Command(python, "-c", "import pefile").Run(); err != nil {
		t.Skip("pefile module not installed (pip install pefile)")
	}

	dir := t.TempDir()
	defPath := dir + "/mymath.def"
	libPath := dir + "/libmymath.dll.a"
	mainPath := dir + "/main.o"

	if err := os.WriteFile(defPath, []byte("LIBRARY mymath.dll\nEXPORTS\nAdd\nSub\nMul\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(def): %v", err)
	}
	if out, err := exec.Command(dlltool, "-d", defPath, "-l", libPath, "-D", "mymath.dll").CombinedOutput(); err != nil {
		t.Fatalf("dlltool: %v\n%s", err, out)
	}

	const mainSrc = `
extern int Add(int, int);
extern int Sub(int, int);
extern int Mul(int, int);
int entry(void) { return Add(1, 2) + Sub(3, 4) + Mul(5, 6); }
`
	cmd := exec.Command(gcc, "-c", "-o", mainPath, "-x", "c", "-")
	cmd.Stdin = strings.NewReader(mainSrc)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc: %v\n%s", err, out)
	}

	mainObj, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("ReadFile(main.o): %v", err)
	}
	lib, err := os.ReadFile(libPath)
	if err != nil {
		t.Fatalf("ReadFile(libmymath.dll.a): %v", err)
	}

	tgt := target(t)
	l, err := link.New(tgt)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()
	if err := l.AddObject("main.o", mainObj); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	if err := l.AddArchive("libmymath.dll.a", lib); err != nil {
		t.Fatalf("AddArchive: %v", err)
	}
	l.SetSubsystem(pe.SubsystemConsole)
	l.SetEntry("entry")
	l.SetOutputKind(link.OutputEXE)

	img, err := l.Link()
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	out, err := img.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	checkWithPefile(t, out, func(info pefileInfo) {
		if len(info.Imports) != 1 {
			t.Fatalf("got %d import entries, want 1: %+v", len(info.Imports), info.Imports)
		}
		imp := info.Imports[0]
		if imp.DLL != "mymath.dll" {
			t.Errorf("import DLL = %q, want mymath.dll", imp.DLL)
		}
		want := map[string]bool{"Add": true, "Sub": true, "Mul": true}
		got := map[string]bool{}
		for _, n := range imp.Names {
			got[n] = true
		}
		for n := range want {
			if !got[n] {
				t.Errorf("imported names = %v, missing %q", imp.Names, n)
			}
		}
		if len(imp.Names) != len(want) {
			t.Errorf("imported names = %v, want exactly %v", imp.Names, want)
		}
	})
}

// TestLinkWithOwnGNUImportLibrary links against an import library this
// package's own implib.Write produces in the GNU (MinGW) shape, rather than
// one dlltool generated — the end-to-end check that writeGNU's object
// layout is not just readable by this package's own resolver (which
// TestLinkWithGNUImportLibrary already establishes against a real dlltool
// archive) but also produces a working import table when this package is
// the one writing every byte of it.
//
// The importing object is still real gcc output: this exercises the
// x64-registered ABI path, so the only thing this test's own code writes is
// the import library.
func TestLinkWithOwnGNUImportLibrary(t *testing.T) {
	gcc, err := exec.LookPath("x86_64-w64-mingw32-gcc")
	if err != nil {
		t.Skip("x86_64-w64-mingw32-gcc not found on PATH")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found on PATH")
	}
	if err := exec.Command(python, "-c", "import pefile").Run(); err != nil {
		t.Skip("pefile module not installed (pip install pefile)")
	}

	gnuTgt, err := pe.ParseTarget("x86_64-w64-windows-gnu")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	var lib bytes.Buffer
	if err := implib.Write(&lib, implib.Options{Target: gnuTgt, DLL: "mymath.dll"}, []pe.Export{
		{Name: "Add"}, {Name: "Sub"}, {Name: "Mul"},
	}); err != nil {
		t.Fatalf("implib.Write: %v", err)
	}

	dir := t.TempDir()
	mainPath := dir + "/main.o"
	cmd := exec.Command(gcc, "-c", "-o", mainPath, "-x", "c", "-")
	cmd.Stdin = strings.NewReader(`
extern int Add(int, int);
extern int Sub(int, int);
extern int Mul(int, int);
int entry(void) { return Add(1, 2) + Sub(3, 4) + Mul(5, 6); }
`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc: %v\n%s", err, out)
	}
	mainObj, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("ReadFile(main.o): %v", err)
	}

	tgt := target(t)
	l, err := link.New(tgt)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()
	if err := l.AddObject("main.o", mainObj); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	if err := l.AddArchive("libmymath.dll.a", lib.Bytes()); err != nil {
		t.Fatalf("AddArchive: %v", err)
	}
	l.SetSubsystem(pe.SubsystemConsole)
	l.SetEntry("entry")
	l.SetOutputKind(link.OutputEXE)

	img, err := l.Link()
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	out, err := img.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	checkWithPefile(t, out, func(info pefileInfo) {
		if len(info.Imports) != 1 {
			t.Fatalf("got %d import entries, want 1: %+v", len(info.Imports), info.Imports)
		}
		imp := info.Imports[0]
		if imp.DLL != "mymath.dll" {
			t.Errorf("import DLL = %q, want mymath.dll", imp.DLL)
		}
		want := map[string]bool{"Add": true, "Sub": true, "Mul": true}
		got := map[string]bool{}
		for _, n := range imp.Names {
			got[n] = true
		}
		for n := range want {
			if !got[n] {
				t.Errorf("imported names = %v, missing %q", imp.Names, n)
			}
		}
		if len(imp.Names) != len(want) {
			t.Errorf("imported names = %v, want exactly %v", imp.Names, want)
		}
	})
}

// TestLinkWithGNUDelayImportLibrary links against a real dlltool-generated
// delay-import archive (dlltool -y) plus a stub __delayLoadHelper2 — the
// actual resolver logic lives in mingw-w64's libdelayimp.a, which this
// package's linker has no more business supplying than it does a CRT
// startup routine, so a stub that satisfies the reference is enough to
// prove the data pe/link is actually responsible for is correct.
//
// dlltool's delay-import archive uses .didat$2 through .didat$7, the exact
// same convention as .idata$2 through .idata$7 one letter over, merged by
// the same $-group pipeline — including the same head/per-symbol/tail
// ordering hazard chunkRank already handles for regular imports. Dirs()'s
// GNU fallback in idata.go is what turns a plain .didat section into a
// registered DirDelayImport directory; without it the descriptor table
// would be correctly laid out and completely unreachable, which is exactly
// how the .idata case behaved before gnuImportDirs existed.
func TestLinkWithGNUDelayImportLibrary(t *testing.T) {
	gcc, err := exec.LookPath("x86_64-w64-mingw32-gcc")
	if err != nil {
		t.Skip("x86_64-w64-mingw32-gcc not found on PATH")
	}
	dlltool, err := exec.LookPath("x86_64-w64-mingw32-dlltool")
	if err != nil {
		t.Skip("x86_64-w64-mingw32-dlltool not found on PATH")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found on PATH")
	}
	if err := exec.Command(python, "-c", "import pefile").Run(); err != nil {
		t.Skip("pefile module not installed (pip install pefile)")
	}

	dir := t.TempDir()
	defPath := dir + "/mymath.def"
	libPath := dir + "/libmymath_delay.dll.a"
	mainPath := dir + "/main.o"
	stubPath := dir + "/delayhelper_stub.o"

	if err := os.WriteFile(defPath, []byte("LIBRARY mymath.dll\nEXPORTS\nAdd\nSub\nMul\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(def): %v", err)
	}
	if out, err := exec.Command(dlltool, "-d", defPath, "-y", libPath, "-D", "mymath.dll").CombinedOutput(); err != nil {
		t.Fatalf("dlltool -y: %v\n%s", err, out)
	}

	cmd := exec.Command(gcc, "-c", "-o", mainPath, "-x", "c", "-")
	cmd.Stdin = strings.NewReader(`
extern int Add(int, int);
extern int Sub(int, int);
extern int Mul(int, int);
int entry(void) { return Add(1, 2) + Sub(3, 4) + Mul(5, 6); }
`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc (main): %v\n%s", err, out)
	}

	cmd = exec.Command(gcc, "-c", "-o", stubPath, "-x", "c", "-")
	cmd.Stdin = strings.NewReader(`
void *__delayLoadHelper2(void *pidd, void **ppfnIATEntry) { return 0; }
`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc (stub): %v\n%s", err, out)
	}

	mainObj, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("ReadFile(main.o): %v", err)
	}
	stubObj, err := os.ReadFile(stubPath)
	if err != nil {
		t.Fatalf("ReadFile(stub.o): %v", err)
	}
	lib, err := os.ReadFile(libPath)
	if err != nil {
		t.Fatalf("ReadFile(libmymath_delay.dll.a): %v", err)
	}

	tgt := target(t)
	l, err := link.New(tgt)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()
	if err := l.AddObject("main.o", mainObj); err != nil {
		t.Fatalf("AddObject(main): %v", err)
	}
	if err := l.AddObject("delayhelper_stub.o", stubObj); err != nil {
		t.Fatalf("AddObject(stub): %v", err)
	}
	if err := l.AddArchive("libmymath_delay.dll.a", lib); err != nil {
		t.Fatalf("AddArchive: %v", err)
	}
	l.SetSubsystem(pe.SubsystemConsole)
	l.SetEntry("entry")
	l.SetOutputKind(link.OutputEXE)

	img, err := l.Link()
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	out, err := img.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	checkWithPefile(t, out, func(info pefileInfo) {
		if len(info.DelayImports) != 1 {
			t.Fatalf("got %d delay import entries, want 1: %+v", len(info.DelayImports), info.DelayImports)
		}
		imp := info.DelayImports[0]
		if imp.DLL != "mymath.dll" {
			t.Errorf("delay import DLL = %q, want mymath.dll", imp.DLL)
		}
		want := map[string]bool{"Add": true, "Sub": true, "Mul": true}
		got := map[string]bool{}
		for _, n := range imp.Names {
			got[n] = true
		}
		for n := range want {
			if !got[n] {
				t.Errorf("delay imported names = %v, missing %q", imp.Names, n)
			}
		}
	})
}

// TestLinkWithResources embeds a real windres-compiled .res (an icon and a
// string table) into a linked EXE and checks the resource data directory is
// registered and its contents parse — the regression test for link/rsrc.go's
// resources synthetic being fully written but never added to synth()'s
// pipeline, so AddResources always failed with ErrUnimplemented no matter
// what was passed to it.
func TestLinkWithResources(t *testing.T) {
	windres, err := exec.LookPath("x86_64-w64-mingw32-windres")
	if err != nil {
		t.Skip("x86_64-w64-mingw32-windres not found on PATH")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found on PATH")
	}
	if err := exec.Command(python, "-c", "import pefile").Run(); err != nil {
		t.Skip("pefile module not installed (pip install pefile)")
	}

	dir := t.TempDir()
	rcPath := dir + "/test.rc"
	icoPath := dir + "/dummy.ico"
	resPath := dir + "/test.res"
	if err := os.WriteFile(rcPath, []byte(`
1 ICON "dummy.ico"
STRINGTABLE
BEGIN
    1, "Hello, world!"
END
`), 0o644); err != nil {
		t.Fatalf("WriteFile(rc): %v", err)
	}
	// A minimal (barely valid) ICO: header plus one directory entry plus
	// padding, enough for windres to accept it without caring what the
	// image actually looks like.
	ico := append([]byte{
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x20, 0x20, 0x10, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x28, 0x01, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00,
	}, make([]byte, 300)...)
	if err := os.WriteFile(icoPath, ico, 0o644); err != nil {
		t.Fatalf("WriteFile(ico): %v", err)
	}
	if out, err := exec.Command(windres, rcPath, "-O", "res", "-o", resPath).CombinedOutput(); err != nil {
		t.Fatalf("windres failed: %v\n%s", err, out)
	}
	resData, err := os.ReadFile(resPath)
	if err != nil {
		t.Fatalf("ReadFile(res): %v", err)
	}

	tgt := target(t)
	l, err := link.New(tgt)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()
	if err := l.AddObject("t.obj", buildObject(t, tgt)); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	if err := l.AddResources(resData); err != nil {
		t.Fatalf("AddResources: %v", err)
	}
	l.SetSubsystem(pe.SubsystemConsole)
	l.SetEntry("entry")
	l.SetOutputKind(link.OutputEXE)

	img, err := l.Link()
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	rva, size, err := img.Dirs.Dir(pe.DirResource)
	if err != nil {
		t.Fatalf("Dirs.Dir(DirResource): %v", err)
	}
	if rva == 0 || size == 0 {
		t.Fatal("the resource directory was never registered")
	}

	out, err := img.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	checkWithPefile(t, out, func(info pefileInfo) {
		if !info.ChecksumOK {
			t.Errorf("checksum mismatch: stored %s, computed %s", info.Checksum, info.ComputedChecksum)
		}
		if len(info.ResourceTypes) == 0 {
			t.Error("pefile found no resource types in the linked image")
		}
	})
}

// pefileInfo is what checkWithPefile's helper script reports back, using the
// independent Python pefile library as an outside check on the linker's own
// output — the same role objdump/codesign play for the macho tree's tests.
type pefileInfo struct {
	Machine          string
	Subsystem        int
	Checksum         string
	ComputedChecksum string
	ChecksumOK       bool
	Imports          []struct {
		DLL   string
		Names []string
	}
	ResourceTypes []int
	DebugEntries  []struct {
		Type       int
		SizeOfData int
	}
	CVSignature          string
	PDBPath              string
	ExDllCharacteristics int
	DelayImports         []struct {
		DLL   string
		Names []string
	}
}

const pefileScript = `
import json, sys
import pefile
p = pefile.PE(sys.argv[1])
p.parse_data_directories()
out = {
    "Machine": hex(p.FILE_HEADER.Machine),
    "Subsystem": p.OPTIONAL_HEADER.Subsystem,
    "Checksum": hex(p.OPTIONAL_HEADER.CheckSum),
    "ComputedChecksum": hex(p.generate_checksum()),
    "ChecksumOK": p.OPTIONAL_HEADER.CheckSum == p.generate_checksum(),
    "Imports": [],
    "ResourceTypes": [],
    "DebugEntries": [],
    "CVSignature": "",
    "PDBPath": "",
    "ExDllCharacteristics": -1,
    "DelayImports": [],
}
for entry in getattr(p, "DIRECTORY_ENTRY_IMPORT", []):
    out["Imports"].append({
        "DLL": entry.dll.decode(),
        "Names": [i.name.decode() for i in entry.imports if i.name],
    })
for entry in getattr(p, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
    out["DelayImports"].append({
        "DLL": entry.dll.decode(),
        "Names": [i.name.decode() for i in entry.imports if i.name],
    })
for entry in getattr(getattr(p, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []):
    out["ResourceTypes"].append(entry.id if entry.id is not None else -1)
for entry in getattr(p, "DIRECTORY_ENTRY_DEBUG", []):
    st = entry.struct
    out["DebugEntries"].append({"Type": st.Type, "SizeOfData": st.SizeOfData})
    data = p.get_data(st.AddressOfRawData, st.SizeOfData)
    if st.Type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
        out["CVSignature"] = hex(int.from_bytes(data[0:4], "little"))
        path = data[24:]
        nul = path.find(b"\x00")
        if nul >= 0:
            path = path[:nul]
        out["PDBPath"] = path.decode(errors="replace")
    elif st.Type == 20:  # IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
        out["ExDllCharacteristics"] = int.from_bytes(data[0:4], "little")
print(json.dumps(out))
`

// checkWithPefile writes out to a temp file and runs it through the
// independent Python "pefile" library, skipping the test if python3 or the
// pefile module is not available on this machine.
func checkWithPefile(t *testing.T, out []byte, check func(pefileInfo)) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found on PATH")
	}
	if err := exec.Command(python, "-c", "import pefile").Run(); err != nil {
		t.Skip("pefile module not installed (pip install pefile)")
	}

	dir := t.TempDir()
	exePath := dir + "/out.exe"
	if err := os.WriteFile(exePath, out, 0o644); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	scriptPath := dir + "/check.py"
	if err := os.WriteFile(scriptPath, []byte(pefileScript), 0o644); err != nil {
		t.Fatalf("writeFile: %v", err)
	}

	cmd := exec.Command(python, scriptPath, exePath)
	stdout, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("pefile check failed: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("pefile check failed: %v", err)
	}

	var info pefileInfo
	if err := json.Unmarshal(stdout, &info); err != nil {
		t.Fatalf("decoding pefile output: %v\n%s", err, stdout)
	}
	check(info)
}

// namedObject is buildObject with the entry symbol named by the caller, so a
// test can say which of the CRT's four entry points the program is written
// for.
func namedObject(t *testing.T, tgt pe.Target, sym string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := coff.NewWriter(&buf, coff.Options{Target: tgt})
	text := w.Section(coff.SectionHeader{
		Name: ".text", Kind: pe.SecCode, Prot: pe.SecExecute | pe.SecRead, Align: 16,
	})
	text.Write([]byte{0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3}) // mov eax, 42; ret
	w.Symbol(coff.SymbolDef{
		Name: sym, Section: text, Value: 0,
		Class: pe.ClassExternal, Type: pe.PackSymType(pe.BaseNull, pe.DerivedFunction),
	})
	if err := w.Close(); err != nil {
		t.Fatalf("coff.Writer.Close: %v", err)
	}
	return buf.Bytes()
}

// TestEntryInferredFromProgram: the CRT supplies four entry points and which
// one an image wants is not on the command line — the program says it by
// which function it defines. A linker that always reaches for mainCRTStartup
// tells a GUI program it has no main, which is a symbol it never mentioned.
//
// The startup routine itself is not present here, so linking cannot finish;
// what the test reads is which name the link went looking for, and the
// subsystem that came with it.
func TestEntryInferredFromProgram(t *testing.T) {
	for _, c := range []struct {
		def   string
		start string
		sub   pe.Subsystem
	}{
		{"main", "mainCRTStartup", pe.SubsystemConsole},
		{"wmain", "wmainCRTStartup", pe.SubsystemConsole},
		{"WinMain", "WinMainCRTStartup", pe.SubsystemGUI},
		{"wWinMain", "wWinMainCRTStartup", pe.SubsystemGUI},
	} {
		t.Run(c.def, func(t *testing.T) {
			tgt := target(t)
			l, err := link.New(tgt)
			if err != nil {
				t.Fatalf("link.New: %v", err)
			}
			defer l.Close()
			if err := l.AddObject("t.obj", namedObject(t, tgt, c.def)); err != nil {
				t.Fatalf("AddObject: %v", err)
			}
			l.SetOutputKind(link.OutputEXE)

			_, err = l.Link()
			if err == nil {
				t.Fatalf("linked with no %s in the input", c.start)
			}
			if !strings.Contains(err.Error(), c.start) {
				t.Errorf("Link: %v, want it to have looked for %q", err, c.start)
			}
		})
	}
}

// An explicit /ENTRY says the caller has already decided, and the inference
// stays out of it.
func TestExplicitEntryWinsOverInference(t *testing.T) {
	tgt := target(t)
	l, err := link.New(tgt)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()
	if err := l.AddObject("t.obj", namedObject(t, tgt, "WinMain")); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	l.SetOutputKind(link.OutputEXE)
	l.SetEntry("WinMain")

	if _, err := l.Link(); err != nil {
		t.Fatalf("Link: %v", err)
	}
}

// TestSubsystemFollowsEntry: inferring the entry point settles the subsystem
// with it, because the two are one decision. A GUI image that came out
// marked console opens a console window nobody asked for.
//
// Both symbols are in the object here — the program's and the CRT's — so the
// link finishes and the header can be read.
func TestSubsystemFollowsEntry(t *testing.T) {
	for _, c := range []struct {
		def, start string
		want       int
	}{
		{"main", "mainCRTStartup", 3},
		{"WinMain", "WinMainCRTStartup", 2},
	} {
		t.Run(c.def, func(t *testing.T) {
			tgt := target(t)
			l, err := link.New(tgt)
			if err != nil {
				t.Fatalf("link.New: %v", err)
			}
			defer l.Close()
			if err := l.AddObject("t.obj", twoSymObject(t, tgt, c.def, c.start)); err != nil {
				t.Fatalf("AddObject: %v", err)
			}
			l.SetOutputKind(link.OutputEXE)

			img, err := l.Link()
			if err != nil {
				t.Fatalf("Link: %v", err)
			}
			out, err := img.Bytes()
			if err != nil {
				t.Fatalf("Bytes: %v", err)
			}
			if got := subsystemOf(t, out); got != c.want {
				t.Errorf("Subsystem = %d, want %d", got, c.want)
			}
		})
	}
}

// twoSymObject defines two names over one body: the program's entry point
// and the CRT startup that would call it.
func twoSymObject(t *testing.T, tgt pe.Target, a, b string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := coff.NewWriter(&buf, coff.Options{Target: tgt})
	text := w.Section(coff.SectionHeader{
		Name: ".text", Kind: pe.SecCode, Prot: pe.SecExecute | pe.SecRead, Align: 16,
	})
	text.Write([]byte{0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3}) // mov eax, 42; ret
	for _, n := range []string{a, b} {
		w.Symbol(coff.SymbolDef{
			Name: n, Section: text, Value: 0,
			Class: pe.ClassExternal, Type: pe.PackSymType(pe.BaseNull, pe.DerivedFunction),
		})
	}
	if err := w.Close(); err != nil {
		t.Fatalf("coff.Writer.Close: %v", err)
	}
	return buf.Bytes()
}

// subsystemOf reads the Subsystem field straight out of a linked image,
// rather than through the pefile check the other tests use: that one skips
// where Python is not installed, and a test that usually skips is not a test
// of anything.
//
// The walk is the format's: e_lfanew at 0x3C names the PE signature, the
// twenty-byte file header follows it, and Subsystem is sixty-eight bytes
// into the PE32+ optional header after that.
func subsystemOf(t *testing.T, img []byte) int {
	t.Helper()
	if len(img) < 0x40 {
		t.Fatal("image is too short to hold a DOS header")
	}
	lfanew := int(binary.LittleEndian.Uint32(img[0x3C:]))
	opt := lfanew + 4 + 20
	if opt+70 > len(img) {
		t.Fatal("image is too short to hold an optional header")
	}
	return int(binary.LittleEndian.Uint16(img[opt+68:]))
}
