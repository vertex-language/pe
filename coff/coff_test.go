package coff_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/coff"
	"github.com/vertex-language/pe/internal/binio"
)

func target(t *testing.T) pe.Target {
	t.Helper()
	tgt, err := pe.ParseTarget("x86_64-pc-windows-msvc")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	return tgt
}

func extentOf(t *testing.T, data []byte) *binio.Extent {
	t.Helper()
	ext, err := binio.NewExtent(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("NewExtent: %v", err)
	}
	return ext
}

// TestWriteReadRoundTrip builds an object with a code section, a data
// section, an external definition, an undefined external, a common symbol,
// and one relocation, then reads it back and checks everything survives.
func TestWriteReadRoundTrip(t *testing.T) {
	tgt := target(t)
	var buf bytes.Buffer
	w := coff.NewWriter(&buf, coff.Options{Target: tgt})

	text := w.Section(coff.SectionHeader{Name: ".text", Kind: pe.SecCode, Prot: pe.SecExecute | pe.SecRead, Align: 16})
	code := []byte{0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3} // mov eax,42; ret
	text.Write(code)

	data := w.Section(coff.SectionHeader{Name: ".data", Kind: pe.SecInitData, Prot: pe.SecRead | pe.SecWrite, Align: 4})
	data.Write([]byte{1, 2, 3, 4})

	w.Symbol(coff.SymbolDef{Name: "entry", Section: text, Value: 0, Class: pe.ClassExternal,
		Type: pe.PackSymType(pe.BaseNull, pe.DerivedFunction)})
	extern := w.Symbol(coff.SymbolDef{Name: "external_fn", Class: pe.ClassExternal})
	w.Symbol(coff.SymbolDef{Name: "g_counter", Value: 8, Class: pe.ClassExternal}) // common: no section, nonzero value

	w.Reloc(text, coff.RelocSpec{Address: 1, Sym: extern, Type: uint16(pe.IMAGE_REL_AMD64_REL32)})

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := coff.NewFile(extentOf(t, buf.Bytes()))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	defer f.Close()

	if f.Machine != pe.MachineAMD64 {
		t.Errorf("Machine = %v, want AMD64", f.Machine)
	}
	if len(f.Sections) != 2 {
		t.Fatalf("got %d sections, want 2", len(f.Sections))
	}
	textSec := f.Sections[0]
	if textSec.Name != ".text" {
		t.Errorf("Sections[0].Name = %q, want .text", textSec.Name)
	}
	got, err := textSec.Data()
	if err != nil {
		t.Fatalf("Data: %v", err)
	}
	if !bytes.Equal(got, code) {
		t.Errorf("text contents = %x, want %x", got, code)
	}

	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("Symbols: %v", err)
	}
	byName := make(map[string]*coff.Symbol, len(syms))
	for _, s := range syms {
		byName[s.Name] = s
	}

	entry, ok := byName["entry"]
	if !ok {
		t.Fatal("entry not found")
	}
	if !entry.External() || !entry.Defined() {
		t.Errorf("entry: External=%v Defined=%v, want true,true", entry.External(), entry.Defined())
	}

	ext, ok := byName["external_fn"]
	if !ok {
		t.Fatal("external_fn not found")
	}
	if !ext.Undefined() {
		t.Error("external_fn should be undefined")
	}
	if _, isCommon := ext.Common(); isCommon {
		t.Error("external_fn should not report Common()")
	}

	common, ok := byName["g_counter"]
	if !ok {
		t.Fatal("g_counter not found")
	}
	size, isCommon := common.Common()
	if !isCommon {
		t.Fatal("g_counter should report Common() = true")
	}
	if size != 8 {
		t.Errorf("g_counter common size = %d, want 8", size)
	}

	relocs, err := textSec.Relocs()
	if err != nil {
		t.Fatalf("Relocs: %v", err)
	}
	if len(relocs) != 1 {
		t.Fatalf("got %d relocations, want 1", len(relocs))
	}
	if relocs[0].Type != uint16(pe.IMAGE_REL_AMD64_REL32) {
		t.Errorf("reloc.Type = %v, want IMAGE_REL_AMD64_REL32", relocs[0].Type)
	}
}

// TestComdat checks a COMDAT section round-trips its selection kind and
// leader symbol.
func TestComdat(t *testing.T) {
	tgt := target(t)
	var buf bytes.Buffer
	w := coff.NewWriter(&buf, coff.Options{Target: tgt})

	fn := w.Section(coff.SectionHeader{Name: ".text", Kind: pe.SecCode | pe.SecLnkComdat, Prot: pe.SecExecute | pe.SecRead, Align: 16})
	fn.Write([]byte{0xC3})
	leader := w.Symbol(coff.SymbolDef{Name: "inline_fn", Section: fn, Class: pe.ClassExternal,
		Type: pe.PackSymType(pe.BaseNull, pe.DerivedFunction)})
	w.SetComdat(fn, pe.SelectAny, leader)

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := coff.NewFile(extentOf(t, buf.Bytes()))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	defer f.Close()

	sec := f.Sections[0]
	if !sec.IsComdat() {
		t.Fatal("section should report IsComdat() = true")
	}
	cd, err := sec.Comdat()
	if err != nil {
		t.Fatalf("Comdat: %v", err)
	}
	if cd.Selection != pe.SelectAny {
		t.Errorf("Selection = %v, want SelectAny", cd.Selection)
	}
	if cd.Leader == nil || cd.Leader.Name != "inline_fn" {
		t.Errorf("Leader = %v, want inline_fn", cd.Leader)
	}
}

// TestWeakExternal checks a weak external round-trips its alternate symbol
// and kind.
func TestWeakExternal(t *testing.T) {
	tgt := target(t)
	var buf bytes.Buffer
	w := coff.NewWriter(&buf, coff.Options{Target: tgt})

	text := w.Section(coff.SectionHeader{Name: ".text", Kind: pe.SecCode, Prot: pe.SecExecute | pe.SecRead, Align: 16})
	text.Write([]byte{0xC3})
	alt := w.Symbol(coff.SymbolDef{Name: "real_impl", Section: text, Class: pe.ClassExternal})
	w.WeakSymbol("weak_alias", alt, pe.WeakNoLibrary)

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := coff.NewFile(extentOf(t, buf.Bytes()))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	defer f.Close()

	weaks, err := f.Weaks()
	if err != nil {
		t.Fatalf("Weaks: %v", err)
	}
	if len(weaks) != 1 {
		t.Fatalf("got %d weak externals, want 1", len(weaks))
	}
	if weaks[0].Kind != pe.WeakNoLibrary {
		t.Errorf("Kind = %v, want WeakNoLibrary", weaks[0].Kind)
	}
}

func TestParseDirectives(t *testing.T) {
	dirs, err := coff.ParseDirectives([]byte(`-defaultlib:msvcrt.lib -include:__imp_thing`))
	if err != nil {
		t.Fatalf("ParseDirectives: %v", err)
	}
	if len(dirs) != 2 {
		t.Fatalf("got %d directives, want 2: %+v", len(dirs), dirs)
	}
}

func TestNewFileRejectsGarbage(t *testing.T) {
	if _, err := coff.NewFile(extentOf(t, []byte("not a coff object at all"))); err == nil {
		t.Fatal("NewFile accepted garbage")
	}
}

// TestReadRealCompilerOutput reads an object built by the real mingw-w64
// GCC, skipped if it is not on PATH.
func TestReadRealCompilerOutput(t *testing.T) {
	gcc, err := exec.LookPath("x86_64-w64-mingw32-gcc")
	if err != nil {
		t.Skip("x86_64-w64-mingw32-gcc not found on PATH")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "t.c")
	obj := filepath.Join(dir, "t.o")
	if err := os.WriteFile(src, []byte(`
int helper(int x) { return x + 1; }
int add(int a, int b) { return helper(a) + b; }
`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cmd := exec.Command(gcc, "-c", "-O0", "-o", obj, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc failed: %v\n%s", err, out)
	}

	data, err := os.ReadFile(obj)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	f, err := coff.NewFile(extentOf(t, data))
	if err != nil {
		t.Fatalf("NewFile on gcc output: %v", err)
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("Symbols: %v", err)
	}
	var sawAdd, sawHelper bool
	for _, s := range syms {
		switch s.Name {
		case "add":
			sawAdd = s.External() && s.Defined()
		case "helper":
			sawHelper = s.Defined()
		}
	}
	if !sawAdd {
		t.Error("add not found as an external definition in gcc's output")
	}
	if !sawHelper {
		t.Error("helper not found as a definition in gcc's output")
	}

	// A direct call within one section needs no relocation — the assembler
	// already knows both addresses — so .text itself may carry none. .pdata
	// (the exception unwind table gcc always emits for x64) always
	// references .text and .xdata by relocation, which is a reliable place
	// to confirm relocation decoding works on real compiler output.
	var pdata *coff.Section
	for _, sec := range f.Sections {
		if sec.Name == ".pdata" {
			pdata = sec
		}
	}
	if pdata == nil {
		t.Fatal("gcc's output has no .pdata section")
	}
	relocs, err := pdata.Relocs()
	if err != nil {
		t.Fatalf(".pdata Relocs: %v", err)
	}
	if len(relocs) == 0 {
		t.Error(".pdata carries no relocations, want several (it references .text and .xdata)")
	}
}
