package implib_test

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/ar"
	"github.com/vertex-language/pe/implib"
)

func target(t *testing.T) pe.Target {
	t.Helper()
	tgt, err := pe.ParseTarget("x86_64-pc-windows-msvc")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	return tgt
}

func TestWriteReadRoundTrip(t *testing.T) {
	tgt := target(t)
	exports := []pe.Export{
		{Name: "Add"},
		{Name: "Sub"},
		{Name: "g_counter", Data: true},
	}
	var buf bytes.Buffer
	if err := implib.Write(&buf, implib.Options{Target: tgt, DLL: "mymath.dll"}, exports); err != nil {
		t.Fatalf("Write: %v", err)
	}

	lib, err := implib.Read(buf.Bytes())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if lib.DLL != "mymath.dll" {
		t.Errorf("DLL = %q, want mymath.dll", lib.DLL)
	}
	if lib.Mixed {
		t.Error("Mixed = true, want false (one DLL)")
	}
	if len(lib.Entries) != len(exports) {
		t.Fatalf("got %d entries, want %d", len(lib.Entries), len(exports))
	}

	byName := make(map[string]implib.Entry, len(lib.Entries))
	for _, e := range lib.Entries {
		byName[e.Symbol] = e
	}
	add, ok := byName["Add"]
	if !ok {
		t.Fatal("Add not found")
	}
	if add.Kind != implib.KindCode {
		t.Errorf("Add.Kind = %v, want KindCode", add.Kind)
	}
	if add.DLL != "mymath.dll" {
		t.Errorf("Add.DLL = %q, want mymath.dll", add.DLL)
	}

	counter, ok := byName["g_counter"]
	if !ok {
		t.Fatal("g_counter not found")
	}
	if counter.Kind != implib.KindData {
		t.Errorf("g_counter.Kind = %v, want KindData", counter.Kind)
	}
}

func TestOrdinalExport(t *testing.T) {
	tgt := target(t)
	exports := []pe.Export{{Name: "HiddenFunc", Ordinal: 7, NoName: true}}
	var buf bytes.Buffer
	if err := implib.Write(&buf, implib.Options{Target: tgt, DLL: "x.dll"}, exports); err != nil {
		t.Fatalf("Write: %v", err)
	}
	lib, err := implib.Read(buf.Bytes())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(lib.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(lib.Entries))
	}
	e := lib.Entries[0]
	if e.NameKind != implib.NameOrdinal {
		t.Errorf("NameKind = %v, want NameOrdinal", e.NameKind)
	}
	if e.Ordinal != 7 {
		t.Errorf("Ordinal = %d, want 7", e.Ordinal)
	}
}

func TestAliasedExport(t *testing.T) {
	tgt := target(t)
	// ExtName is the exported name, Name is the internal symbol — matching
	// def.Export's own documented convention (see def package).
	exports := []pe.Export{{Name: "ActualImpl", ExtName: "PublicName"}}
	var buf bytes.Buffer
	if err := implib.Write(&buf, implib.Options{Target: tgt, DLL: "x.dll"}, exports); err != nil {
		t.Fatalf("Write: %v", err)
	}
	lib, err := implib.Read(buf.Bytes())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(lib.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(lib.Entries))
	}
	if got := lib.Entries[0].Exported(); got != "PublicName" {
		t.Errorf("Exported() = %q, want PublicName", got)
	}
}

func TestWriteRejectsNoDLL(t *testing.T) {
	var buf bytes.Buffer
	err := implib.Write(&buf, implib.Options{Target: target(t)}, []pe.Export{{Name: "Foo"}})
	if err == nil {
		t.Fatal("Write accepted an empty DLL name")
	}
}

// TestWriteMinGWAMD64 checks that the GNU shape's one implemented machine
// produces an archive at all — this package's own Read only understands the
// MS shape (see the package doc comment), so a real end-to-end check that
// the bytes are correct lives in pe/link, which actually links against
// this output. This test is the narrower one: does it produce a
// well-formed archive with the symbols an importing object needs to find.
func TestWriteMinGWAMD64(t *testing.T) {
	tgt, err := pe.ParseTarget("x86_64-w64-windows-gnu")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	var buf bytes.Buffer
	if err := implib.Write(&buf, implib.Options{Target: tgt, DLL: "mymath.dll"},
		[]pe.Export{{Name: "Add"}, {Name: "Sub"}}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	path := t.TempDir() + "/libmymath.dll.a"
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := ar.Open(path)
	if err != nil {
		t.Fatalf("ar.Open: %v", err)
	}
	defer f.Close()

	for _, name := range []string{"Add", "__imp_Add", "Sub", "__imp_Sub"} {
		if _, err := f.Lookup(name); err != nil {
			t.Errorf("Lookup(%q): %v", name, err)
		}
	}
}

// TestWriteMinGWUnsupportedMachine checks that a machine writeGNU does not
// implement fails clearly rather than producing bytes nothing can link.
func TestWriteMinGWUnsupportedMachine(t *testing.T) {
	tgt, err := pe.ParseTarget("i686-w64-windows-gnu")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	var buf bytes.Buffer
	err = implib.Write(&buf, implib.Options{Target: tgt, DLL: "x.dll"}, []pe.Export{{Name: "Foo"}})
	var machErr *implib.UnsupportedGNUMachineError
	if !errors.As(err, &machErr) {
		t.Errorf("Write for i686 MinGW: err = %v, want *UnsupportedGNUMachineError", err)
	}
}

func TestReadRejectsGarbage(t *testing.T) {
	if _, err := implib.Read([]byte("not an archive")); err == nil {
		t.Fatal("Read accepted garbage")
	}
}
