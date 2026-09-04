package def_test

import (
	"testing"

	"github.com/vertex-language/pe/def"
)

func TestParseBasicDLL(t *testing.T) {
	src := `
LIBRARY mymath.dll
EXPORTS
    Add
    Sub
`
	f, err := def.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.IsDLL() {
		t.Error("IsDLL() = false, want true")
	}
	if f.Module() != "mymath.dll" {
		t.Errorf("Module() = %q, want mymath.dll", f.Module())
	}
	if len(f.Exports) != 2 {
		t.Fatalf("got %d exports, want 2", len(f.Exports))
	}
	if f.Exports[0].Name != "Add" || f.Exports[1].Name != "Sub" {
		t.Errorf("Exports = %+v", f.Exports)
	}
}

func TestParseAliasIsReversed(t *testing.T) {
	// entryname=internalname: the DLL exports "PublicName" but the symbol
	// implementing it is "ActualImpl" — Name is the internal one.
	f, err := def.Parse([]byte("LIBRARY x.dll\nEXPORTS\n  PublicName=ActualImpl\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(f.Exports) != 1 {
		t.Fatalf("got %d exports, want 1", len(f.Exports))
	}
	e := f.Exports[0]
	if e.Name != "ActualImpl" {
		t.Errorf("Name = %q, want ActualImpl", e.Name)
	}
	if e.ExtName != "PublicName" {
		t.Errorf("ExtName = %q, want PublicName", e.ExtName)
	}
	if e.Exported() != "PublicName" {
		t.Errorf("Exported() = %q, want PublicName", e.Exported())
	}
}

func TestParseOrdinalAndFlags(t *testing.T) {
	f, err := def.Parse([]byte("LIBRARY x.dll\nEXPORTS\n  Hidden @5 NONAME DATA\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(f.Exports) != 1 {
		t.Fatalf("got %d exports, want 1", len(f.Exports))
	}
	e := f.Exports[0]
	if e.Ordinal != 5 {
		t.Errorf("Ordinal = %d, want 5", e.Ordinal)
	}
	if !e.NoName {
		t.Error("NoName = false, want true")
	}
	if !e.Data {
		t.Error("Data = false, want true")
	}
}

func TestParseForwarder(t *testing.T) {
	f, err := def.Parse([]byte("LIBRARY x.dll\nEXPORTS\n  MyFunc=other.RealFunc\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	e := f.Exports[0]
	target, ok := e.Forwarder()
	if !ok {
		t.Fatal("Forwarder() ok = false, want true")
	}
	if target != "other.RealFunc" {
		t.Errorf("Forwarder target = %q, want other.RealFunc", target)
	}
}

func TestParseNameStatementIsExecutable(t *testing.T) {
	f, err := def.Parse([]byte("NAME myapp.exe\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if f.IsDLL() {
		t.Error("IsDLL() = true for a NAME statement, want false")
	}
	if f.Module() != "myapp.exe" {
		t.Errorf("Module() = %q, want myapp.exe", f.Module())
	}
}

func TestParseStackAndHeapSizes(t *testing.T) {
	f, err := def.Parse([]byte("LIBRARY x.dll\nSTACKSIZE 1048576,4096\nHEAPSIZE 65536\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.HasStack || f.StackReserve != 1048576 {
		t.Errorf("StackReserve = %d (has=%v), want 1048576", f.StackReserve, f.HasStack)
	}
	if !f.HasStackCommit || f.StackCommit != 4096 {
		t.Errorf("StackCommit = %d (has=%v), want 4096", f.StackCommit, f.HasStackCommit)
	}
	if !f.HasHeap || f.HeapReserve != 65536 {
		t.Errorf("HeapReserve = %d (has=%v), want 65536", f.HeapReserve, f.HasHeap)
	}
	if f.HasHeapCommit {
		t.Error("HasHeapCommit = true, want false (no commit given)")
	}
}

func TestParseRejectsBothLibraryAndName(t *testing.T) {
	_, err := def.Parse([]byte("LIBRARY x.dll\nNAME y.exe\n"))
	if err == nil {
		t.Fatal("Parse accepted both LIBRARY and NAME")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	_, err := def.Parse([]byte("this is not valid def syntax @#$%\n"))
	if err == nil {
		t.Error("Parse accepted garbage")
	}
}

func TestParseEmptyIsNotAnError(t *testing.T) {
	// An empty .def is unusual but not itself malformed; it just describes
	// nothing.
	f, err := def.Parse([]byte(""))
	if err != nil {
		t.Fatalf("Parse(empty): %v", err)
	}
	if f.IsDLL() || f.Module() != "" {
		t.Errorf("empty file: IsDLL=%v Module=%q, want false,\"\"", f.IsDLL(), f.Module())
	}
}
