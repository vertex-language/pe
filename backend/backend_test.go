package backend_test

import (
	"errors"
	"testing"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/backend"
	"github.com/vertex-language/pe/image"

	_ "github.com/vertex-language/pe/x64"
)

func sym(name string) *image.Symbol {
	tab := image.NewSymbolTable()
	return tab.Undefined(name)
}

func TestReqsIATAndThunkDedup(t *testing.T) {
	r := backend.NewReqs()
	a, b := sym("Foo"), sym("Bar")

	r.NeedIATSlot(a)
	r.NeedIATSlot(a) // idempotent
	r.NeedIATSlot(b)
	if got := r.IATSlots(); len(got) != 2 {
		t.Fatalf("IATSlots() = %v, want 2 entries", got)
	}

	// A thunk implies its own IAT slot without duplicating it.
	c := sym("Baz")
	r.NeedImportThunk(c)
	if got := r.IATSlots(); len(got) != 3 {
		t.Fatalf("IATSlots() after NeedImportThunk = %v, want 3 entries", got)
	}
	if got := r.ImportThunks(); len(got) != 1 || got[0] != c {
		t.Fatalf("ImportThunks() = %v, want [c]", got)
	}
	r.NeedImportThunk(c) // idempotent
	if got := r.ImportThunks(); len(got) != 1 {
		t.Fatalf("ImportThunks() after duplicate = %v, want 1 entry", got)
	}

	r.NeedIATSlot(nil) // must not panic or record
	if got := r.IATSlots(); len(got) != 3 {
		t.Errorf("NeedIATSlot(nil) changed the slot count: %v", got)
	}
}

func TestReqsBaseReloc(t *testing.T) {
	r := backend.NewReqs()
	c := image.NewChunk(".data", "<link>", &image.Blob{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}, Alignment: 8})

	r.NeedBaseReloc(c, 0, pe.BaseRelocDir64)
	// BaseRelocAbsolute is padding, not a real fixup, and must be skipped.
	r.NeedBaseReloc(c, 8, pe.BaseRelocAbsolute)

	relocs := r.BaseRelocs()
	if len(relocs) != 1 {
		t.Fatalf("BaseRelocs() = %v, want 1 entry (the absolute one is padding)", relocs)
	}
	if relocs[0].Off != 0 || relocs[0].Kind != pe.BaseRelocDir64 {
		t.Errorf("BaseRelocs()[0] = %+v, want Off=0 Kind=BaseRelocDir64", relocs[0])
	}

	rva, err := relocs[0].RVA()
	if err == nil {
		t.Errorf("RVA() before layout = %v, want an error (ErrNoRVA)", rva)
	}
}

func TestReqsGuardAndTLS(t *testing.T) {
	r := backend.NewReqs()
	a := sym("IndirectTarget")
	r.NeedGuardTarget(a)
	r.NeedGuardTarget(a)
	if got := r.GuardTargets(); len(got) != 1 {
		t.Errorf("GuardTargets() = %v, want 1 entry", got)
	}

	b := sym("ThreadLocalVar")
	r.NeedTLSFixup(b)
	r.NeedTLSFixup(b)
	if got := r.TLSFixups(); len(got) != 1 {
		t.Errorf("TLSFixups() = %v, want 1 entry", got)
	}
}

func TestKindClassification(t *testing.T) {
	if !backend.KindVA.NeedsSymbol() {
		t.Error("KindVA.NeedsSymbol() = false, want true")
	}
	if backend.KindIgnored.NeedsSymbol() {
		t.Error("KindIgnored.NeedsSymbol() = true, want false")
	}
	if backend.KindPair.NeedsSymbol() {
		t.Error("KindPair.NeedsSymbol() = true, want false")
	}
	if !backend.KindBranch.Thunkable() {
		t.Error("KindBranch.Thunkable() = false, want true")
	}
	if backend.KindRelative.Thunkable() {
		t.Error("KindRelative.Thunkable() = true, want false")
	}
}

// TestRegisterAndFor checks the backend registry against the real AMD64
// backend, registered by this test file's blank import of pe/x64.
func TestRegisterAndFor(t *testing.T) {
	tgt, err := pe.ParseTarget("x86_64-pc-windows-msvc")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	b, err := backend.For(tgt)
	if err != nil {
		t.Fatalf("For(amd64): %v", err)
	}
	if b == nil {
		t.Fatal("For(amd64) returned a nil backend with no error")
	}

	found := false
	for _, t2 := range backend.Registered() {
		if t2.Machine == pe.MachineAMD64 {
			found = true
		}
	}
	if !found {
		t.Error("Registered() does not list AMD64")
	}
}

func TestForUnregisteredMachineFails(t *testing.T) {
	tgt, err := pe.ParseTarget("aarch64-pc-windows-msvc")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	_, err = backend.For(tgt)
	if err == nil {
		t.Fatal("For(arm64) succeeded; arm64 has no registered backend in this module")
	}
	var nbe *backend.NoBackendError
	if !errors.As(err, &nbe) {
		t.Errorf("For(arm64) error = %v (%T), want *NoBackendError", err, err)
	}
	if !errors.Is(err, backend.ErrNoBackend) {
		t.Error("For(arm64) error does not unwrap to ErrNoBackend")
	}
}
