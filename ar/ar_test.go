package ar_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/ar"
	"github.com/vertex-language/pe/internal/binio"
)

func extentOf(t *testing.T, data []byte) *binio.Extent {
	t.Helper()
	ext, err := binio.NewExtent(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("NewExtent: %v", err)
	}
	return ext
}

func writeArchive(t *testing.T, inputs []ar.Input) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := ar.NewWriter(&buf, ar.Options{Deterministic: true})
	for _, in := range inputs {
		w.Add(in)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Writer.Close: %v", err)
	}
	return buf.Bytes()
}

func TestRoundTrip(t *testing.T) {
	inputs := []ar.Input{
		{Name: "foo.obj", Data: []byte("foo contents"), Symbols: []string{"_foo", "_foo_helper"}},
		{Name: "bar.obj", Data: []byte("bar contents, a bit longer than foo's"), Symbols: []string{"_bar"}},
	}
	data := writeArchive(t, inputs)

	f, err := ar.NewFile(extentOf(t, data))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	defer f.Close()

	objs := f.Objects()
	if len(objs) != len(inputs) {
		t.Fatalf("got %d members, want %d", len(objs), len(inputs))
	}
	for i, in := range inputs {
		got, err := objs[i].Data()
		if err != nil {
			t.Fatalf("member %d Data: %v", i, err)
		}
		if !bytes.Equal(got, in.Data) {
			t.Errorf("member %d contents = %q, want %q", i, got, in.Data)
		}
	}

	for _, in := range inputs {
		for _, sym := range in.Symbols {
			m, err := f.Lookup(sym)
			if err != nil {
				t.Fatalf("Lookup(%q): %v", sym, err)
			}
			got, err := m.Data()
			if err != nil {
				t.Fatalf("Data: %v", err)
			}
			if !bytes.Equal(got, in.Data) {
				t.Errorf("Lookup(%q) returned member with contents %q, want %q", sym, got, in.Data)
			}
		}
	}

	if m, err := f.Lookup("_nonexistent"); err != nil || m != nil {
		t.Errorf("Lookup(_nonexistent) = %v, %v, want nil, nil", m, err)
	}

	syms := f.Symbols()
	if len(syms) != 3 {
		t.Errorf("Symbols() = %v, want 3 entries", syms)
	}
}

func TestLongNames(t *testing.T) {
	longName := "this_is_a_member_name_much_longer_than_the_fixed_field_width.obj"
	data := writeArchive(t, []ar.Input{
		{Name: longName, Data: []byte("payload"), Symbols: []string{"_sym"}},
	})
	f, err := ar.NewFile(extentOf(t, data))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	defer f.Close()

	objs := f.Objects()
	if len(objs) != 1 {
		t.Fatalf("got %d members, want 1", len(objs))
	}
	if objs[0].Name != longName {
		t.Errorf("member name = %q, want %q", objs[0].Name, longName)
	}
}

func TestNewFileRejectsGarbage(t *testing.T) {
	if _, err := ar.NewFile(extentOf(t, []byte("not an archive"))); err == nil {
		t.Fatal("NewFile accepted garbage")
	}
}

// TestReadRealMinGWArchive is an integration check against a real GNU-format
// import library shipped with mingw-w64, if installed. MSVC-layout writing
// is this package's tested write path; MinGW .dll.a reading is a distinct
// code path this exercises directly.
func TestReadRealMinGWArchive(t *testing.T) {
	candidates := []string{
		"/opt/homebrew/Cellar/mingw-w64/14.0.0_3/toolchain-x86_64/x86_64-w64-mingw32/lib/libkernel32.a",
	}
	var path string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		t.Skip("no known mingw-w64 import library found on this machine")
	}

	f, err := ar.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	if len(f.Objects()) == 0 {
		t.Fatal("libkernel32.a has no members")
	}
	m, err := f.Lookup("ExitProcess")
	if err != nil {
		t.Fatalf("Lookup(ExitProcess): %v", err)
	}
	if m == nil {
		t.Fatal("Lookup(ExitProcess) = nil, want a member")
	}
	data, err := m.Data()
	if err != nil {
		t.Fatalf("Data: %v", err)
	}
	if len(data) == 0 {
		t.Error("ExitProcess member has no data")
	}
	// A real object from this archive should parse as a COFF file. Reading
	// this deep isn't ar's job — that's coff's — but confirming the
	// extracted bytes really do start with a recognizable object avoids
	// the extraction offset being silently wrong for the GNU layout.
	if pe.KindOf(data) != pe.KindObject {
		t.Errorf("ExitProcess member does not look like a plain COFF object: KindOf = %v", pe.KindOf(data))
	}
}
