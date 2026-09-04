package image_test

import (
	"errors"
	"testing"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/image"
)

func cfg(t *testing.T) image.Config {
	t.Helper()
	tgt, err := pe.ParseTarget("x86_64-pc-windows-msvc")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	return image.Config{
		Target:           tgt,
		ImageBase:        0x140000000,
		SectionAlignment: 0x1000,
		FileAlignment:    0x200,
		StubSize:         0x40,
		NumDataDirs:      pe.NumDataDirs,
	}
}

func newImage(t *testing.T) *image.Image {
	t.Helper()
	img, err := image.New(cfg(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return img
}

func TestConfigValidation(t *testing.T) {
	base := cfg(t)

	bad := base
	bad.FileAlignment = 3 // not a power of two
	if _, err := image.New(bad); err == nil {
		t.Error("New accepted a non-power-of-two FileAlignment")
	}

	bad = base
	bad.SectionAlignment = 0x100 // less than FileAlignment
	if _, err := image.New(bad); err == nil {
		t.Error("New accepted SectionAlignment < FileAlignment")
	}

	bad = base
	bad.ImageBase = 0x1401 // not a multiple of 64K
	if _, err := image.New(bad); err == nil {
		t.Error("New accepted an unaligned ImageBase")
	}
}

func TestPhaseOrderIsEnforced(t *testing.T) {
	img := newImage(t)

	if err := img.Assign(); !errors.Is(err, image.ErrPhase) {
		t.Errorf("Assign before Seal: err = %v, want ErrPhase", err)
	}
	if err := img.Freeze(); !errors.Is(err, image.ErrPhase) {
		t.Errorf("Freeze before Seal: err = %v, want ErrPhase", err)
	}
	if _, err := img.Bytes(); !errors.Is(err, image.ErrNotFrozen) {
		t.Errorf("Bytes before Freeze: err = %v, want ErrNotFrozen", err)
	}

	sec, err := img.AddSection(".text", pe.SecCode, pe.SecExecute|pe.SecRead)
	if err != nil {
		t.Fatalf("AddSection: %v", err)
	}
	chunk := image.NewChunk(".text", "<link>", &image.Blob{Data: []byte{0xC3}, Alignment: 1})
	chunk.Reachable = true
	if err := sec.Add(chunk); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if err := img.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := img.AddSection(".data", pe.SecInitData, pe.SecRead); !errors.Is(err, image.ErrPhase) {
		t.Errorf("AddSection after Seal: err = %v, want ErrPhase", err)
	}
	if err := img.Seal(); !errors.Is(err, image.ErrPhase) {
		t.Errorf("Seal twice: err = %v, want ErrPhase", err)
	}

	if err := img.Assign(); err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if err := img.Freeze(); err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	if err := img.Assign(); !errors.Is(err, image.ErrPhase) {
		t.Errorf("Assign after Freeze: err = %v, want ErrPhase", err)
	}
	if _, err := img.Bytes(); err != nil {
		t.Errorf("Bytes after Freeze: %v", err)
	}
}

func TestSealRejectsNoSections(t *testing.T) {
	img := newImage(t)
	if err := img.Seal(); !errors.Is(err, image.ErrNoSections) {
		t.Errorf("Seal with no sections: err = %v, want ErrNoSections", err)
	}
}

func TestAddSectionRejectsLongName(t *testing.T) {
	img := newImage(t)
	if _, err := img.AddSection(".way_too_long", pe.SecInitData, pe.SecRead); err == nil {
		t.Error("AddSection accepted a name longer than eight bytes")
	}
}

// TestAssignLayoutBasics builds a two-section image and checks the resulting
// RVAs are section-aligned, adjacent, and that section content round-trips
// into Bytes() at the right file offset.
func TestAssignLayoutBasics(t *testing.T) {
	img := newImage(t)
	code := []byte{0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3}
	text, err := img.AddSection(".text", pe.SecCode, pe.SecExecute|pe.SecRead)
	if err != nil {
		t.Fatalf("AddSection(.text): %v", err)
	}
	textChunk := image.NewChunk(".text", "<link>", &image.Blob{Data: code, Alignment: 16})
	textChunk.Reachable = true
	if err := text.Add(textChunk); err != nil {
		t.Fatalf("Add: %v", err)
	}

	data, err := img.AddSection(".data", pe.SecInitData, pe.SecRead|pe.SecWrite)
	if err != nil {
		t.Fatalf("AddSection(.data): %v", err)
	}
	dataBytes := []byte{1, 2, 3, 4}
	dataChunk := image.NewChunk(".data", "<link>", &image.Blob{Data: dataBytes, Alignment: 4})
	dataChunk.Reachable = true
	if err := data.Add(dataChunk); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if err := img.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := img.Assign(); err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if err := img.Freeze(); err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	// Freeze only fixes addresses and allocates the buffer; copying each
	// chunk's bytes in is the caller's job (link/apply.go's contents step
	// does this for a real link).
	for _, sec := range []*image.Section{text, data} {
		for _, c := range sec.Chunks() {
			if !c.HasContent() {
				continue
			}
			rva, err := c.RVA()
			if err != nil {
				t.Fatalf("chunk RVA: %v", err)
			}
			bytes, err := c.Bytes()
			if err != nil {
				t.Fatalf("chunk Bytes: %v", err)
			}
			dst, err := img.AtRVA(rva, len(bytes))
			if err != nil {
				t.Fatalf("AtRVA: %v", err)
			}
			copy(dst, bytes)
		}
	}

	textRVA, err := text.RVA()
	if err != nil {
		t.Fatalf("text.RVA: %v", err)
	}
	if textRVA%pe.RVA(img.Cfg.SectionAlignment) != 0 {
		t.Errorf(".text RVA %v is not section-aligned", textRVA)
	}
	dataRVA, err := data.RVA()
	if err != nil {
		t.Fatalf("data.RVA: %v", err)
	}
	if dataRVA <= textRVA {
		t.Errorf(".data RVA %v should be after .text RVA %v", dataRVA, textRVA)
	}

	out, err := img.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	textOff, err := text.Off()
	if err != nil {
		t.Fatalf("text.Off: %v", err)
	}
	if got := out[textOff : int(textOff)+len(code)]; string(got) != string(code) {
		t.Errorf(".text content at file offset = %x, want %x", got, code)
	}
}

// TestZeroFillMustBeLastInSection checks that Assign refuses a section where
// a chunk with real file content follows a zero-filled one — SizeOfRawData
// can only describe a prefix.
func TestZeroFillMustBeLastInSection(t *testing.T) {
	img := newImage(t)
	sec, err := img.AddSection(".data", pe.SecInitData, pe.SecRead|pe.SecWrite)
	if err != nil {
		t.Fatalf("AddSection: %v", err)
	}
	bss := image.NewChunk(".data", "<link>", &image.Zeroed{Length: 16, Alignment: 4})
	bss.Reachable = true
	if err := sec.Add(bss); err != nil {
		t.Fatalf("Add(bss): %v", err)
	}
	real := image.NewChunk(".data", "<link>", &image.Blob{Data: []byte{1, 2, 3, 4}, Alignment: 4})
	real.Reachable = true
	if err := sec.Add(real); err != nil {
		t.Fatalf("Add(real): %v", err)
	}

	if err := img.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	var layoutErr *image.LayoutError
	if err := img.Assign(); !errors.As(err, &layoutErr) {
		t.Errorf("Assign with content after zero-fill: err = %v, want *LayoutError", err)
	}
}

func TestSymbolTable(t *testing.T) {
	tab := image.NewSymbolTable()
	c := image.NewChunk(".text", "<link>", &image.Blob{Data: []byte{0xC3}, Alignment: 1})

	sym := tab.Define("entry", c, 0)
	if tab.Lookup("entry") != sym {
		t.Error("Lookup did not return the defined symbol")
	}
	if sym.Kind() != image.SymDefined {
		t.Errorf("Kind() = %v, want SymDefined", sym.Kind())
	}

	abs := tab.Absolute("__ImageBase", 0x140000000)
	if abs.Kind() != image.SymAbsolute {
		t.Errorf("Absolute symbol Kind() = %v, want SymAbsolute", abs.Kind())
	}
	if v, ok := abs.Value(); !ok || v != 0x140000000 {
		t.Errorf("Absolute Value() = %#x,%v, want 0x140000000,true", v, ok)
	}

	undef := tab.Undefined("external_fn")
	if undef.Kind() != image.SymUndefined {
		t.Errorf("Undefined symbol Kind() = %v, want SymUndefined", undef.Kind())
	}

	if tab.Lookup("nonexistent") != nil {
		t.Error("Lookup on an unknown name returned non-nil")
	}
	if len(tab.Symbols()) != 3 {
		t.Errorf("Symbols() has %d entries, want 3", len(tab.Symbols()))
	}
}
