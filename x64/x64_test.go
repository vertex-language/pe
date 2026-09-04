package x64_test

import (
	"encoding/binary"
	"testing"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/backend"
	"github.com/vertex-language/pe/image"
	"github.com/vertex-language/pe/x64"
)

func TestClassify(t *testing.T) {
	var b x64.Backend
	cases := []struct {
		typ  pe.RelocAMD64
		want backend.Kind
	}{
		{pe.IMAGE_REL_AMD64_ABSOLUTE, backend.KindIgnored},
		{pe.IMAGE_REL_AMD64_ADDR64, backend.KindVA},
		{pe.IMAGE_REL_AMD64_ADDR32, backend.KindVA},
		{pe.IMAGE_REL_AMD64_ADDR32NB, backend.KindRVA},
		{pe.IMAGE_REL_AMD64_REL32, backend.KindRelative},
		{pe.IMAGE_REL_AMD64_REL32_5, backend.KindRelative},
		{pe.IMAGE_REL_AMD64_SECTION, backend.KindSectionIndex},
		{pe.IMAGE_REL_AMD64_SECREL, backend.KindSectionRel},
		{pe.IMAGE_REL_AMD64_TOKEN, backend.KindToken},
		{pe.IMAGE_REL_AMD64_PAIR, backend.KindPair},
	}
	for _, c := range cases {
		if got := b.Classify(uint16(c.typ)); got != c.want {
			t.Errorf("Classify(%v) = %v, want %v", c.typ, got, c.want)
		}
	}
	if got := b.Classify(0xffff); got != backend.KindUnsupported {
		t.Errorf("Classify(unknown) = %v, want KindUnsupported", got)
	}
}

func TestBaseRelocKind(t *testing.T) {
	var b x64.Backend
	tab := image.NewSymbolTable()
	real := tab.Define("real_target", image.NewChunk(".data", "<link>", &image.Blob{Data: []byte{0}, Alignment: 1}), 0)
	abs := tab.Absolute("__guard_fids_count", 3)

	cases := []struct {
		name     string
		r        image.Reloc
		wantKind pe.BaseRelocKind
		wantOK   bool
	}{
		{"ADDR64 to a real address", image.Reloc{Type: uint16(pe.IMAGE_REL_AMD64_ADDR64), Sym: real}, pe.BaseRelocDir64, true},
		{"ADDR32 to a real address", image.Reloc{Type: uint16(pe.IMAGE_REL_AMD64_ADDR32), Sym: real}, pe.BaseRelocHighLow, true},
		{"ADDR32NB never needs one", image.Reloc{Type: uint16(pe.IMAGE_REL_AMD64_ADDR32NB), Sym: real}, pe.BaseRelocAbsolute, false},
		{"REL32 never needs one", image.Reloc{Type: uint16(pe.IMAGE_REL_AMD64_REL32), Sym: real}, pe.BaseRelocAbsolute, false},
		{"ADDR64 to an absolute constant needs none", image.Reloc{Type: uint16(pe.IMAGE_REL_AMD64_ADDR64), Sym: abs}, pe.BaseRelocAbsolute, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kind, ok := b.BaseRelocKind(c.r)
			if kind != c.wantKind || ok != c.wantOK {
				t.Errorf("BaseRelocKind(%s) = %v,%v, want %v,%v", c.name, kind, ok, c.wantKind, c.wantOK)
			}
		})
	}
}

// buildFrozenImage lays out the given sections (name -> chunks) into a
// minimal frozen image and returns it along with each chunk's assigned RVA,
// so a test can build a backend.Site over one of them.
func buildFrozenImage(t *testing.T, layout map[string][]*image.Chunk) *image.Image {
	t.Helper()
	tgt, err := pe.ParseTarget("x86_64-pc-windows-msvc")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	img, err := image.New(image.Config{
		Target: tgt, ImageBase: 0x140000000,
		SectionAlignment: 0x1000, FileAlignment: 0x200,
		StubSize: 0x40, NumDataDirs: pe.NumDataDirs,
	})
	if err != nil {
		t.Fatalf("image.New: %v", err)
	}
	for name, chunks := range layout {
		sec, err := img.AddSection(name, pe.SecInitData, pe.SecRead|pe.SecWrite)
		if err != nil {
			t.Fatalf("AddSection(%s): %v", name, err)
		}
		for _, c := range chunks {
			c.Reachable = true
			if err := sec.Add(c); err != nil {
				t.Fatalf("Add: %v", err)
			}
		}
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
	return img
}

// decodeThunkTarget independently decodes the RIP-relative displacement an
// x64 import thunk (ff 25 <rel32>) encodes, given the thunk's own RVA.
func decodeThunkTarget(t *testing.T, code []byte, thunkRVA pe.RVA) pe.RVA {
	t.Helper()
	if code[0] != 0xff || code[1] != 0x25 {
		t.Fatalf("opcode bytes = %02x %02x, want ff 25 (jmp qword ptr [rip+disp32])", code[0], code[1])
	}
	disp := int32(binary.LittleEndian.Uint32(code[2:6]))
	return pe.RVA(int64(thunkRVA) + 6 + int64(disp))
}

func TestImportThunkWrite(t *testing.T) {
	var b x64.Backend
	shape := b.ImportThunk()
	if shape.Size() != 6 {
		t.Errorf("Size() = %d, want 6", shape.Size())
	}

	thunkChunk := image.NewChunk(".text", "<link>", &image.Blob{Data: make([]byte, 6), Alignment: 16})
	iatChunk := image.NewChunk(".idata", "<link>", &image.Blob{Data: make([]byte, 8), Alignment: 8})

	img := buildFrozenImage(t, map[string][]*image.Chunk{
		".text":  {thunkChunk},
		".idata": {iatChunk},
	})

	site, err := backend.NewSite(img, thunkChunk)
	if err != nil {
		t.Fatalf("NewSite: %v", err)
	}
	iatRVA, err := iatChunk.RVA()
	if err != nil {
		t.Fatalf("iatChunk.RVA: %v", err)
	}
	if err := shape.Write(site, iatRVA); err != nil {
		t.Fatalf("Write: %v", err)
	}

	out, err := img.AtRVA(site.RVA, 6)
	if err != nil {
		t.Fatalf("AtRVA: %v", err)
	}
	got := decodeThunkTarget(t, out, site.RVA)
	if got != iatRVA {
		t.Errorf("decoded thunk target = %v, want %v (the IAT slot)", got, iatRVA)
	}
}

func TestImportThunkWriteTooSmall(t *testing.T) {
	var b x64.Backend
	shape := b.ImportThunk()

	small := image.NewChunk(".text", "<link>", &image.Blob{Data: make([]byte, 3), Alignment: 16})
	img := buildFrozenImage(t, map[string][]*image.Chunk{".text": {small}})
	site, err := backend.NewSite(img, small)
	if err != nil {
		t.Fatalf("NewSite: %v", err)
	}
	if err := shape.Write(site, 0x1000); err == nil {
		t.Error("Write into a too-small chunk should fail")
	}
}
