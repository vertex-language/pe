package pe_test

import (
	"testing"

	"github.com/vertex-language/pe"
)

func TestParseTargetBasic(t *testing.T) {
	tgt, err := pe.ParseTarget("x86_64-pc-windows-msvc")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if tgt.Machine != pe.MachineAMD64 {
		t.Errorf("Machine = %v, want AMD64", tgt.Machine)
	}
	if tgt.OS != pe.OSWindows {
		t.Errorf("OS = %v, want OSWindows", tgt.OS)
	}
	if tgt.ABI != pe.ABIMSVC {
		t.Errorf("ABI = %v, want ABIMSVC", tgt.ABI)
	}
	if err := tgt.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestParseTargetDefaultsToMSVC(t *testing.T) {
	// No explicit environment: LLVM canonicalizes a bare Windows triple to
	// MSVC, and ParseTarget documents matching that.
	tgt, err := pe.ParseTarget("x86_64-pc-windows")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if tgt.ABI != pe.ABIMSVC {
		t.Errorf("ABI = %v, want ABIMSVC (the default)", tgt.ABI)
	}
}

func TestParseTargetMinGW(t *testing.T) {
	cases := []string{
		"x86_64-w64-windows-gnu",
		"x86_64-w64-mingw32",
	}
	for _, triple := range cases {
		t.Run(triple, func(t *testing.T) {
			tgt, err := pe.ParseTarget(triple)
			if err != nil {
				t.Fatalf("ParseTarget(%q): %v", triple, err)
			}
			if tgt.ABI != pe.ABIMinGW {
				t.Errorf("ABI = %v, want ABIMinGW", tgt.ABI)
			}
		})
	}
}

func TestParseTargetElidedVendor(t *testing.T) {
	tgt, err := pe.ParseTarget("x86_64--windows-msvc")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if tgt.Machine != pe.MachineAMD64 || tgt.ABI != pe.ABIMSVC {
		t.Errorf("Machine=%v ABI=%v, want AMD64,MSVC", tgt.Machine, tgt.ABI)
	}
}

func TestParseTargetUEFI(t *testing.T) {
	tgt, err := pe.ParseTarget("x86_64-unknown-uefi")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if tgt.OS != pe.OSUEFI {
		t.Errorf("OS = %v, want OSUEFI", tgt.OS)
	}
}

func TestParseTargetRejectsBad(t *testing.T) {
	cases := []string{
		"",
		"nonsense_arch-pc-windows-msvc",
		"x86_64-pc-linux-gnu",            // no windows/uefi OS component
		"x86_64-pc-windows-msvc-windows", // two OS components... actually just garbage tail
		"x86_64-pc-windows-msvc-gnu",     // contradictory environment
	}
	for _, triple := range cases {
		t.Run(triple, func(t *testing.T) {
			if _, err := pe.ParseTarget(triple); err == nil {
				t.Errorf("ParseTarget(%q) succeeded, want an error", triple)
			}
		})
	}
}

func TestArchNECWidthAndHybrid(t *testing.T) {
	if pe.MachineAMD64.Width() != pe.Width64 {
		t.Errorf("AMD64.Width() = %v, want Width64", pe.MachineAMD64.Width())
	}
	if pe.MachineI386.Width() != pe.Width32 {
		t.Errorf("I386.Width() = %v, want Width32", pe.MachineI386.Width())
	}
	if !pe.MachineARM64X.Hybrid() {
		t.Error("ARM64X.Hybrid() = false, want true")
	}
	if pe.MachineAMD64.Hybrid() {
		t.Error("AMD64.Hybrid() = true, want false")
	}
	if !pe.MachineARM64EC.ObjectOnly() {
		t.Error("ARM64EC.ObjectOnly() = false, want true (not a registered linkable image machine)")
	}
}

func TestIsAndKindOf(t *testing.T) {
	// A minimal COFF file header: Machine=AMD64, NumberOfSections=0,
	// followed by enough zeroed bytes to reach a plausible header length.
	obj := make([]byte, 20)
	obj[0], obj[1] = 0x64, 0x86 // IMAGE_FILE_MACHINE_AMD64, little-endian

	if !pe.Is(obj) {
		t.Error("Is() = false for a well-formed COFF header")
	}
	if pe.IsImage(obj) {
		t.Error("IsImage() = true for a plain object header")
	}
	if kind := pe.KindOf(obj); kind != pe.KindObject {
		t.Errorf("KindOf() = %v, want KindObject", kind)
	}
	m, ok := pe.MachineOf(obj)
	if !ok || m != pe.MachineAMD64 {
		t.Errorf("MachineOf() = %v,%v, want AMD64,true", m, ok)
	}
}

func TestIsArchive(t *testing.T) {
	if !pe.IsArchive([]byte("!<arch>\nrest of the file")) {
		t.Error("IsArchive() = false for a well-formed archive magic")
	}
	if pe.IsArchive([]byte("not an archive")) {
		t.Error("IsArchive() = true for non-archive data")
	}
}

func TestSectionCharacteristicsRoundTrip(t *testing.T) {
	kind, prot, align := pe.SecCode, pe.SecExecute|pe.SecRead, 16
	char, err := pe.PackSecChar(kind, prot, align)
	if err != nil {
		t.Fatalf("PackSecChar: %v", err)
	}
	gotKind, gotProt, gotAlign := pe.SplitSecChar(char)
	if gotKind != kind {
		t.Errorf("SplitSecChar kind = %v, want %v", gotKind, kind)
	}
	if gotProt != prot {
		t.Errorf("SplitSecChar prot = %v, want %v", gotProt, prot)
	}
	if gotAlign != align {
		t.Errorf("SplitSecChar align = %d, want %d", gotAlign, align)
	}
}

func TestEncodeEncodeAlignRejectsNonPowerOfTwo(t *testing.T) {
	if _, err := pe.EncodeAlign(3); err == nil {
		t.Error("EncodeAlign(3) succeeded, want an error (not a power of two)")
	}
	v, err := pe.EncodeAlign(16)
	if err != nil {
		t.Fatalf("EncodeAlign(16): %v", err)
	}
	if got := pe.DecodeAlign(v << 20); got != 16 {
		t.Errorf("DecodeAlign round trip = %d, want 16", got)
	}
}

func TestVersionParsing(t *testing.T) {
	v, err := pe.ParseVersion("10.0")
	if err != nil {
		t.Fatalf("ParseVersion: %v", err)
	}
	if v.String() != "10.0" {
		t.Errorf("String() = %q, want 10.0", v.String())
	}
	if v.IsZero() {
		t.Error("IsZero() = true for a nonzero version")
	}
	if _, err := pe.ParseVersion("not.a.version"); err == nil {
		t.Error("ParseVersion accepted garbage")
	}
}
