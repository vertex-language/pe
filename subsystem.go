package pe

// Subsystem is the environment an image needs, from the optional header. It
// decides which entry point the CRT supplies and, for the EFI values, that the
// image is a flat one with SectionAlignment below the page size.
type Subsystem uint16

const (
	SubsystemUnknown            Subsystem = 0
	SubsystemNative             Subsystem = 1  // device drivers and native processes
	SubsystemGUI                Subsystem = 2  // IMAGE_SUBSYSTEM_WINDOWS_GUI
	SubsystemConsole            Subsystem = 3  // IMAGE_SUBSYSTEM_WINDOWS_CUI
	SubsystemOS2Console         Subsystem = 5
	SubsystemPosixConsole       Subsystem = 7
	SubsystemNativeWindows      Subsystem = 8  // native Win9x driver
	SubsystemWindowsCEGUI       Subsystem = 9
	SubsystemEFIApplication     Subsystem = 10
	SubsystemEFIBootDriver      Subsystem = 11 // EFI driver with boot services
	SubsystemEFIRuntimeDriver   Subsystem = 12 // EFI driver with run-time services
	SubsystemEFIROM             Subsystem = 13
	SubsystemXbox               Subsystem = 14
	SubsystemWindowsBootApp     Subsystem = 16
	// 4, 6, and 15 are unassigned. The gaps are in the specification.
)

// IsEFI reports whether s is one of the four EFI subsystems. These imply the
// flat-image alignment mode, in which a section's file offset must equal its
// RVA — declared up front on the Target rather than discovered during layout.
func (s Subsystem) IsEFI() bool {
	return s >= SubsystemEFIApplication && s <= SubsystemEFIROM
}

func (s Subsystem) String() string {
	switch s {
	case SubsystemNative:
		return "native"
	case SubsystemGUI:
		return "windows"
	case SubsystemConsole:
		return "console"
	case SubsystemOS2Console:
		return "os2"
	case SubsystemPosixConsole:
		return "posix"
	case SubsystemNativeWindows:
		return "native-windows"
	case SubsystemWindowsCEGUI:
		return "windowsce"
	case SubsystemEFIApplication:
		return "efi-application"
	case SubsystemEFIBootDriver:
		return "efi-boot-driver"
	case SubsystemEFIRuntimeDriver:
		return "efi-runtime-driver"
	case SubsystemEFIROM:
		return "efi-rom"
	case SubsystemXbox:
		return "xbox"
	case SubsystemWindowsBootApp:
		return "bootapp"
	case SubsystemUnknown:
		return "unknown"
	}
	return "subsystem(" + itoa(int(s)) + ")"
}

// DllChar is the DllCharacteristics field of the optional header. Despite the
// name it applies to executables as much as to DLLs: DynamicBase, NXCompat,
// and GuardCF are the three security features a modern .exe is expected to
// declare.
type DllChar uint16

const (
	// Bits 0x0001 through 0x0008 and 0x0010 are reserved and must be zero.

	// HighEntropyVA means the image tolerates a high-entropy 64-bit address
	// space. It has no effect without DynamicBase.
	HighEntropyVA DllChar = 0x0020
	// DynamicBase means the image can be relocated at load time — ASLR.
	// Without it, the base relocations may as well not exist.
	DynamicBase DllChar = 0x0040
	// ForceIntegrity means code integrity checks are enforced.
	ForceIntegrity DllChar = 0x0080
	// NXCompat means the image is compatible with data execution prevention.
	NXCompat DllChar = 0x0100
	// NoIsolation means isolation aware, but do not isolate.
	NoIsolation DllChar = 0x0200
	// NoSEH means no structured exception handler may be called in this
	// image.
	NoSEH DllChar = 0x0400
	// NoBind tells the loader not to use bound import data. This tree sets
	// it by default, because it never produces the bound import directory
	// and stale bindings are worse than none.
	NoBind DllChar = 0x0800
	// AppContainer means the image must execute in an AppContainer.
	AppContainer DllChar = 0x1000
	// WDMDriver marks a Windows Driver Model driver.
	WDMDriver DllChar = 0x2000
	// GuardCF means the image supports Control Flow Guard. Setting it
	// without DynamicBase is an error, not a no-op: CFG depends on ASLR.
	GuardCF DllChar = 0x4000
	// TerminalServerAware means the image is Terminal Server aware.
	TerminalServerAware DllChar = 0x8000
)

// Has reports whether every bit in c is set in d.
func (d DllChar) Has(c DllChar) bool { return d&c == c }

var dllCharNames = []flagName{
	{uint32(HighEntropyVA), "HIGH_ENTROPY_VA"},
	{uint32(DynamicBase), "DYNAMIC_BASE"},
	{uint32(ForceIntegrity), "FORCE_INTEGRITY"},
	{uint32(NXCompat), "NX_COMPAT"},
	{uint32(NoIsolation), "NO_ISOLATION"},
	{uint32(NoSEH), "NO_SEH"},
	{uint32(NoBind), "NO_BIND"},
	{uint32(AppContainer), "APPCONTAINER"},
	{uint32(WDMDriver), "WDM_DRIVER"},
	{uint32(GuardCF), "GUARD_CF"},
	{uint32(TerminalServerAware), "TERMINAL_SERVER_AWARE"},
}

func (d DllChar) String() string { return formatFlags(uint32(d), dllCharNames) }

// DllCharEx is the extended DLL characteristics bitmask.
//
// It is not a field of the optional header — DllChar's sixteen bits ran out
// — but a 32-bit value carried in an IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
// debug directory entry. CETCompat is the only bit any current toolchain
// sets.
type DllCharEx uint32

const (
	// CETCompat means the image is compatible with Intel CET shadow stacks
	// (Hardware-enforced Stack Protection). Setting it on code that was not
	// actually compiled with shadow-stack instrumentation is not a no-op:
	// the loader enables shadow-stack enforcement for the process on the
	// strength of this bit, and every return address it does not expect to
	// find is CFG-equivalent to a crash on the first mismatch.
	CETCompat DllCharEx = 0x1
)

// Has reports whether every bit in c is set in d.
func (d DllCharEx) Has(c DllCharEx) bool { return d&c == c }