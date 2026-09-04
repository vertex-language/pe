package pe

// Control Flow Guard metadata lives in the load configuration directory. The
// linker's part is to collect targets from the four guard sections —
// .gfids$y, .giats$y, .gljmp$y, and .gehcont$y — build sorted RVA tables from
// them, and fill the directory's fields and flags.
//
// Two of these tables must be sorted or the image will not load at all, which
// is why the sort happens after Freeze, when addresses are final, rather than
// wherever the entries were collected.

// GuardFlags is the GuardFlags field of the load configuration directory. Its
// low bits are feature flags and its top nibble is a size, not a flag — see
// GFIDSEntrySize.
type GuardFlags uint32

const (
	// GuardCFInstrumented means the module performs control flow integrity
	// checks on indirect calls.
	GuardCFInstrumented GuardFlags = 0x00000100
	// GuardCFWInstrumented means the module performs write integrity checks.
	GuardCFWInstrumented GuardFlags = 0x00000200
	// GuardCFFunctionTablePresent means the module has a valid CFG target
	// table — the GFIDS table.
	GuardCFFunctionTablePresent GuardFlags = 0x00000400
	// GuardSecurityCookieUnused means the module does not use a /GS cookie.
	GuardSecurityCookieUnused GuardFlags = 0x00000800
	// GuardProtectDelayloadIAT means the delay-load IAT is read-only.
	GuardProtectDelayloadIAT GuardFlags = 0x00001000
	// GuardDelayloadIATInItsOwnSection means the delay-load IAT lives in
	// .didat, so it can be page-protected independently.
	GuardDelayloadIATInItsOwnSection GuardFlags = 0x00002000
	// GuardCFExportSuppressionInfoPresent means the CFG target table
	// carries export suppression information.
	GuardCFExportSuppressionInfoPresent GuardFlags = 0x00004000
	// GuardCFEnableExportSuppression means export suppression is enforced.
	GuardCFEnableExportSuppression GuardFlags = 0x00008000
	// GuardCFLongjumpTablePresent means the module has a longjmp target
	// table, built from .gljmp$y.
	GuardCFLongjumpTablePresent GuardFlags = 0x00010000

	// The Return Flow Guard and retpoline bits below, and the EH
	// continuation bit, come from winnt.h rather than from the PE
	// specification. Only the EH continuation flag matters to this tree,
	// and only under /GUARD:EHCONT.
	GuardRFInstrumented          GuardFlags = 0x00020000
	GuardRFEnable                GuardFlags = 0x00040000
	GuardRFStrict                GuardFlags = 0x00080000
	GuardRetpolinePresent        GuardFlags = 0x00100000
	GuardEHContinuationTablePresent GuardFlags = 0x00400000

	// GuardCFFunctionTableSizeMask holds the count of metadata bytes
	// attached to each GFIDS entry, beyond the four bytes of RVA.
	GuardCFFunctionTableSizeMask  GuardFlags = 0xf0000000
	guardCFFunctionTableSizeShift             = 28
)

// Has reports whether every bit in f is set in g.
func (g GuardFlags) Has(f GuardFlags) bool { return g&f == f }

// GFIDSEntrySize returns the size in bytes of one entry in the guard CF
// function table, which is four bytes of RVA plus n bytes of metadata, where n
// is encoded in the top nibble of GuardFlags itself.
//
// The only metadata currently defined is a single byte of GFIDSFlags, so n is
// 0 or 1 in practice — but reading the stride from the flags rather than
// assuming it is what lets a future entry format be walked correctly, and what
// lets this tree walk one it does not understand.
func (g GuardFlags) GFIDSEntrySize() int {
	return 4 + int((g&GuardCFFunctionTableSizeMask)>>guardCFFunctionTableSizeShift)
}

// WithGFIDSMetadataBytes returns g with its table-stride nibble set to n,
// which must be 0 through 15.
func (g GuardFlags) WithGFIDSMetadataBytes(n int) (GuardFlags, bool) {
	if n < 0 || n > 15 {
		return g, false
	}
	return (g &^ GuardCFFunctionTableSizeMask) |
		GuardFlags(uint32(n)<<guardCFFunctionTableSizeShift), true
}

var guardFlagNames = []flagName{
	{uint32(GuardCFInstrumented), "CF_INSTRUMENTED"},
	{uint32(GuardCFWInstrumented), "CFW_INSTRUMENTED"},
	{uint32(GuardCFFunctionTablePresent), "CF_FUNCTION_TABLE_PRESENT"},
	{uint32(GuardSecurityCookieUnused), "SECURITY_COOKIE_UNUSED"},
	{uint32(GuardProtectDelayloadIAT), "PROTECT_DELAYLOAD_IAT"},
	{uint32(GuardDelayloadIATInItsOwnSection), "DELAYLOAD_IAT_IN_ITS_OWN_SECTION"},
	{uint32(GuardCFExportSuppressionInfoPresent), "CF_EXPORT_SUPPRESSION_INFO_PRESENT"},
	{uint32(GuardCFEnableExportSuppression), "CF_ENABLE_EXPORT_SUPPRESSION"},
	{uint32(GuardCFLongjumpTablePresent), "CF_LONGJUMP_TABLE_PRESENT"},
	{uint32(GuardRFInstrumented), "RF_INSTRUMENTED"},
	{uint32(GuardRFEnable), "RF_ENABLE"},
	{uint32(GuardRFStrict), "RF_STRICT"},
	{uint32(GuardRetpolinePresent), "RETPOLINE_PRESENT"},
	{uint32(GuardEHContinuationTablePresent), "EH_CONTINUATION_TABLE_PRESENT"},
}

// String renders the feature flags. The table-stride nibble is deliberately
// left in the hex remainder rather than named, because it is a number wearing
// a flag's clothing and printing it as one has confused readers of dumpbin
// output for years.
func (g GuardFlags) String() string {
	return formatFlags(uint32(g&^GuardCFFunctionTableSizeMask), guardFlagNames) +
		"+" + itoa(g.GFIDSEntrySize()-4) + "b"
}

// GFIDSFlags is the optional one-byte metadata attached to a guard CF function
// table entry, present only when GuardFlags says the stride leaves room.
type GFIDSFlags uint8

const (
	// GFIDSSuppressed means the target is explicitly not a valid indirect
	// call target, despite appearing in the table.
	GFIDSSuppressed GFIDSFlags = 0x1
	// GFIDSExportSuppressed means the target is export suppressed.
	GFIDSExportSuppressed GFIDSFlags = 0x2
)

func (f GFIDSFlags) String() string {
	return formatFlags(uint32(f), []flagName{
		{uint32(GFIDSSuppressed), "FID_SUPPRESSED"},
		{uint32(GFIDSExportSuppressed), "EXPORT_SUPPRESSED"},
	})
}