package pe

// The optional header ends with an array of address/size pairs, one per
// special table the loader knows about. Two things about it are load-bearing
// and both are easy to get wrong.
//
// The count is variable. NumberOfRvaAndSizes says how many entries are
// actually present, and SizeOfOptionalHeader bounds the whole header, so a
// probe for a particular directory must be checked against both before it is
// trusted. Assuming sixteen is the single most common way to read past the
// end of a truncated or hostile file. That check lives in exactly one function
// in internal/format, not at every call site.
//
// And one entry is not an RVA. See DirCertificate.

// DataDirIndex names a slot in the data directory array.
type DataDirIndex int

const (
	DirExport      DataDirIndex = 0  // .edata
	DirImport      DataDirIndex = 1  // .idata
	DirResource    DataDirIndex = 2  // .rsrc
	DirException   DataDirIndex = 3  // .pdata
	DirCertificate DataDirIndex = 4  // attribute certificates — a file offset
	DirBaseReloc   DataDirIndex = 5  // .reloc
	DirDebug       DataDirIndex = 6  // .debug
	DirArchitecture DataDirIndex = 7 // reserved, must be zero
	DirGlobalPtr   DataDirIndex = 8  // RVA of the global pointer; size must be zero
	DirTLS         DataDirIndex = 9  // .tls
	DirLoadConfig  DataDirIndex = 10 // _load_config_used
	DirBoundImport DataDirIndex = 11 // written by /BIND; this tree never emits one
	DirIAT         DataDirIndex = 12 // the import address table
	DirDelayImport DataDirIndex = 13 // delay-load descriptors
	DirCLRHeader   DataDirIndex = 14 // .cormeta
	DirReserved    DataDirIndex = 15 // reserved, must be zero
)

const (
	// NumDataDirs is the count a full optional header carries. It is not a
	// guarantee: read NumberOfRvaAndSizes.
	NumDataDirs = 16

	// DataDirSize is the size of one entry: two 32-bit words.
	DataDirSize = 8
)

// UsesFileOffset reports whether this directory's first word is a file offset
// rather than an RVA.
//
// Exactly one directory answers yes. The attribute certificates are not mapped
// into memory — they sit past the last section and are excluded from the
// image's own hash — so an RVA would be meaningless for them and the field
// holds a file pointer instead. This is the reason RVA and Off are separate
// types in this module: in a uint32 world the distinction is a comment, and
// image.DataDir would have one field where it needs two.
func (d DataDirIndex) UsesFileOffset() bool { return d == DirCertificate }

// MustBeZero reports whether the specification reserves this directory. A
// non-zero value in one is not an error to read, but this tree never writes
// one.
func (d DataDirIndex) MustBeZero() bool {
	return d == DirArchitecture || d == DirReserved
}

// Valid reports whether d is within the sixteen defined slots.
func (d DataDirIndex) Valid() bool { return d >= 0 && d < NumDataDirs }

func (d DataDirIndex) String() string {
	switch d {
	case DirExport:
		return "export"
	case DirImport:
		return "import"
	case DirResource:
		return "resource"
	case DirException:
		return "exception"
	case DirCertificate:
		return "certificate"
	case DirBaseReloc:
		return "basereloc"
	case DirDebug:
		return "debug"
	case DirArchitecture:
		return "architecture"
	case DirGlobalPtr:
		return "globalptr"
	case DirTLS:
		return "tls"
	case DirLoadConfig:
		return "loadconfig"
	case DirBoundImport:
		return "boundimport"
	case DirIAT:
		return "iat"
	case DirDelayImport:
		return "delayimport"
	case DirCLRHeader:
		return "clrheader"
	case DirReserved:
		return "reserved"
	}
	return "datadir(" + itoa(int(d)) + ")"
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [12]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}