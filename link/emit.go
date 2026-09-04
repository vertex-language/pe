package link

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/image"
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
)

// Emit serializes the headers into the space layout reserved for them at RVA 0
// and then computes the checksum over the finished file.
//
// Everything it writes is a restatement of decisions made earlier — the
// section table restates the placement, the optional header restates the
// alignments and the sizes — with one exception that is easy to miss. The COFF
// header's Machine field is not the target's machine. An ARM64EC image is
// marked AMD64 so the x64 loader path accepts it, and an ARM64X image is
// marked ARM64; both are object-only machine types that no loader will take in
// a header. That is what Machine.ImageMachine exists for, and it is the reason
// nothing in this tree writes pe.Machine into a header directly.

// linkerVersion is written into MajorLinkerVersion and MinorLinkerVersion.
//
// Nothing consults it. dumpbin prints it, and a byte diff against link.exe
// output that differs only here is a diff nobody reads past, so it claims a
// plausible MSVC version rather than zero.
const (
	linkerVersionMajor = 14
	linkerVersionMinor = 0
)

// emit writes the DOS stub, the PE signature, and the three headers.
func (l *Linker) emit() error {
	img := l.img
	sizeOfHeaders, err := img.SizeOfHeaders()
	if err != nil {
		return l.fail(err)
	}

	b := binio.NewBufSize(int(sizeOfHeaders))
	stub, err := l.stub()
	if err != nil {
		return err
	}
	b.Bytes(stub)
	b.Bytes(format.PESignature[:])

	opt, err := l.optionalHeader()
	if err != nil {
		return err
	}
	fh := format.FileHeader{
		// ImageMachine, never Machine.
		Machine:              uint16(l.opt.Target.Machine.ImageMachine()),
		NumberOfSections:     uint16(len(img.Sections())),
		TimeDateStamp:        l.opt.TimeStamp,
		PointerToSymbolTable: 0, // COFF debugging information is deprecated
		NumberOfSymbols:      0,
		SizeOfOptionalHeader: uint16(opt.Size(l.opt.Target.Width())),
		Characteristics:      uint16(l.fileCharacteristics()),
	}
	fh.Encode(b)
	opt.Encode(b, l.opt.Target.Width())

	for _, s := range img.Sections() {
		h, err := l.sectionHeader(s)
		if err != nil {
			return err
		}
		h.Encode(b)
	}

	data, err := b.Data()
	if err != nil {
		return l.fail(err)
	}
	if uint32(len(data)) > sizeOfHeaders {
		// HeaderSize is an input to address assignment, so this cannot
		// differ from what layout assumed without the first section
		// having been placed on top of the section table.
		return l.fail(&image.LayoutError{
			Reason: "headers encode to " + itoa(len(data)) +
				" bytes, more than layout reserved",
		})
	}
	out, err := img.At(0, len(data))
	if err != nil {
		return l.fail(err)
	}
	copy(out, data)
	return nil
}

// stub returns the MS-DOS stub with its PE signature offset patched in.
//
// A caller's stub is used verbatim except for that one field, because a stub
// is a place people put things — /STUB exists so a build can ship its own
// message, and some installers hide payloads there. The length must match what
// Config.StubSize told layout, since it fed SizeOfHeaders and therefore every
// address in the image.
func (l *Linker) stub() ([]byte, error) {
	if len(l.opt.Stub) == 0 {
		b := binio.NewBufSize(format.DOSHeaderSize)
		h := format.DOSHeader{Magic: format.DOSMagic, Lfanew: format.DOSHeaderSize}
		h.Encode(b)
		return b.Data()
	}
	stub := append([]byte(nil), l.opt.Stub...)
	if len(stub) < format.LfanewOffset+4 {
		return nil, l.fail(&image.LayoutError{
			Reason: "supplied MS-DOS stub is too short to hold the PE signature offset",
		})
	}
	if stub[0] != 'M' || stub[1] != 'Z' {
		return nil, l.fail(&image.LayoutError{
			Reason: "supplied MS-DOS stub does not begin with the MZ magic",
		})
	}
	n := uint32(len(stub))
	stub[format.LfanewOffset+0] = byte(n)
	stub[format.LfanewOffset+1] = byte(n >> 8)
	stub[format.LfanewOffset+2] = byte(n >> 16)
	stub[format.LfanewOffset+3] = byte(n >> 24)
	return stub, nil
}

// fileCharacteristics assembles the COFF header's flag field.
//
// RELOCS_STRIPPED is the interesting one: it is set when the image has no base
// relocation table, and it tells the loader that the image must load at its
// preferred base or not at all. It is therefore the exact complement of
// /DYNAMICBASE, and setting both is an image that claims to be relocatable and
// says it cannot be moved.
func (l *Linker) fileCharacteristics() pe.FileChar {
	c := pe.FileExecutable | l.opt.FileChar
	if l.opt.Target.Width() == pe.Width64 {
		c |= pe.FileLargeAddressAware
	} else {
		c |= pe.File32BitMachine
	}
	if !l.opt.DllChar.Has(pe.DynamicBase) {
		c |= pe.FileRelocsStripped
	}
	switch l.opt.Kind {
	case OutputDLL:
		c |= pe.FileDLL
	case OutputSYS:
		c |= pe.FileSystem
	}
	return c
}

// optionalHeader assembles the header between the file header and the section
// table.
func (l *Linker) optionalHeader() (*format.OptionalHeader, error) {
	img := l.img
	w := l.opt.Target.Width()

	sizeOfImage, sizeOfHeaders, err := l.sizes()
	if err != nil {
		return nil, l.fail(err)
	}
	code, err := l.sizeOfCode()
	if err != nil {
		return nil, l.fail(err)
	}
	initialized, uninitialized, err := l.dataSizes()
	if err != nil {
		return nil, l.fail(err)
	}
	entry, err := l.entryRVA()
	if err != nil {
		return nil, err
	}
	stackReserve, stackCommit := l.opt.Stack()
	heapReserve, heapCommit := l.opt.Heap()
	osVer, subVer := l.opt.OSVer(), l.opt.SubVersion()

	h := &format.OptionalHeader{
		MajorLinkerVersion:      linkerVersionMajor,
		MinorLinkerVersion:      linkerVersionMinor,
		SizeOfCode:              code,
		SizeOfInitializedData:   initialized,
		SizeOfUninitializedData: uninitialized,
		AddressOfEntryPoint:     uint32(entry),
		BaseOfCode:              uint32(l.baseOf(pe.SecCode)),
		ImageBase:               uint64(l.opt.Base()),
		SectionAlignment:        img.Cfg.SectionAlignment,
		FileAlignment:           img.Cfg.FileAlignment,
		SizeOfImage:             sizeOfImage,
		SizeOfHeaders:           sizeOfHeaders,
		Subsystem:               uint16(l.opt.Sub()),
		DllCharacteristics:      uint16(l.opt.DllChar),
		SizeOfStackReserve:      stackReserve,
		SizeOfStackCommit:       stackCommit,
		SizeOfHeapReserve:       heapReserve,
		SizeOfHeapCommit:        heapCommit,

		MajorOperatingSystemVersion: osVer.Major,
		MinorOperatingSystemVersion: osVer.Minor,
		MajorImageVersion:           l.opt.ImageVer.Major,
		MinorImageVersion:           l.opt.ImageVer.Minor,
		MajorSubsystemVersion:       subVer.Major,
		MinorSubsystemVersion:       subVer.Minor,

		// Win32VersionValue and LoaderFlags are reserved and must be
		// zero. CheckSum is written last, over the finished file, and
		// is zero here because it is computed with itself read as zero.
		Win32VersionValue: 0,
		LoaderFlags:       0,
		CheckSum:          0,
	}
	if w == pe.Width32 {
		// The only field that exists in one width and not the other,
		// and the reason OptionalHeaderSize is the one function in the
		// tree that knows it.
		h.BaseOfData = uint32(l.baseOf(pe.SecInitData))
	}

	ndirs := img.Cfg.NumDataDirs
	h.Dirs = make([]format.DataDir, ndirs)
	for i := 0; i < ndirs; i++ {
		idx := pe.DataDirIndex(i)
		if idx.UsesFileOffset() {
			// The certificate table. link never writes one: the
			// signature is appended to a finished image and this
			// entry is authenticode's to fill.
			continue
		}
		rva, size, err := img.Dirs.Dir(idx)
		if err != nil {
			continue
		}
		h.Dirs[i] = format.DataDir{VirtualAddress: uint32(rva), Size: size}
	}
	return h, nil
}

// entryRVA resolves the entry point.
//
// A DLL may legitimately have none — the field is then zero and the loader
// calls nothing on attach — but an executable without one is an image that
// cannot start, and the useful answer is /ENTRY rather than a zero the loader
// will jump to.
func (l *Linker) entryRVA() (pe.RVA, error) {
	name := l.opt.EntryName()
	if name == "" {
		if l.opt.Kind == OutputDLL {
			return 0, nil
		}
		return 0, l.fail(ErrNoEntry)
	}
	s := l.tabs[0].Lookup(name)
	if s == nil || s.Out == nil {
		if l.opt.Kind == OutputDLL {
			return 0, nil
		}
		return 0, l.fail(&UndefinedError{Name: name, Refs: []string{"<entry point>"}})
	}
	rva, err := s.Out.RVA()
	if err != nil {
		return 0, l.fail(&InputError{Name: name, Err: err})
	}
	l.img.Native().Entry = rva
	return rva, nil
}

// baseOf returns the RVA of the first section with a content flag, which is
// what BaseOfCode and BaseOfData report.
//
// Both fields are advisory — nothing in the loader consults either — and both
// are zero in an image with no such section rather than pointing at the
// headers.
func (l *Linker) baseOf(kind pe.SecKind) pe.RVA {
	for _, s := range l.img.Sections() {
		if !s.Kind.Has(kind) {
			continue
		}
		if rva, err := s.RVA(); err == nil {
			return rva
		}
	}
	return 0
}

// dataSizes sums the initialized and uninitialized section sizes.
//
// Initialized data is measured on disk and uninitialized in memory, because
// the second has no bytes on disk to measure. A section that is both — which
// the flags permit and some producers emit — counts once, as initialized.
func (l *Linker) dataSizes() (initialized, uninitialized uint32, err error) {
	for _, s := range l.img.Sections() {
		if s.Kind.Has(pe.SecCode) {
			continue
		}
		switch {
		case s.Kind.Has(pe.SecInitData):
			n, err := s.SizeOfRawData()
			if err != nil {
				return 0, 0, err
			}
			initialized += n
		case s.Kind.Has(pe.SecUninitData):
			n, err := s.VirtualSize()
			if err != nil {
				return 0, 0, err
			}
			uninitialized += n
		}
	}
	return initialized, uninitialized, nil
}

// sectionHeader restates one section's placement.
//
// VirtualSize is unrounded and SizeOfRawData is rounded to FileAlignment, so
// either can be the larger: a small section is bigger on disk and one with a
// zero-filled tail is bigger in memory. Code that assumes an order between
// them is wrong in one of the two directions, which is why image computes both
// and this only copies them.
//
// The alignment nibble is absent, and that is not an omission. Alignment is an
// object-file property; every section in an image is aligned to
// SectionAlignment, and a nibble here would describe a constraint the format
// does not honour.
func (l *Linker) sectionHeader(s *image.Section) (format.SectionHeader, error) {
	var h format.SectionHeader
	if len(s.Name) > format.SectionNameSize {
		return h, l.fail(&image.LayoutError{
			Section: s.Name,
			Reason:  "image section names cannot exceed eight bytes and there is no string table",
		})
	}
	copy(h.Name[:], s.Name)

	rva, err := s.RVA()
	if err != nil {
		return h, l.fail(err)
	}
	off, err := s.Off()
	if err != nil {
		return h, l.fail(err)
	}
	vsize, err := s.VirtualSize()
	if err != nil {
		return h, l.fail(err)
	}
	raw, err := s.SizeOfRawData()
	if err != nil {
		return h, l.fail(err)
	}

	h.VirtualAddress = uint32(rva)
	h.VirtualSize = vsize
	h.SizeOfRawData = raw
	h.PointerToRawData = uint32(off)
	// Zero in an image: there are no COFF relocations and no line numbers,
	// and a non-zero value here is how a reader ends up parsing section
	// data as a relocation table.
	h.PointerToRelocations = 0
	h.PointerToLinenumbers = 0
	h.NumberOfRelocations = 0
	h.NumberOfLinenumbers = 0
	h.Characteristics = uint32(s.Kind) | uint32(s.Prot)
	return h, nil
}

// checksumFinalizer computes the header checksum over the finished file.
//
// It runs last, after every other byte including the dynamic relocations, and
// that ordering is the only thing that makes the value right: the checksum
// covers the file, so anything written after it invalidates it.
type checksumFinalizer struct{ l *Linker }

// Finalize writes the checksum.
//
// The algorithm is a 16-bit ones-complement sum over the whole file with the
// checksum field itself read as zero, plus the file's length. Reading the
// field as zero is what makes it self-consistent — the value cannot depend on
// itself — and the length is added at the end so that two files differing only
// by trailing zeroes do not agree.
//
// It matters for drivers, for DLLs loaded at boot, and for anything mapped
// into a critical process; the loader validates it for those and ignores it for
// everything else. Emitting zero would be legal for an ordinary executable and
// wrong for a .sys, and there is no way to tell from here which one the caller
// is building.
func (c *checksumFinalizer) Finalize(img *image.Image) error {
	l := c.l
	data, err := img.Bytes()
	if err != nil {
		return err
	}
	off, err := l.checksumOffset()
	if err != nil {
		return err
	}
	sum := imageChecksum(data, off)
	out, err := img.At(off, 4)
	if err != nil {
		return err
	}
	out[0], out[1], out[2], out[3] = byte(sum), byte(sum>>8), byte(sum>>16), byte(sum>>24)
	return nil
}

// checksumOffset returns the file offset of the optional header's CheckSum
// field: past the stub, the signature, and the file header, then 64 bytes into
// the optional header at either width.
//
// Sixty-four is the same at PE32 and PE32+ by coincidence rather than by
// design — PE32 has BaseOfData and four-byte ImageBase where PE32+ has an
// eight-byte ImageBase and no BaseOfData, and the two cancel — which is
// exactly the kind of coincidence worth writing down before someone relies on
// it for a field further along.
const checksumFieldOffset = 64

func (l *Linker) checksumOffset() (pe.Off, error) {
	stub := uint32(len(l.opt.Stub))
	if stub == 0 {
		stub = format.DOSHeaderSize
	}
	return pe.Off(stub + format.PESignatureSize + format.FileHeaderSize + checksumFieldOffset), nil
}

// imageChecksum computes the checksum of b with the four bytes at skip read as
// zero.
//
// The sum folds the carry back in after every word, which is what keeps it a
// 16-bit ones-complement sum rather than a 32-bit one truncated at the end;
// the two disagree. An odd-length file — which FileAlignment makes impossible
// for anything this tree emits, but not for a signed file authenticode has
// appended to — is padded with a zero byte.
func imageChecksum(b []byte, skip pe.Off) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		w := uint32(b[i]) | uint32(b[i+1])<<8
		if pe.Off(i) >= skip && pe.Off(i) < skip+4 {
			w = 0
		}
		sum += w
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1])
		sum = (sum & 0xffff) + (sum >> 16)
	}
	sum = (sum & 0xffff) + (sum >> 16)
	return sum + uint32(len(b))
}