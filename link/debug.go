package link

import (
	"crypto/sha256"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/image"
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
)

// debugDir builds the debug data directory: an IMAGE_DEBUG_DIRECTORY array,
// a CodeView record naming a PDB, a repro hash for reproducible-build
// verification, and — when requested — an extended-DLL-characteristics entry
// carrying the /CETCOMPAT bit.
//
// It lands in its own section, .buildid, rather than .rdata: none of this is
// read at runtime, only by a debugger or a build-verification tool walking
// the directory, so it has no reason to share a page with anything the
// loader maps for execution.
type debugDir struct {
	l     *Linker
	chunk *image.Chunk

	size    uint32
	entries int
	cvOff   uint32
	cvSize  uint32
	reproOff uint32
	exOff   uint32 // 0 when there is no CET entry
	hasCET  bool
}

// reproSize is the width of the IMAGE_DEBUG_TYPE_REPRO payload: a raw SHA-256
// digest, not a length-prefixed or hex-encoded one, matching what link.exe
// and lld both write.
const reproSize = sha256.Size

// exCharacteristicsSize is IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS' payload: a
// single 32-bit flags word.
const exCharacteristicsSize = 4

func (d *debugDir) Size() uint32           { return d.size }
func (d *debugDir) Align() int             { return 4 }
func (d *debugDir) Bytes() ([]byte, error) { return nil, nil }

// Prepare lays out the directory array followed by the CodeView record, the
// repro hash slot, and the optional CET entry, then reserves one chunk
// covering all of it. A single chunk rather than one per part keeps the
// three pieces contiguous without depending on merge order, since nothing
// but this synthetic ever contributes to .buildid.
func (d *debugDir) Prepare(img *image.Image) error {
	l := d.l

	d.entries = 2
	if l.opt.CETCompat {
		d.entries = 3
	}
	dirSize := uint32(d.entries) * format.DebugDirectorySize

	cv := &format.CodeViewRecord{PDBPath: l.pdbName()}
	d.cvOff = dirSize
	d.cvSize = uint32(cv.Size())

	d.reproOff = d.cvOff + d.cvSize
	off := d.reproOff + reproSize

	if l.opt.CETCompat {
		d.hasCET = true
		d.exOff = off
		off += exCharacteristicsSize
	}
	d.size = off

	sec, err := l.section(".buildid", pe.SecInitData, pe.SecRead)
	if err != nil {
		return err
	}
	d.chunk = image.NewChunk(".buildid", "<link>", &importPart{size: d.size})
	d.chunk.Reachable = true
	if err := sec.Add(d.chunk); err != nil {
		return l.fail(err)
	}
	l.chunks = append(l.chunks, d.chunk)
	return nil
}

// Generate fills the directory array, the CodeView record, and the CET entry
// if requested. The GUID and the repro hash both stay zero here: neither can
// be known until the rest of the file — including this chunk's own
// placeholder bytes — is final, so patchRepro fills them in a second pass
// after emit.
func (d *debugDir) Generate(img *image.Image) error {
	if d.chunk == nil {
		return nil
	}
	rva, err := d.chunk.RVA()
	if err != nil {
		return err
	}

	dir := func(typ uint32, partOff, partSize uint32) (format.DebugDirectory, error) {
		partRVA := rva.Add(partOff)
		fileOff, err := img.Off(partRVA)
		if err != nil {
			return format.DebugDirectory{}, err
		}
		return format.DebugDirectory{
			Type:             typ,
			SizeOfData:       partSize,
			AddressOfRawData: uint32(partRVA),
			PointerToRawData: uint32(fileOff),
		}, nil
	}

	b := binio.NewBufSize(int(d.size))

	cvDir, err := dir(format.DebugTypeCodeView, d.cvOff, d.cvSize)
	if err != nil {
		return err
	}
	cvDir.Encode(b)

	reproDir, err := dir(format.DebugTypeRepro, d.reproOff, reproSize)
	if err != nil {
		return err
	}
	reproDir.Encode(b)

	if d.hasCET {
		exDir, err := dir(format.DebugTypeExDLLCharacteristics, d.exOff, exCharacteristicsSize)
		if err != nil {
			return err
		}
		exDir.Encode(b)
	}

	cv := &format.CodeViewRecord{PDBPath: d.l.pdbName(), Age: 1}
	cv.Encode(b)

	b.Zero(reproSize) // patched by patchRepro, once the file is final

	if d.hasCET {
		var ex pe.DllCharEx
		if d.l.opt.CETCompat {
			ex |= pe.CETCompat
		}
		b.U32(uint32(ex))
	}

	data, err := b.Data()
	if err != nil {
		return err
	}
	return writeAt(img, rva, d.size, data)
}

// Dirs returns the debug directory entry: one directory spanning every
// IMAGE_DEBUG_DIRECTORY record this synthetic wrote, since the format has no
// per-type sub-directory the way resources does.
func (d *debugDir) Dirs() []dirEntry {
	if d.chunk == nil {
		return nil
	}
	rva, err := d.chunk.RVA()
	if err != nil {
		return nil
	}
	return []dirEntry{{pe.DirDebug, rva, uint32(d.entries) * format.DebugDirectorySize}}
}

// patchRepro computes the SHA-256 of the finished image with the GUID and
// the repro hash both still zero, then writes that hash into both fields.
//
// It cannot run as a Finalizer: a Finalizer runs during fill, before emit has
// written the PE header and section table, so "the finished image" would be
// missing most of the file. It runs as an explicit statement in Link instead,
// after emit and after the dynamic relocations patch the header, and before
// the checksum — which must cover these bytes, not run before they exist.
func (d *debugDir) patchRepro(img *image.Image) error {
	if d.chunk == nil {
		return nil
	}
	data, err := img.Bytes()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)

	rva, err := d.chunk.RVA()
	if err != nil {
		return err
	}
	guidOff, err := img.Off(rva.Add(d.cvOff + 4)) // past the 4-byte 'RSDS' signature
	if err != nil {
		return err
	}
	guid, err := img.At(guidOff, format.CodeViewGUIDSize)
	if err != nil {
		return err
	}
	copy(guid, sum[:format.CodeViewGUIDSize])

	reproOff, err := img.Off(rva.Add(d.reproOff))
	if err != nil {
		return err
	}
	repro, err := img.At(reproOff, reproSize)
	if err != nil {
		return err
	}
	copy(repro, sum[:])
	return nil
}

// pdbName is the path the CodeView record points a debugger at.
//
// This package never writes a PDB, so the field names one on faith — but
// every real toolchain does exactly that even when the PDB does not exist
// yet, because the alternative (an empty path) tells a debugger there is
// definitely nothing to look for, rather than something it merely could not
// find.
func (l *Linker) pdbName() string {
	if l.opt.PDBPath != "" {
		return l.opt.PDBPath
	}
	return l.outputName() + ".pdb"
}
