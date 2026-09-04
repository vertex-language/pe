package image

import "github.com/vertex-language/pe"

// DataDir is the sixteen data directories, filled from final RVAs at the end
// of a link.
//
// The certificate entry is a separate field of a different type, and that is
// the whole reason this structure is not an array. Fifteen directories store
// an RVA; the Certificate Table stores a file pointer, because the attribute
// certificates are not mapped into memory — they sit past the last section and
// are hashed out of the image's own signature. In a uint32 world that
// distinction is a comment. Here Dirs cannot hold the certificate entry
// because the types do not match.
type DataDir struct {
	// Dirs holds the fifteen RVA-typed directories. The certificate slot is
	// present so indices line up with pe.DataDirIndex, and is never read:
	// Dir and Set reject it.
	Dirs [pe.NumDataDirs]struct {
		RVA  pe.RVA
		Size uint32
	}

	// CertDir is the Certificate Table: a file offset and a size.
	//
	// link never fills it. The certificate table is appended to a finished
	// image by authenticode, which does not disturb a byte of layout, so
	// this exists for a reader describing an image someone else signed.
	CertDir struct {
		Off  pe.Off
		Size uint32
	}
}

// Set records a directory's address and size.
//
// It refuses DirCertificate, whose first word is not an RVA. A caller with a
// certificate entry sets CertDir directly, and having to reach for a
// differently typed field is the point.
func (d *DataDir) Set(i pe.DataDirIndex, rva pe.RVA, size uint32) error {
	if !i.Valid() {
		return ErrOutOfBounds
	}
	if i.UsesFileOffset() {
		return ErrCertDirIsFileOffset
	}
	if i.MustBeZero() {
		return ErrReservedDir
	}
	d.Dirs[i].RVA, d.Dirs[i].Size = rva, size
	return nil
}

// Dir returns a directory's address and size.
func (d *DataDir) Dir(i pe.DataDirIndex) (pe.RVA, uint32, error) {
	if !i.Valid() {
		return 0, 0, ErrOutOfBounds
	}
	if i.UsesFileOffset() {
		return 0, 0, ErrCertDirIsFileOffset
	}
	return d.Dirs[i].RVA, d.Dirs[i].Size, nil
}