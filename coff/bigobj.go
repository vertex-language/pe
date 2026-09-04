package coff

import "github.com/vertex-language/pe"

// The bigobj variant exists for one reason: a 16-bit section count. An object
// with more sections than that can hold gets ANON_OBJECT_HEADER_BIGOBJ, which
// widens the count to 32 bits and the symbol record to 20 bytes.
//
// It is not a superset. The bigobj header has no Characteristics field, so
// promotion is lossy for an object that set one, and this tree makes that an
// error rather than a silent drop — see ErrBigObjDropsCharacteristics.

// BigObjMode decides whether Close writes a bigobj header.
//
// All three exist so a build can be byte-deterministic across toolchain
// versions. BigObjAuto is what a compiler wants; the other two are what a
// build system wants when the output is compared against a reference.
type BigObjMode uint8

const (
	// BigObjAuto promotes when the section count requires it.
	BigObjAuto BigObjMode = iota
	// BigObjNever refuses to promote, making an oversized object an error.
	BigObjNever
	// BigObjAlways promotes unconditionally.
	BigObjAlways
)

func (m BigObjMode) String() string {
	switch m {
	case BigObjAuto:
		return "auto"
	case BigObjNever:
		return "never"
	case BigObjAlways:
		return "always"
	}
	return "bigobj(" + itoa(int(m)) + ")"
}

// needsBigObj reports whether nsec sections require the wide header.
//
// The threshold is a ceiling, not a limit: section numbers above
// pe.MaxSections16 are reserved by the specification, so the remaining values
// up to 0xffff cannot simply be used.
func needsBigObj(nsec int) bool { return nsec > pe.MaxSections16 }

// pickHeaderFamily resolves the mode against the object being written.
//
// The Characteristics check applies to promotion, not to bigobj as such:
// BigObjAlways with characteristics set is the same loss as BigObjAuto that
// happened to cross the ceiling, and both are refused.
func pickHeaderFamily(mode BigObjMode, nsec int, char pe.FileChar) (bool, error) {
	big := false
	switch mode {
	case BigObjAlways:
		big = true
	case BigObjNever:
		if needsBigObj(nsec) {
			return false, ErrBigObjRequired
		}
	case BigObjAuto:
		big = needsBigObj(nsec)
	default:
		big = needsBigObj(nsec)
	}
	if big && char != 0 {
		return false, ErrBigObjDropsCharacteristics
	}
	return big, nil
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