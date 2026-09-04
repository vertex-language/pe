package link

import "strconv"

// Small helpers shared across this package.
//
// itoa exists because pe and coff each hand-roll one to avoid importing
// strconv — they are leaf packages and keep their dependency list at zero on
// purpose — and link's diagnostics kept reaching for the name without there
// being one here. This package already depends on strconv through errors.go,
// so this is a wrapper rather than a third copy of the loop.
func itoa(v int) string { return strconv.Itoa(v) }

// min and max over ints, for the diagnostics that clamp a list before printing
// it. Go 1.23 has builtins for these; the module targets 1.23 in go.mod, so
// these should go away — they are here only until the call sites are checked.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}