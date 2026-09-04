package pe

import "strconv"

// flagName pairs a single bit, or a group of bits, with its spelling.
type flagName struct {
	bit  uint32
	name string
}

// formatFlags renders a bitfield as NAME|NAME|0xrest. Bits with no name are
// collected into a trailing hex remainder rather than dropped, so an unknown
// flag is visible in a diff instead of silently vanishing.
//
// Entries are tested in order and consumed, so an alias of an earlier bit
// never appears twice.
func formatFlags(v uint32, names []flagName) string {
	if v == 0 {
		return "0"
	}
	s, rest := "", v
	for _, n := range names {
		if rest&n.bit == n.bit && n.bit != 0 {
			if s != "" {
				s += "|"
			}
			s += n.name
			rest &^= n.bit
		}
	}
	if rest != 0 {
		if s != "" {
			s += "|"
		}
		s += "0x" + strconv.FormatUint(uint64(rest), 16)
	}
	return s
}