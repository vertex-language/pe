package pe

// Relocation type values are per-machine and they overlap. IMAGE_REL_I386_DIR32
// and IMAGE_REL_AMD64_REL32_2 are both 6; IMAGE_REL_ARM64_SECREL and
// IMAGE_REL_AMD64_REL32_4 are both 8. A single Reloc type over uint16 would
// let an ARM64 constant be handed to an AMD64 writer and produce a file that
// is wrong in a way no bounds check catches.
//
// So each machine gets its own defined type in its own file, and the wire edge
// is the only place they become uint16 again. The three tables here are a
// template, not a generalization: a fourth architecture is a fourth file with
// the same three methods, and RelocName gains a case.

// RelocName returns the spelling of a relocation type for a machine, in
// llvm-readobj's form. The spelling matters because the stated verification
// plan for coff is to diff against llvm-readobj --coff-relocations, and a
// dumper whose names differ turns that diff into manual work.
//
// An unknown pairing renders as the number rather than guessing.
func RelocName(m Machine, typ uint16) string {
	switch m {
	case MachineAMD64:
		return RelocAMD64(typ).String()
	case MachineI386:
		return RelocI386(typ).String()
	case MachineARM64, MachineARM64EC, MachineARM64X:
		// ARM64EC objects hold AArch64 instructions and therefore
		// AArch64 relocations; the EC-ness is an ABI property expressed
		// in thunks and metadata, not in the relocation table. An
		// ARM64X image mixes objects of several machines, but each
		// object still carries its own machine and is asked about with
		// that machine, not with ARM64X.
		return RelocARM64(typ).String()
	}
	return "reloc(" + itoa(int(typ)) + ")"
}

// RelocIsPair reports whether a relocation type is one whose SymbolTableIndex
// field holds a displacement rather than an index into the symbol table.
//
// This is the single most important thing to know about a relocation before
// reading it. Nothing in either record names the other, so a reader that
// resolves the index of a PAIR entry will look up an arbitrary symbol and
// silently relocate against it. Of the seeded machines only AMD64 has such a
// type; ARM, MIPS, PowerPC, and Itanium have their own, which is why the
// invariant is stated over all machines rather than over one.
func RelocIsPair(m Machine, typ uint16) bool {
	if m == MachineAMD64 {
		return RelocAMD64(typ).IsPair()
	}
	return false
}