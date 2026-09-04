package backend

import "github.com/vertex-language/pe"

// ThunkShape is an import thunk described rather than spelled.
//
// The thunk is the code a call to an unprefixed imported name lands in: it
// jumps through the IAT slot, and it is the PE equivalent of an ELF PLT entry.
// With __declspec(dllimport) the compiler emits an indirect call through
// __imp_foo and no thunk is retained at all, which is the more efficient shape
// and the analogue of -fno-plt.
//
// It is a shape and not a byte array because the shapes differ in kind. x86
// and x64 jump through the slot in one instruction — six bytes, with x64's
// displacement RIP-relative and x86's absolute, which is why the x86 one needs
// a base relocation and the x64 one does not. AArch32 builds the address with
// movw/movt and loads. AArch64 needs adrp/ldr/br x16, twelve bytes, because no
// single AArch64 instruction can name a 32-bit displacement. A caller that
// wanted bytes would have to know all of that; a caller that wants a size and
// a writer does not.
type ThunkShape interface {
	// Size is the thunk's length in bytes.
	Size() int

	// Align is the alignment the thunk requires.
	Align() int

	// Write emits the thunk at s, jumping through the IAT slot at slot.
	//
	// It may need base relocations of its own — the x86 shape embeds the
	// slot's absolute address — which the backend reports through Reqs
	// during Scan rather than discovering here, since here is too late for
	// .reloc to have been sized.
	Write(s *Site, slot pe.RVA) error
}