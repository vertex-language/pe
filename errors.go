// Package pe defines the identity types and constant tables shared by every
// package in this module: machine types, address kinds, and targets.
//
// It performs no I/O and depends on nothing else in the tree.
package pe

import (
	"errors"
	"fmt"
)

// Sentinel errors returned, or wrapped, by this package. Callers match with
// errors.Is; the wrapped forms carry the offending value in their message.
var (
	// ErrNotCOFF means machine and header inference rejected the buffer.
	// COFF has no magic number, so this is a judgement, not a comparison.
	ErrNotCOFF = errors.New("pe: not a COFF object")

	// ErrShortHeader means the buffer was too short for the detection
	// function called. See MagicSize and KindPrefix for the requirements.
	ErrShortHeader = errors.New("pe: buffer shorter than the header it must hold")

	// ErrImageFile means a linked image reached a reader that wants an
	// object.
	ErrImageFile = errors.New("pe: linked image passed to an object reader")

	// ErrObjectFile means a relocatable object reached a reader that wants
	// an image.
	ErrObjectFile = errors.New("pe: object file passed to an image reader")

	// ErrUnsupportedMachine means the Machine value is not in this tree's
	// seeded table. The constant may still be defined; being named is not
	// the same as being supported.
	ErrUnsupportedMachine = errors.New("pe: unsupported machine type")

	// ErrInvalidTarget means a triple did not parse, or a Target failed
	// Validate.
	ErrInvalidTarget = errors.New("pe: invalid target")

	// ErrBaseRelocKind means a base relocation type did not fit the four
	// bits an entry gives it.
	ErrBaseRelocKind = errors.New("pe: base relocation type does not fit four bits")

	// ErrBaseRelocOffset means a base relocation offset was not within the
	// 4K page its block covers. The offset field is twelve bits, so a
	// larger value would silently alias a different address in the same
	// block rather than fail.
	ErrBaseRelocOffset = errors.New("pe: base relocation offset outside its page")
)

// errBaseRelocKind wraps ErrBaseRelocKind with the offending type.
func errBaseRelocKind(k BaseRelocKind) error {
	return fmt.Errorf("%w: %d", ErrBaseRelocKind, uint8(k))
}

// errBaseRelocOffset wraps ErrBaseRelocOffset with the offending offset and
// the page size it exceeded.
func errBaseRelocOffset(off uint16) error {
	return fmt.Errorf("%w: %#x is not below %#x", ErrBaseRelocOffset, off, BaseRelocPageSize)
}