package pe

// The COFF symbol table is an array of fixed-size records, most of which
// describe a symbol and some of which are auxiliary data belonging to the
// record before them. An index into it is a physical slot, not an ordinal
// into "the symbols", which is why nothing in this module hands out integer
// symbol indices.

const (
	// SymbolSize is one record in a standard object.
	SymbolSize = 18
	// BigObjSymbolSize is one record in a bigobj. The extra two bytes widen
	// SectionNumber from 16 to 32 bits; every other field keeps its size
	// and its meaning.
	BigObjSymbolSize = 20
	// NameSize is the inline name field. A name of exactly eight bytes has
	// no terminator, so it must be read as a fixed slice and trimmed, never
	// as a C string.
	NameSize = 8
)

// StorageClass says what kind of thing a symbol is and how to read its Value.
//
// The wire field is one unsigned byte. The specification lists
// IMAGE_SYM_CLASS_END_OF_FUNCTION as -1, which is 0xff here; treating the
// field as signed would be the other reasonable choice, but then every other
// class would need a cast.
type StorageClass uint8

const (
	ClassEndOfFunction  StorageClass = 0xff // spelled -1 in the specification
	ClassNull           StorageClass = 0
	ClassAutomatic      StorageClass = 1
	ClassExternal       StorageClass = 2
	ClassStatic         StorageClass = 3
	ClassRegister       StorageClass = 4
	ClassExternalDef    StorageClass = 5
	ClassLabel          StorageClass = 6
	ClassUndefinedLabel StorageClass = 7
	ClassMemberOfStruct StorageClass = 8
	ClassArgument       StorageClass = 9
	ClassStructTag      StorageClass = 10
	ClassMemberOfUnion  StorageClass = 11
	ClassUnionTag       StorageClass = 12
	ClassTypeDefinition StorageClass = 13
	ClassUndefinedStatic StorageClass = 14
	ClassEnumTag        StorageClass = 15
	ClassMemberOfEnum   StorageClass = 16
	ClassRegisterParam  StorageClass = 17
	ClassBitField       StorageClass = 18

	ClassBlock        StorageClass = 100 // .bb or .eb
	ClassFunction     StorageClass = 101 // .bf or .ef
	ClassEndOfStruct  StorageClass = 102
	ClassFile         StorageClass = 103 // .file
	ClassSection      StorageClass = 104
	ClassWeakExternal StorageClass = 105
	ClassCLRToken     StorageClass = 107 // 106 is unassigned
)

func (c StorageClass) String() string {
	switch c {
	case ClassEndOfFunction:
		return "END_OF_FUNCTION"
	case ClassNull:
		return "NULL"
	case ClassAutomatic:
		return "AUTOMATIC"
	case ClassExternal:
		return "EXTERNAL"
	case ClassStatic:
		return "STATIC"
	case ClassRegister:
		return "REGISTER"
	case ClassExternalDef:
		return "EXTERNAL_DEF"
	case ClassLabel:
		return "LABEL"
	case ClassUndefinedLabel:
		return "UNDEFINED_LABEL"
	case ClassMemberOfStruct:
		return "MEMBER_OF_STRUCT"
	case ClassArgument:
		return "ARGUMENT"
	case ClassStructTag:
		return "STRUCT_TAG"
	case ClassMemberOfUnion:
		return "MEMBER_OF_UNION"
	case ClassUnionTag:
		return "UNION_TAG"
	case ClassTypeDefinition:
		return "TYPE_DEFINITION"
	case ClassUndefinedStatic:
		return "UNDEFINED_STATIC"
	case ClassEnumTag:
		return "ENUM_TAG"
	case ClassMemberOfEnum:
		return "MEMBER_OF_ENUM"
	case ClassRegisterParam:
		return "REGISTER_PARAM"
	case ClassBitField:
		return "BIT_FIELD"
	case ClassBlock:
		return "BLOCK"
	case ClassFunction:
		return "FUNCTION"
	case ClassEndOfStruct:
		return "END_OF_STRUCT"
	case ClassFile:
		return "FILE"
	case ClassSection:
		return "SECTION"
	case ClassWeakExternal:
		return "WEAK_EXTERNAL"
	case ClassCLRToken:
		return "CLR_TOKEN"
	}
	return "class(" + itoa(int(c)) + ")"
}

// SymType is the packed Type field.
//
// The specification describes it as two bytes, the low one a base type and the
// high one a complex type. That description does not survive contact with the
// only value anyone emits: a function is 0x20, which is the derived type
// FUNCTION (2) shifted left by four, and so sits in the *low* byte. The shift
// is four, not eight — traditional COFF stacked derived types a nibble at a
// time so that "pointer to array of" could be expressed — and this package
// follows the arithmetic rather than the prose.
//
// In practice Microsoft tools set only SymNull and SymFunc, and put real type
// information in the debug sections instead.
type SymType uint16

const (
	// SymNull means no type information. Nearly every symbol has this.
	SymNull SymType = 0x0000
	// SymFunc marks a function. It is DerivedFunction packed at shift four.
	SymFunc SymType = 0x0020
)

// SymBaseType is the low nibble-pair: what the thing ultimately is.
type SymBaseType uint8

const (
	BaseNull   SymBaseType = 0
	BaseVoid   SymBaseType = 1
	BaseChar   SymBaseType = 2
	BaseShort  SymBaseType = 3
	BaseInt    SymBaseType = 4
	BaseLong   SymBaseType = 5
	BaseFloat  SymBaseType = 6
	BaseDouble SymBaseType = 7
	BaseStruct SymBaseType = 8
	BaseUnion  SymBaseType = 9
	BaseEnum   SymBaseType = 10
	BaseMOE    SymBaseType = 11 // member of enumeration
	BaseByte   SymBaseType = 12
	BaseWord   SymBaseType = 13
	BaseUInt   SymBaseType = 14
	BaseDWord  SymBaseType = 15
)

// SymDerivedType is how the base type is wrapped.
type SymDerivedType uint8

const (
	DerivedNull     SymDerivedType = 0 // a plain scalar
	DerivedPointer  SymDerivedType = 1
	DerivedFunction SymDerivedType = 2
	DerivedArray    SymDerivedType = 3
)

const symDerivedShift = 4

// PackSymType composes a Type field from a base and a derived type.
func PackSymType(base SymBaseType, derived SymDerivedType) SymType {
	return SymType(base) | SymType(derived)<<symDerivedShift
}

// SplitSymType decomposes a Type field. Only the first level of derivation is
// reported; deeper nibbles are historical and no Microsoft tool emits them.
func SplitSymType(t SymType) (SymBaseType, SymDerivedType) {
	return SymBaseType(t & 0x0f), SymDerivedType((t >> symDerivedShift) & 0x0f)
}

// IsFunction reports whether t marks a function.
func (t SymType) IsFunction() bool {
	_, d := SplitSymType(t)
	return d == DerivedFunction
}

// SectionNumber is a symbol's section, one-based, with three sentinel values
// below one.
//
// The wire width differs between object kinds — signed 16-bit in a standard
// object, signed 32-bit in a bigobj — so 0xffff is ABSOLUTE in one and an
// ordinary section number in the other. DecodeSectionNumber exists so that
// difference is applied once rather than at every read.
type SectionNumber int32

const (
	// SectionUndefined means the symbol is not defined here. For an
	// external symbol with a non-zero Value, that Value is a common-block
	// size request rather than an address.
	SectionUndefined SectionNumber = 0
	// SectionAbsolute means Value is a constant, not an address.
	SectionAbsolute SectionNumber = -1
	// SectionDebug means the symbol carries type or debug information and
	// corresponds to no section. .file records use it.
	SectionDebug SectionNumber = -2
)

// DecodeSectionNumber sign-extends a raw section number according to the
// record width it came from.
func DecodeSectionNumber(raw uint32, bigObj bool) SectionNumber {
	if bigObj {
		return SectionNumber(int32(raw))
	}
	return SectionNumber(int16(uint16(raw)))
}

// Defined reports whether n names an actual section, which is the only case in
// which Value is an offset into one.
func (n SectionNumber) Defined() bool { return n > 0 }

func (n SectionNumber) String() string {
	switch n {
	case SectionUndefined:
		return "UNDEF"
	case SectionAbsolute:
		return "ABS"
	case SectionDebug:
		return "DEBUG"
	}
	return "SECT" + itoa(int(n))
}

// AuxKind says how to interpret the auxiliary records that follow a symbol.
// The kind is not stored anywhere; it is inferred from the symbol's storage
// class, type, and section number, which is why AuxKindOf takes all three.
type AuxKind uint8

const (
	// AuxOpaque means this tree does not recognize the combination. The
	// bytes round-trip unchanged rather than being dropped or guessed at.
	AuxOpaque AuxKind = iota
	AuxFunctionDef            // format 1
	AuxBfEf                   // format 2: .bf and .ef records
	AuxWeakExternal           // format 3
	AuxFile                   // format 4
	AuxSectionDef             // format 5
	AuxCLRToken               // format 6
)

// AuxTypeCLRToken is the AuxType byte that identifies a CLR token definition
// record. It is the only aux format that self-identifies.
const AuxTypeCLRToken = 1

// AuxKindOf infers the format of the auxiliary records following a symbol.
//
// The function-definition case is the one that bites. A definition requires
// all three of: storage class EXTERNAL, a function type, and a section number
// greater than zero. An *undefined* external function symbol matches the first
// two and has no auxiliary record at all — so a reader that dispatches on
// class and type alone will consume the following symbol as aux data and
// desynchronise every record after it.
//
// name is the symbol's name, needed only to tell .bf and .ef records from
// other symbols of storage class FUNCTION.
func AuxKindOf(class StorageClass, typ SymType, sect SectionNumber, name string) AuxKind {
	switch class {
	case ClassExternal:
		if typ.IsFunction() && sect.Defined() {
			return AuxFunctionDef
		}
	case ClassFunction:
		if name == ".bf" || name == ".ef" {
			return AuxBfEf
		}
	case ClassWeakExternal:
		return AuxWeakExternal
	case ClassFile:
		return AuxFile
	case ClassStatic:
		// A static symbol whose name matches a section is that section's
		// definition record. The caller confirms the name match; this
		// answers for the common case where it does.
		return AuxSectionDef
	case ClassCLRToken:
		return AuxCLRToken
	}
	return AuxOpaque
}

// WeakKind is the Characteristics field of a weak-external auxiliary record:
// what the linker should do before falling back to the alternate symbol.
type WeakKind uint32

const (
	// WeakNoLibrary means do not search libraries for the name.
	WeakNoLibrary WeakKind = 1
	// WeakLibrary means search libraries for the name.
	WeakLibrary WeakKind = 2
	// WeakAlias means use the alternate unconditionally if nothing else
	// defines the name. This is the ELF-weak-definition analogue.
	WeakAlias WeakKind = 3
	// WeakAntiDependency is the ARM64EC anti-dependency alias. It shares
	// the WEAK_EXTERNAL storage class with the three above and means
	// something different in kind, not in degree, which is why WeakKind is
	// an enumeration and not a bool.
	//
	// The specification spells this IMAGE_WEAK_EXTERN_ANTI_DEPENDENCY;
	// note the absent SEARCH_, which several transcriptions add.
	WeakAntiDependency WeakKind = 4
)

func (w WeakKind) String() string {
	switch w {
	case WeakNoLibrary:
		return "NOLIBRARY"
	case WeakLibrary:
		return "LIBRARY"
	case WeakAlias:
		return "ALIAS"
	case WeakAntiDependency:
		return "ANTI_DEPENDENCY"
	}
	return "weak(" + itoa(int(w)) + ")"
}

// Compiler-generated absolute symbols that carry flags rather than addresses.
const (
	// FeatSymbol is emitted as an absolute symbol whose Value is a bitfield
	// of compiler features.
	FeatSymbol = "@feat.00"
	// CompIDSymbol identifies the compiler build that produced the object.
	// Its Value is opaque to this tree.
	CompIDSymbol = "@comp.id"

	// FeatSafeSEH is the only @feat.00 bit the specification documents: set
	// when the object has registered SEH. An object with @feat.00 and this
	// bit but no .sxdata section has registered *zero* handlers, which is
	// meaningfully different from having never opted in.
	//
	// Other bits exist and are used by /GUARD:CF and friends; they are not
	// documented and are not named here rather than named wrongly.
	FeatSafeSEH uint32 = 0x1
)