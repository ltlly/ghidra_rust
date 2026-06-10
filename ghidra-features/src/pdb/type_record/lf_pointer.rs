//! LF_POINTER -- concrete Pointer type record.
//!
//! Ports Ghidra's `PointerMsType` (PDB_ID = 0x1002) and
//! `AbstractPointerMsType` Java classes.
//!
//! Represents a C/C++ pointer type in the PDB type stream.
//!
//! # Binary Layout (LF_POINTER / 0x1002)
//!
//! ```text
//! +0  u32   underlyingType   Type index of the pointed-to type
//! +4  u32   attributes       Bitfield encoding pointer properties
//!     ...                    Optional extended pointer info
//! ```
//!
//! The `attributes` bitfield layout:
//!
//! ```text
//! bits  0..4   PointerType    (near, far, ptr64, etc.)
//! bits  5..7   PointerMode    (*, &, &&, ::*, etc.)
//! bit   8      isFlat         0:32 flat address model
//! bit   9      isVolatile
//! bit  10     isConst
//! bit  11     isUnaligned
//! bit  12     isRestrict
//! bits 13..18  pointerSize    Size in bits (6-bit field)
//! bit  19     isMocom
//! bit  20     isLRef          left reference
//! bit  21     isRRef          right reference
//! bit  22     unk             unknown bit
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

// =============================================================================
// PointerType -- the kind of pointer address model
// =============================================================================

/// The address model / kind of a pointer.
///
/// Corresponds to the Java `AbstractPointerMsType.PointerType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PointerType {
    /// Invalid/unrecognized pointer type (default fallback).
    Invalid = 0xFF,
    /// 16-bit pointer (near).
    Near = 0,
    /// 16:16 far pointer.
    Far = 1,
    /// 16:16 huge pointer.
    Huge = 2,
    /// Segment-relative pointer.
    SegmentBased = 3,
    /// Value-based pointer.
    ValueBased = 4,
    /// Segment-value-based pointer.
    SegmentValueBased = 5,
    /// Address-based pointer.
    AddressBased = 6,
    /// Segment-address-based pointer.
    SegmentAddressBased = 7,
    /// Type-based pointer.
    TypeBased = 8,
    /// Self-based pointer.
    SelfBased = 9,
    /// 32-bit pointer (near32).
    Near32 = 10,
    /// 16:32 far pointer.
    Far32 = 11,
    /// 64-bit pointer.
    Ptr64 = 12,
    /// Unspecified pointer kind.
    Unspecified = 13,
}

impl PointerType {
    /// Label string used in emit output.
    pub fn label(&self) -> &'static str {
        match self {
            PointerType::Invalid => "invalid",
            PointerType::Near => "",
            PointerType::Far => "far ",
            PointerType::Huge => "huge ",
            PointerType::SegmentBased => "base(seg) ",
            PointerType::ValueBased => "base(val) ",
            PointerType::SegmentValueBased => "base(segval) ",
            PointerType::AddressBased => "base(addr) ",
            PointerType::SegmentAddressBased => "base(segaddr) ",
            PointerType::TypeBased => "base(type) ",
            PointerType::SelfBased => "base(addr) ",
            PointerType::Near32 => "",
            PointerType::Far32 => "far32 ",
            PointerType::Ptr64 => "far64 ",
            PointerType::Unspecified => "unspecified ",
        }
    }

    /// Parse from a 5-bit integer value.
    ///
    /// Returns `Invalid` for unknown values (matching Java's default mapping).
    pub fn from_value(val: u8) -> Self {
        match val {
            0 => Self::Near,
            1 => Self::Far,
            2 => Self::Huge,
            3 => Self::SegmentBased,
            4 => Self::ValueBased,
            5 => Self::SegmentValueBased,
            6 => Self::AddressBased,
            7 => Self::SegmentAddressBased,
            8 => Self::TypeBased,
            9 => Self::SelfBased,
            10 => Self::Near32,
            11 => Self::Far32,
            12 => Self::Ptr64,
            13 => Self::Unspecified,
            _ => Self::Invalid,
        }
    }

    /// Whether this is an invalid/unrecognized pointer type.
    pub fn is_invalid(&self) -> bool {
        *self == Self::Invalid
    }
}

impl fmt::Display for PointerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// =============================================================================
// PointerMode -- syntactic pointer mode (*, &, &&, ::*)
// =============================================================================

/// The syntactic mode of a pointer (dereference, reference, member pointer, etc.).
///
/// Corresponds to the Java `AbstractPointerMsType.MsPointerMode` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PointerMode {
    /// Invalid/unrecognized pointer mode (default fallback).
    Invalid = 0xFF,
    /// Normal pointer (`*`).
    Pointer = 0,
    /// Lvalue reference (`&`).
    LValueReference = 1,
    /// Member data pointer (`::*`).
    MemberDataPointer = 2,
    /// Member function pointer (`::*`).
    MemberFunctionPointer = 3,
    /// Rvalue reference (`&&`).
    RValueReference = 4,
    /// Reserved (unused).
    Reserved = 5,
}

impl PointerMode {
    /// Label string used in emit output.
    pub fn label(&self) -> &'static str {
        match self {
            PointerMode::Invalid => "",
            PointerMode::Pointer => "*",
            PointerMode::LValueReference => "&",
            PointerMode::MemberDataPointer => "::*",
            PointerMode::MemberFunctionPointer => "::*",
            PointerMode::RValueReference => "&&",
            PointerMode::Reserved => "",
        }
    }

    /// Parse from a 3-bit integer value.
    ///
    /// Returns `Invalid` for unknown values (matching Java's default mapping).
    pub fn from_value(val: u8) -> Self {
        match val {
            0 => Self::Pointer,
            1 => Self::LValueReference,
            2 => Self::MemberDataPointer,
            3 => Self::MemberFunctionPointer,
            4 => Self::RValueReference,
            5 => Self::Reserved,
            _ => Self::Invalid,
        }
    }

    /// Whether this is an invalid/unrecognized pointer mode.
    pub fn is_invalid(&self) -> bool {
        *self == Self::Invalid
    }

    /// Whether this is a member pointer (data or function).
    pub fn is_member_pointer(&self) -> bool {
        matches!(self, Self::MemberDataPointer | Self::MemberFunctionPointer)
    }
}

impl fmt::Display for PointerMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// =============================================================================
// MemberPointerType -- member pointer classification
// =============================================================================

/// Classification of a member pointer (data/function, single/multiple/virtual
/// inheritance).
///
/// Corresponds to the Java `AbstractPointerMsType.MemberPointerType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MemberPointerType {
    /// Invalid/unrecognized member pointer type (default fallback).
    Invalid = 0xFF,
    /// Unspecified / 16-bit non-virtual.
    Unspecified = 0,
    /// Data, single inheritance.
    DataSingleInheritance = 1,
    /// Data, multiple inheritance.
    DataMultipleInheritance = 2,
    /// Data, virtual inheritance (no vbase).
    DataVirtualInheritance = 3,
    /// Data, general (vbase).
    DataGeneral = 4,
    /// Function, single inheritance, 16-bit near.
    FunctionSingleInheritance = 5,
    /// Function, multiple inheritance, 16-bit near.
    FunctionMultipleInheritance = 6,
    /// Function, virtual inheritance, 16-bit near.
    FunctionVirtualInheritance = 7,
    /// Function, single inheritance, 16:32 far.
    FunctionSingleInheritance1632 = 8,
    /// Function, multiple inheritance, 16:32 far.
    FunctionMultipleInheritance1632 = 9,
    /// Function, virtual inheritance, 16:32 far.
    FunctionVirtualInheritance1632 = 10,
    /// Function, single inheritance, 32-bit.
    FunctionSingleInheritance32 = 11,
    /// Function, multiple inheritance, 32-bit.
    FunctionMultipleInheritance32 = 12,
    /// Function, virtual inheritance, 32-bit.
    FunctionVirtualInheritance32 = 13,
}

impl MemberPointerType {
    /// Label string used in emit output.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Unspecified => "pdm16_nonvirt",
            Self::DataSingleInheritance => "pdm16_vfcn",
            Self::DataMultipleInheritance => "pdm16_vbase",
            Self::DataVirtualInheritance => "pdm32_nvvfcn",
            Self::DataGeneral => "pdm32_vbase",
            Self::FunctionSingleInheritance => "pmf16_nearnvsa",
            Self::FunctionMultipleInheritance => "pmf16_nearnvma",
            Self::FunctionVirtualInheritance => "pmf16_nearvbase",
            Self::FunctionSingleInheritance1632 => "pmf16_farnvsa",
            Self::FunctionMultipleInheritance1632 => "pmf16_farnvma",
            Self::FunctionVirtualInheritance1632 => "pmf16_farvbase",
            Self::FunctionSingleInheritance32 => "pmf32_nvsa",
            Self::FunctionMultipleInheritance32 => "pmf32_nvma",
            Self::FunctionVirtualInheritance32 => "pmf32_vbase",
        }
    }

    /// Parse from a raw integer value.
    ///
    /// Returns `Invalid` for unknown values (matching Java's default mapping).
    pub fn from_value(val: u8) -> Self {
        match val {
            0 => Self::Unspecified,
            1 => Self::DataSingleInheritance,
            2 => Self::DataMultipleInheritance,
            3 => Self::DataVirtualInheritance,
            4 => Self::DataGeneral,
            5 => Self::FunctionSingleInheritance,
            6 => Self::FunctionMultipleInheritance,
            7 => Self::FunctionVirtualInheritance,
            8 => Self::FunctionSingleInheritance1632,
            9 => Self::FunctionMultipleInheritance1632,
            10 => Self::FunctionVirtualInheritance1632,
            11 => Self::FunctionSingleInheritance32,
            12 => Self::FunctionMultipleInheritance32,
            13 => Self::FunctionVirtualInheritance32,
            _ => Self::Invalid,
        }
    }

    /// Whether this is an invalid/unrecognized member pointer type.
    pub fn is_invalid(&self) -> bool {
        *self == Self::Invalid
    }
}

impl fmt::Display for MemberPointerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// =============================================================================
// LfPointer -- the concrete pointer type record
// =============================================================================

/// Concrete PDB pointer type record (`LF_POINTER`).
///
/// This is the Rust equivalent of Ghidra's `PointerMsType`.  It stores the
/// underlying (pointed-to) type record number along with all pointer
/// attributes parsed from the binary PDB stream.
#[derive(Debug, Clone)]
pub struct LfPointer {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the type that this pointer points to.
    pub underlying_record_number: RecordNumber,
    /// The kind of pointer (near, far, ptr64, etc.).
    pub pointer_type: PointerType,
    /// The syntactic mode (*, &, &&, ::*).
    pub pointer_mode: PointerMode,
    /// Whether this is a flat 0:32 pointer.
    pub is_flat: bool,
    /// Whether this is a volatile pointer.
    pub is_volatile: bool,
    /// Whether this is a const pointer.
    pub is_const: bool,
    /// Whether this pointer is unaligned.
    pub is_unaligned: bool,
    /// Whether this pointer has the restrict qualifier.
    pub is_restrict: bool,
    /// Size of the pointer in bytes.
    pub size: u8,
    /// Whether this is a MOCOM pointer.
    pub is_mocom: bool,
    /// Whether this is an lvalue reference.
    pub is_lref: bool,
    /// Whether this is an rvalue reference.
    pub is_rref: bool,
    /// Unknown attribute bit.
    pub is_unknown: bool,
    /// For member pointers: record number of the containing class.
    pub member_pointer_containing_class_record_number: RecordNumber,
    /// For member pointers: the member pointer classification.
    pub member_pointer_type: Option<MemberPointerType>,
    /// For segment-based pointers: the base segment.
    pub base_segment: u16,
    /// For type-based pointers: the pointer base type record number.
    pub pointer_base_type_record_number: RecordNumber,
    /// For invalid pointer types: the base symbol name.
    pub base_symbol: String,
    /// Optional name associated with this pointer (e.g., for type-based pointers).
    pub pointer_name: String,
}

impl LfPointer {
    /// PDB ID for the 16-bit pointer variant.
    pub const PDB_ID_16: u32 = 0x0200;
    /// PDB ID for the 32-bit (MsType) pointer variant.
    pub const PDB_ID_32: u32 = 0x1002;

    /// Create a new pointer type record with explicit fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        underlying_record_number: RecordNumber,
        pointer_type: PointerType,
        pointer_mode: PointerMode,
        is_flat: bool,
        is_volatile: bool,
        is_const: bool,
        is_unaligned: bool,
        is_restrict: bool,
        size: u8,
        is_mocom: bool,
        is_lref: bool,
        is_rref: bool,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            underlying_record_number,
            pointer_type,
            pointer_mode,
            is_flat,
            is_volatile,
            is_const,
            is_unaligned,
            is_restrict,
            size,
            is_mocom,
            is_lref,
            is_rref,
            is_unknown: false,
            member_pointer_containing_class_record_number: RecordNumber::NO_TYPE,
            member_pointer_type: None,
            base_segment: 0,
            pointer_base_type_record_number: RecordNumber::NO_TYPE,
            base_symbol: String::new(),
            pointer_name: String::new(),
        }
    }

    /// Create a simple pointer to the given type with default attributes.
    ///
    /// This creates a near32 normal pointer (`*`) of default size with no
    /// qualifiers -- the most common case.
    pub fn simple(underlying_type_index: u32, pointer_size: u8) -> Self {
        Self::new(
            RecordNumber::type_record(underlying_type_index),
            PointerType::Near32,
            PointerMode::Pointer,
            false,
            false,
            false,
            false,
            false,
            pointer_size,
            false,
            false,
            false,
        )
    }

    /// Create from raw parsed values, decoding the 32-bit attributes word.
    pub fn from_parsed(
        underlying_type_index: u32,
        attributes: u32,
    ) -> Self {
        let mut attrs = attributes;

        let pt_val = (attrs & 0x1F) as u8;
        attrs >>= 5;
        let pm_val = (attrs & 0x07) as u8;
        attrs >>= 3;

        let is_flat = (attrs & 0x01) != 0;
        attrs >>= 1;
        let is_volatile = (attrs & 0x01) != 0;
        attrs >>= 1;
        let is_const = (attrs & 0x01) != 0;
        attrs >>= 1;
        let is_unaligned = (attrs & 0x01) != 0;
        attrs >>= 1;
        let is_restrict = (attrs & 0x01) != 0;
        attrs >>= 1;

        let size = (attrs & 0x3F) as u8;
        attrs >>= 6;

        let is_mocom = (attrs & 0x01) != 0;
        attrs >>= 1;
        let is_lref = (attrs & 0x01) != 0;
        attrs >>= 1;
        let is_rref = (attrs & 0x01) != 0;
        attrs >>= 1;
        let is_unknown = (attrs & 0x01) != 0;

        let pointer_type = PointerType::from_value(pt_val);
        let pointer_mode = PointerMode::from_value(pm_val);

        Self {
            record_number: RecordNumber::NO_TYPE,
            underlying_record_number: RecordNumber::type_record(underlying_type_index),
            pointer_type,
            pointer_mode,
            is_flat,
            is_volatile,
            is_const,
            is_unaligned,
            is_restrict,
            size,
            is_mocom,
            is_lref,
            is_rref,
            is_unknown,
            member_pointer_containing_class_record_number: RecordNumber::NO_TYPE,
            member_pointer_type: None,
            base_segment: 0,
            pointer_base_type_record_number: RecordNumber::NO_TYPE,
            base_symbol: String::new(),
            pointer_name: String::new(),
        }
    }

    /// Whether this is a member pointer (data or function).
    pub fn is_member_pointer(&self) -> bool {
        self.pointer_mode.is_member_pointer()
    }

    /// Get the size of the pointer in bytes.
    ///
    /// Mirrors Java `AbstractPointerMsType.getSize()`.
    pub fn get_size(&self) -> u8 {
        self.size
    }

    /// Whether this pointer has the restrict qualifier.
    ///
    /// Mirrors Java `PointerMsType.isRestrict()`.
    pub fn is_restrict(&self) -> bool {
        self.is_restrict
    }

    /// Whether this is a MOCOM pointer.
    ///
    /// Mirrors Java `PointerMsType.isMocom()`.
    pub fn is_mocom(&self) -> bool {
        self.is_mocom
    }

    /// Whether this is a left (lvalue) reference.
    ///
    /// Mirrors Java `PointerMsType.isLeftReference()`.
    pub fn is_left_reference(&self) -> bool {
        self.is_lref
    }

    /// Whether this is a right (rvalue) reference.
    ///
    /// Mirrors Java `PointerMsType.isRightReference()`.
    pub fn is_right_reference(&self) -> bool {
        self.is_rref
    }

    /// Whether the pointer type attribute is unknown/unrecognized.
    ///
    /// Mirrors Java `PointerMsType.isUnknownAttributes()`.
    pub fn is_unknown_attributes(&self) -> bool {
        self.is_unknown
    }

    /// Get the pointer size in bytes.
    ///
    /// This is a convenience alias for [`get_size`] that returns `usize`.
    pub fn pointer_size_bytes(&self) -> usize {
        self.size as usize
    }

    /// Whether this pointer type is valid (recognized).
    ///
    /// Returns `false` if either the pointer type or pointer mode is invalid.
    pub fn is_valid(&self) -> bool {
        !self.pointer_type.is_invalid() && !self.pointer_mode.is_invalid()
    }

    /// Whether this pointer has any qualifiers (const, volatile, unaligned, restrict).
    pub fn has_qualifiers(&self) -> bool {
        self.is_const || self.is_volatile || self.is_unaligned || self.is_restrict
    }

    /// Build a qualifier string for this pointer.
    ///
    /// Returns a space-separated string of active qualifiers (e.g.,
    /// `"const volatile "`). Returns an empty string if no qualifiers
    /// are set.
    pub fn qualifier_string(&self) -> String {
        let mut result = String::new();
        if self.is_const {
            result.push_str("const ");
        }
        if self.is_volatile {
            result.push_str("volatile ");
        }
        if self.is_unaligned {
            result.push_str("__unaligned ");
        }
        if self.is_restrict {
            result.push_str("restrict ");
        }
        result
    }

    /// Set the member pointer extended info.
    ///
    /// This corresponds to the Java `parseExtendedPointerInfo` method for
    /// `MEMBER_DATA_POINTER` and `MEMBER_FUNCTION_POINTER` modes.
    pub fn set_member_pointer_info(
        &mut self,
        containing_class_record_number: RecordNumber,
        member_pointer_type: MemberPointerType,
    ) {
        self.member_pointer_containing_class_record_number = containing_class_record_number;
        self.member_pointer_type = Some(member_pointer_type);
    }

    /// Set the segment-based pointer extended info.
    ///
    /// This corresponds to the Java `parseExtendedPointerInfo` method for
    /// `SEGMENT_BASED` pointer type.
    pub fn set_segment_info(&mut self, base_segment: u16) {
        self.base_segment = base_segment;
    }

    /// Set the type-based pointer extended info.
    ///
    /// This corresponds to the Java `parseExtendedPointerInfo` method for
    /// `TYPE_BASED` pointer type.
    pub fn set_type_based_info(
        &mut self,
        pointer_base_type_record_number: RecordNumber,
        name: String,
    ) {
        self.pointer_base_type_record_number = pointer_base_type_record_number;
        self.pointer_name = name;
    }

    /// Set the base symbol for invalid pointer types.
    ///
    /// This corresponds to the Java `parseExtendedPointerInfo` method for
    /// `INVALID` pointer type.
    pub fn set_base_symbol(&mut self, base_symbol: String) {
        self.base_symbol = base_symbol;
    }

    /// Whether this pointer is a reference (lvalue or rvalue).
    pub fn is_reference(&self) -> bool {
        self.pointer_mode == PointerMode::LValueReference
            || self.pointer_mode == PointerMode::RValueReference
    }

    /// Whether this is a pointer to a function.
    ///
    /// Note: This is a syntactic check based on the pointer mode.
    /// For a definitive check, the underlying type should be resolved.
    pub fn is_function_pointer_mode(&self) -> bool {
        self.pointer_mode == PointerMode::MemberFunctionPointer
    }
}

impl AbstractMsType for LfPointer {
    fn pdb_id(&self) -> u32 {
        Self::PDB_ID_32 // LF_POINTER = 0x1002
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, bind: Bind) -> String {
        let mut result = String::new();

        if bind < Bind::PTR {
            result.push('(');
        }

        if self.is_flat {
            result.push_str("flat ");
        }

        if self.is_member_pointer() {
            // Member pointer: emit containing class, then the mode and member pointer type.
            result.push_str(&self.member_pointer_containing_class_record_number.to_string());
            result.push_str(self.pointer_mode.label());
            if let Some(mpt) = self.member_pointer_type {
                result.push_str(" <");
                result.push_str(mpt.label());
                result.push('>');
            }
        } else {
            result.push_str(self.pointer_type.label());
            result.push_str(self.pointer_mode.label());
        }

        if self.is_const {
            result.push_str("const ");
        }
        if self.is_volatile {
            result.push_str("volatile ");
        }

        result.push(' ');

        // Underlying type reference (in full implementation this would recursively emit).
        result.push_str(&self.underlying_record_number.to_string());

        if bind < Bind::PTR {
            result.push(')');
        }

        result
    }
}

impl fmt::Display for LfPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pointer_type_from_value() {
        assert_eq!(PointerType::from_value(0), PointerType::Near);
        assert_eq!(PointerType::from_value(12), PointerType::Ptr64);
        assert_eq!(PointerType::from_value(13), PointerType::Unspecified);
        assert_eq!(PointerType::from_value(14), PointerType::Invalid);
    }

    #[test]
    fn test_pointer_type_label() {
        assert_eq!(PointerType::Near.label(), "");
        assert_eq!(PointerType::Ptr64.label(), "far64 ");
        assert_eq!(PointerType::Far.label(), "far ");
        assert_eq!(PointerType::Invalid.label(), "invalid");
    }

    #[test]
    fn test_pointer_type_is_invalid() {
        assert!(!PointerType::Near.is_invalid());
        assert!(PointerType::Invalid.is_invalid());
    }

    #[test]
    fn test_pointer_mode_from_value() {
        assert_eq!(PointerMode::from_value(0), PointerMode::Pointer);
        assert_eq!(PointerMode::from_value(1), PointerMode::LValueReference);
        assert_eq!(PointerMode::from_value(4), PointerMode::RValueReference);
        assert_eq!(PointerMode::from_value(5), PointerMode::Reserved);
        assert_eq!(PointerMode::from_value(6), PointerMode::Invalid);
    }

    #[test]
    fn test_pointer_mode_label() {
        assert_eq!(PointerMode::Pointer.label(), "*");
        assert_eq!(PointerMode::LValueReference.label(), "&");
        assert_eq!(PointerMode::RValueReference.label(), "&&");
    }

    #[test]
    fn test_pointer_mode_is_member_pointer() {
        assert!(!PointerMode::Pointer.is_member_pointer());
        assert!(PointerMode::MemberDataPointer.is_member_pointer());
        assert!(PointerMode::MemberFunctionPointer.is_member_pointer());
    }

    #[test]
    fn test_member_pointer_type_from_value() {
        assert_eq!(
            MemberPointerType::from_value(0),
            MemberPointerType::Unspecified
        );
        assert_eq!(
            MemberPointerType::from_value(13),
            MemberPointerType::FunctionVirtualInheritance32
        );
        assert_eq!(MemberPointerType::from_value(14), MemberPointerType::Invalid);
    }

    #[test]
    fn test_simple_pointer() {
        let p = LfPointer::simple(0x0074, 4);
        assert_eq!(p.pdb_id(), 0x1002);
        assert_eq!(p.underlying_record_number, RecordNumber::type_record(0x0074));
        assert_eq!(p.pointer_type, PointerType::Near32);
        assert_eq!(p.pointer_mode, PointerMode::Pointer);
        assert_eq!(p.size, 4);
        assert!(!p.is_const);
        assert!(!p.is_volatile);
    }

    #[test]
    fn test_pointer_from_parsed() {
        // Construct attributes: ptrType=10(near32), mode=0(*), flat=0, vol=0, const=0,
        // unaligned=0, restrict=0, size=8, mocom=0, lref=0, rref=0, unk=0
        // bits: [0..4]=10, [5..7]=0, [8]=0, [9]=0, [10]=0, [11]=0, [12]=0,
        //       [13..18]=8, [19]=0, [20]=0, [21]=0, [22]=0
        let attrs: u32 = 10 | (0 << 5) | (0 << 8) | (0 << 9) | (0 << 10) | (0 << 11)
            | (0 << 12) | (8u32 << 13);
        let p = LfPointer::from_parsed(0x0074, attrs);
        assert_eq!(p.pointer_type, PointerType::Near32);
        assert_eq!(p.pointer_mode, PointerMode::Pointer);
        assert_eq!(p.size, 8);
        assert!(!p.is_const);
        assert!(!p.is_volatile);
    }

    #[test]
    fn test_pointer_from_parsed_with_const() {
        // const=1 at bit 10
        let attrs: u32 = 10 | (0 << 5) | (1 << 10) | (8u32 << 13);
        let p = LfPointer::from_parsed(0x0074, attrs);
        assert!(p.is_const);
        assert!(!p.is_volatile);
    }

    #[test]
    fn test_pointer_from_parsed_with_volatile() {
        // volatile=1 at bit 9
        let attrs: u32 = 10 | (0 << 5) | (1 << 9) | (8u32 << 13);
        let p = LfPointer::from_parsed(0x0074, attrs);
        assert!(p.is_volatile);
        assert!(!p.is_const);
    }

    #[test]
    fn test_pointer_is_member_pointer() {
        let mut p = LfPointer::simple(0x0074, 4);
        assert!(!p.is_member_pointer());
        p.pointer_mode = PointerMode::MemberDataPointer;
        assert!(p.is_member_pointer());
        p.pointer_mode = PointerMode::MemberFunctionPointer;
        assert!(p.is_member_pointer());
    }

    #[test]
    fn test_pointer_emit() {
        let p = LfPointer::simple(0x0074, 4);
        let emitted = p.emit(Bind::NONE);
        assert!(emitted.contains('*'));
        assert!(emitted.contains("0x0074"));
    }

    #[test]
    fn test_pointer_emit_in_ptr_context() {
        let p = LfPointer::simple(0x0074, 4);
        let emitted = p.emit(Bind::PTR);
        // At PTR level, no extra parentheses needed.
        assert!(!emitted.starts_with('('));
    }

    #[test]
    fn test_pointer_emit_below_ptr() {
        let p = LfPointer::simple(0x0074, 4);
        // PTR is the loosest binding (ordinal 0), so nothing is "below" it.
        // ARRAY (ordinal 1) does NOT trigger parentheses -- only if there
        // were a binding looser than PTR would they appear.
        let emitted = p.emit(Bind::ARRAY);
        assert!(!emitted.starts_with('('));
        assert!(emitted.contains('*'));
    }

    #[test]
    fn test_pointer_record_number() {
        let mut p = LfPointer::simple(0x0074, 4);
        assert!(p.record_number().is_no_type());
        p.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(p.record_number().index(), 0x2000);
    }

    #[test]
    fn test_pointer_display() {
        let p = LfPointer::simple(0x0074, 4);
        let display = format!("{}", p);
        assert!(!display.is_empty());
    }

    #[test]
    fn test_pointer_ref() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.pointer_mode = PointerMode::LValueReference;
        let emitted = p.emit(Bind::NONE);
        assert!(emitted.contains('&'));
    }

    #[test]
    fn test_pointer_rvalue_ref() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.pointer_mode = PointerMode::RValueReference;
        let emitted = p.emit(Bind::NONE);
        assert!(emitted.contains("&&"));
    }

    #[test]
    fn test_display_enum_variants() {
        assert_eq!(format!("{}", PointerType::Far), "far ");
        assert_eq!(format!("{}", PointerMode::Pointer), "*");
        assert_eq!(
            format!("{}", MemberPointerType::DataGeneral),
            "pdm32_vbase"
        );
    }

    #[test]
    fn test_pointer_get_size() {
        let p = LfPointer::simple(0x0074, 8);
        assert_eq!(p.get_size(), 8);

        let p = LfPointer::simple(0x0074, 4);
        assert_eq!(p.get_size(), 4);
    }

    #[test]
    fn test_pointer_is_restrict() {
        let mut p = LfPointer::simple(0x0074, 4);
        assert!(!p.is_restrict());
        p.is_restrict = true;
        assert!(p.is_restrict());
    }

    #[test]
    fn test_pointer_is_mocom() {
        let mut p = LfPointer::simple(0x0074, 4);
        assert!(!p.is_mocom());
        p.is_mocom = true;
        assert!(p.is_mocom());
    }

    #[test]
    fn test_pointer_is_left_reference() {
        let mut p = LfPointer::simple(0x0074, 4);
        assert!(!p.is_left_reference());
        p.is_lref = true;
        assert!(p.is_left_reference());
    }

    #[test]
    fn test_pointer_is_right_reference() {
        let mut p = LfPointer::simple(0x0074, 4);
        assert!(!p.is_right_reference());
        p.is_rref = true;
        assert!(p.is_right_reference());
    }

    #[test]
    fn test_pointer_is_unknown_attributes() {
        let mut p = LfPointer::simple(0x0074, 4);
        assert!(!p.is_unknown_attributes());
        p.is_unknown = true;
        assert!(p.is_unknown_attributes());
    }

    #[test]
    fn test_pointer_pdb_id_constants() {
        assert_eq!(LfPointer::PDB_ID_16, 0x0200);
        assert_eq!(LfPointer::PDB_ID_32, 0x1002);
    }

    #[test]
    fn test_pointer_base_symbol_default() {
        let p = LfPointer::simple(0x0074, 4);
        assert!(p.base_symbol.is_empty());
    }

    #[test]
    fn test_pointer_with_base_symbol() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.pointer_type = PointerType::Invalid;
        p.base_symbol = "_some_symbol".to_string();
        assert!(p.pointer_type.is_invalid());
        assert_eq!(p.base_symbol, "_some_symbol");
    }

    #[test]
    fn test_pointer_size_bytes() {
        let p = LfPointer::simple(0x0074, 4);
        assert_eq!(p.pointer_size_bytes(), 4);

        let p = LfPointer::simple(0x0074, 8);
        assert_eq!(p.pointer_size_bytes(), 8);
    }

    #[test]
    fn test_pointer_is_valid() {
        let p = LfPointer::simple(0x0074, 4);
        assert!(p.is_valid());
    }

    #[test]
    fn test_pointer_is_valid_invalid_type() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.pointer_type = PointerType::Invalid;
        assert!(!p.is_valid());
    }

    #[test]
    fn test_pointer_is_valid_invalid_mode() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.pointer_mode = PointerMode::Invalid;
        assert!(!p.is_valid());
    }

    #[test]
    fn test_pointer_has_qualifiers_false() {
        let p = LfPointer::simple(0x0074, 4);
        assert!(!p.has_qualifiers());
    }

    #[test]
    fn test_pointer_has_qualifiers_true_const() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.is_const = true;
        assert!(p.has_qualifiers());
    }

    #[test]
    fn test_pointer_has_qualifiers_true_restrict() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.is_restrict = true;
        assert!(p.has_qualifiers());
    }

    #[test]
    fn test_pointer_qualifier_string_empty() {
        let p = LfPointer::simple(0x0074, 4);
        assert_eq!(p.qualifier_string(), "");
    }

    #[test]
    fn test_pointer_qualifier_string_const() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.is_const = true;
        assert_eq!(p.qualifier_string(), "const ");
    }

    #[test]
    fn test_pointer_qualifier_string_volatile() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.is_volatile = true;
        assert_eq!(p.qualifier_string(), "volatile ");
    }

    #[test]
    fn test_pointer_qualifier_string_const_volatile() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.is_const = true;
        p.is_volatile = true;
        assert_eq!(p.qualifier_string(), "const volatile ");
    }

    #[test]
    fn test_pointer_qualifier_string_all() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.is_const = true;
        p.is_volatile = true;
        p.is_unaligned = true;
        p.is_restrict = true;
        assert_eq!(p.qualifier_string(), "const volatile __unaligned restrict ");
    }

    #[test]
    fn test_pointer_set_member_pointer_info() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.pointer_mode = PointerMode::MemberDataPointer;
        p.set_member_pointer_info(
            RecordNumber::type_record(0x2000),
            MemberPointerType::DataSingleInheritance,
        );
        assert_eq!(
            p.member_pointer_containing_class_record_number,
            RecordNumber::type_record(0x2000)
        );
        assert_eq!(
            p.member_pointer_type,
            Some(MemberPointerType::DataSingleInheritance)
        );
    }

    #[test]
    fn test_pointer_set_segment_info() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.pointer_type = PointerType::SegmentBased;
        p.set_segment_info(0x0001);
        assert_eq!(p.base_segment, 0x0001);
    }

    #[test]
    fn test_pointer_set_type_based_info() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.pointer_type = PointerType::TypeBased;
        p.set_type_based_info(
            RecordNumber::type_record(0x3000),
            "my_type_ptr".to_string(),
        );
        assert_eq!(
            p.pointer_base_type_record_number,
            RecordNumber::type_record(0x3000)
        );
        assert_eq!(p.pointer_name, "my_type_ptr");
    }

    #[test]
    fn test_pointer_set_base_symbol() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.pointer_type = PointerType::Invalid;
        p.set_base_symbol("_extern_sym".to_string());
        assert_eq!(p.base_symbol, "_extern_sym");
    }

    #[test]
    fn test_pointer_is_reference_lvalue() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.pointer_mode = PointerMode::LValueReference;
        assert!(p.is_reference());
    }

    #[test]
    fn test_pointer_is_reference_rvalue() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.pointer_mode = PointerMode::RValueReference;
        assert!(p.is_reference());
    }

    #[test]
    fn test_pointer_is_reference_false() {
        let p = LfPointer::simple(0x0074, 4);
        assert!(!p.is_reference());
    }

    #[test]
    fn test_pointer_is_function_pointer_mode_true() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.pointer_mode = PointerMode::MemberFunctionPointer;
        assert!(p.is_function_pointer_mode());
    }

    #[test]
    fn test_pointer_is_function_pointer_mode_false() {
        let p = LfPointer::simple(0x0074, 4);
        assert!(!p.is_function_pointer_mode());
    }

    #[test]
    fn test_pointer_emit_member_pointer() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.pointer_mode = PointerMode::MemberDataPointer;
        p.set_member_pointer_info(
            RecordNumber::type_record(0x2000),
            MemberPointerType::DataSingleInheritance,
        );
        let emitted = p.emit(Bind::NONE);
        assert!(emitted.contains("::*"));
        assert!(emitted.contains("0x2000"));
        assert!(emitted.contains("pdm16_vfcn"));
    }

    #[test]
    fn test_pointer_emit_const_ref() {
        let mut p = LfPointer::simple(0x0074, 4);
        p.pointer_mode = PointerMode::LValueReference;
        p.is_const = true;
        let emitted = p.emit(Bind::NONE);
        assert!(emitted.contains('&'));
        assert!(emitted.contains("const "));
    }
}
