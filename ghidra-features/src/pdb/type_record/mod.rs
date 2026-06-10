//! PDB Abstract Type Records
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.type` package.
//!
//! This module provides abstract type record representations for PDB data types,
//! including arrays, classes, composites (structs/classes/unions), enums, and
//! field lists. Each abstract type implements the [`AbstractMsType`] trait which
//! provides common accessors and the [`AbstractMsType::emit`] method for
//! debug/type-string output.
//!
//! # Hierarchy (mirrors Java)
//!
//! ```text
//! AbstractMsType (trait)
//!   +-- AbstractArrayMsType
//!   +-- ComplexTypeFields
//!   |     +-- AbstractCompositeMsType
//!   |     |     +-- AbstractClassMsType
//!   |     |     +-- AbstractStructureMsType
//!   |     |     +-- AbstractUnionMsType
//!   |     +-- AbstractEnumMsType
//!   +-- AbstractFieldListMsType
//! ```

pub mod bind;
pub mod ms_property;
pub mod abstract_ms_type;
pub mod abstract_complex_ms_type;
pub mod abstract_array_ms_type;
pub mod abstract_class_ms_type;
pub mod abstract_composite_ms_type;
pub mod abstract_enum_ms_type;
pub mod abstract_field_list_ms_type;

// Concrete LF_* type records.
pub mod lf_arglist;
pub mod lf_array;
pub mod lf_bclass;
pub mod lf_bitfield;
pub mod lf_class;
pub mod lf_enum;
pub mod lf_fieldlist;
pub mod lf_member;
pub mod lf_method;
pub mod lf_mfunction;
pub mod lf_modifier;
pub mod lf_nesttype;
pub mod lf_onemethod;
pub mod lf_pointer;
pub mod lf_procedure;
pub mod lf_stmember;
pub mod lf_structure;
pub mod lf_union;
pub mod lf_vfunctab;
pub mod lf_vtshape;
pub mod lf_oem;
pub mod lf_skip;
pub mod lf_index;
pub mod lf_func_id;
pub mod lf_mfunc_id;

// Re-export key types for convenience.
pub use bind::Bind;
pub use ms_property::MsProperty;
pub use abstract_ms_type::{AbstractMsType, UnknownMsType};
pub use abstract_complex_ms_type::ComplexTypeFields;
pub use abstract_array_ms_type::AbstractArrayMsType;
pub use abstract_class_ms_type::AbstractClassMsType;
pub use abstract_composite_ms_type::AbstractCompositeMsType;
pub use abstract_enum_ms_type::AbstractEnumMsType;
pub use abstract_field_list_ms_type::AbstractFieldListMsType;

// Re-export concrete LF_* types.
pub use lf_arglist::LfArglist;
pub use lf_array::LfArray;
pub use lf_bclass::LfBclass;
pub use lf_bitfield::LfBitfield;
pub use lf_class::LfClass;
pub use lf_enum::LfEnum;
pub use lf_fieldlist::LfFieldlist;
pub use lf_member::LfMember;
pub use lf_method::LfMethod;
pub use lf_mfunction::LfMfunction;
pub use lf_modifier::{LfModifier, LfModifierEx, ExtendedModifier};
pub use lf_nesttype::LfNesttype;
pub use lf_onemethod::LfOnemethod;
pub use lf_pointer::LfPointer;
pub use lf_procedure::LfProcedure;
pub use lf_stmember::LfStmember;
pub use lf_structure::LfStructure;
pub use lf_union::LfUnion;
pub use lf_vfunctab::{LfVfunctab, LfVfuncoff};
pub use lf_vtshape::{LfVtshape, VtShapeDescriptor};
pub use lf_oem::{LfOem, LfOemString2};
pub use lf_skip::LfSkip;
pub use lf_index::LfIndex;
pub use lf_func_id::LfFuncId;
pub use lf_mfunc_id::LfMfuncId;

use std::fmt;

// =============================================================================
// MsTypeField — marker trait for type records that appear inside LF_FIELDLIST
// =============================================================================

/// Marker trait for PDB type records that can appear as sub-entries within
/// an `LF_FIELDLIST` container.
///
/// In the Java implementation this is the `MsTypeField` interface, which
/// extends `IdMsParsable`. In our Rust port, this serves as a compile-time
/// marker to identify types that participate in field list composition:
/// members, static members, methods, base classes, nested types, vftable
/// pointers, enumerates, and indices.
///
/// All types implementing this trait also implement [`AbstractMsType`].
pub trait MsTypeField: AbstractMsType {}

// =============================================================================
// RecordNumber — a PDB type/symbol record reference
// =============================================================================

/// A reference to a record within the TPI or IPI stream.
///
/// In the Java implementation this is `RecordNumber` with a category (TYPE or
/// SYMBOL) and an index. For our Rust port we simplify to a flat `u32` that
/// encodes the same information via the high bit: bit 31 = 0 means TYPE,
/// bit 31 = 1 means SYMBOL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordNumber(u32);

impl RecordNumber {
    /// Sentinel value indicating no type.
    pub const NO_TYPE: RecordNumber = RecordNumber(0);

    /// Create a TYPE category record number.
    pub fn type_record(index: u32) -> Self {
        RecordNumber(index & 0x7FFF_FFFF)
    }

    /// Create a SYMBOL category record number.
    pub fn symbol_record(index: u32) -> Self {
        RecordNumber((index & 0x7FFF_FFFF) | 0x8000_0000)
    }

    /// Get the raw index (without the category bit).
    pub fn index(self) -> u32 {
        self.0 & 0x7FFF_FFFF
    }

    /// Check if this is a symbol record.
    pub fn is_symbol(self) -> bool {
        self.0 & 0x8000_0000 != 0
    }

    /// Check if this is the NO_TYPE sentinel.
    pub fn is_no_type(self) -> bool {
        self == Self::NO_TYPE
    }
}

impl fmt::Display for RecordNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_no_type() {
            write!(f, "NO_TYPE")
        } else if self.is_symbol() {
            write!(f, "SYM(0x{:04X})", self.index())
        } else {
            write!(f, "0x{:04X}", self.index())
        }
    }
}

// =============================================================================
// DelimiterState — helper for emit() formatting
// =============================================================================

/// Helper for building delimited output (e.g., comma-separated member lists).
///
/// Mirrors the Java `DelimiterState` utility class.
#[derive(Debug)]
pub struct DelimiterState {
    first_delimiter: &'static str,
    subsequent_delimiter: &'static str,
    is_first: bool,
}

impl DelimiterState {
    /// Create a new delimiter state.
    pub fn new(first: &'static str, subsequent: &'static str) -> Self {
        Self {
            first_delimiter: first,
            subsequent_delimiter: subsequent,
            is_first: true,
        }
    }

    /// Produce the appropriate delimiter string and advance state.
    ///
    /// If `emit` is `true`, returns the delimiter string; otherwise returns
    /// an empty string (but still advances the first/subsequent state).
    pub fn out(&mut self, emit: bool) -> &str {
        if self.is_first {
            self.is_first = false;
            if emit {
                self.first_delimiter
            } else {
                ""
            }
        } else if emit {
            self.subsequent_delimiter
        } else {
            ""
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_number_type() {
        let rn = RecordNumber::type_record(0x1000);
        assert_eq!(rn.index(), 0x1000);
        assert!(!rn.is_symbol());
        assert!(!rn.is_no_type());
    }

    #[test]
    fn test_record_number_symbol() {
        let rn = RecordNumber::symbol_record(0x2000);
        assert_eq!(rn.index(), 0x2000);
        assert!(rn.is_symbol());
    }

    #[test]
    fn test_record_number_no_type() {
        assert!(RecordNumber::NO_TYPE.is_no_type());
        assert_eq!(RecordNumber::NO_TYPE.index(), 0);
    }

    #[test]
    fn test_record_number_display() {
        assert_eq!(format!("{}", RecordNumber::type_record(0x1000)), "0x1000");
        assert_eq!(format!("{}", RecordNumber::symbol_record(0x0042)), "SYM(0x0042)");
        assert_eq!(format!("{}", RecordNumber::NO_TYPE), "NO_TYPE");
    }

    #[test]
    fn test_delimiter_state() {
        let mut ds = DelimiterState::new(" : ", ", ");
        assert_eq!(ds.out(true), " : ");
        assert_eq!(ds.out(true), ", ");
        assert_eq!(ds.out(true), ", ");
    }

    #[test]
    fn test_delimiter_state_suppressed() {
        let mut ds = DelimiterState::new(" : ", ", ");
        assert_eq!(ds.out(false), "");
        assert_eq!(ds.out(true), ", ");
    }
}
