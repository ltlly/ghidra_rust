//! Code unit types for the trace database listing.
//!
//! Ported from Ghidra's `AbstractDBTraceCodeUnit`, `DBTraceData`,
//! `DBTraceDataArrayElementComponent`, and `DBTraceDataCompositeFieldComponent`.

use crate::model::CodeUnitType;

/// The kind of code unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeUnitKind {
    /// An instruction.
    Instruction,
    /// A defined data element.
    Data,
    /// An undefined region.
    Undefined,
    /// A data component (array element or composite field).
    DataComponent,
}

/// An abstract code unit in a trace.
///
/// Each code unit occupies a range of addresses at a particular snap and
/// optionally within a thread scope.
#[derive(Debug, Clone)]
pub struct AbstractCodeUnit {
    /// The start offset of this code unit.
    pub offset: u64,
    /// The length in bytes.
    pub length: u32,
    /// The snap at which this unit is valid.
    pub snap: i64,
    /// The thread ID (0 for global).
    pub thread_id: u64,
    /// The kind of code unit.
    pub kind: CodeUnitKind,
    /// The code unit type code (from Ghidra's CodeUnit interface).
    pub unit_type: CodeUnitType,
    /// Whether this unit is in an overlay space.
    pub is_overlay: bool,
    /// The address space name.
    pub space_name: String,
}

impl AbstractCodeUnit {
    /// Get the maximum (last) address offset of this code unit.
    pub fn max_offset(&self) -> u64 {
        self.offset + self.length as u64 - 1
    }

    /// Get the address range as (min, max) offsets.
    pub fn offset_range(&self) -> (u64, u64) {
        (self.offset, self.max_offset())
    }

    /// Check whether an offset falls within this code unit.
    pub fn contains_offset(&self, offset: u64) -> bool {
        offset >= self.offset && offset <= self.max_offset()
    }

    /// Check if this is an instruction.
    pub fn is_instruction(&self) -> bool {
        self.kind == CodeUnitKind::Instruction
    }

    /// Check if this is defined data.
    pub fn is_data(&self) -> bool {
        self.kind == CodeUnitKind::Data
    }

    /// Check if this is undefined.
    pub fn is_undefined(&self) -> bool {
        self.kind == CodeUnitKind::Undefined
    }
}

/// A defined data element in the trace listing.
#[derive(Debug, Clone)]
pub struct DbTraceData {
    /// The base code unit properties.
    pub base: AbstractCodeUnit,
    /// The name of the data type.
    pub data_type_name: String,
    /// The category path of the data type.
    pub category_path: String,
    /// The number of components (for arrays/structs).
    pub num_components: u32,
    /// Whether this data has been explicitly defined by the user.
    pub is_user_defined: bool,
    /// The value as raw bytes, if available.
    pub value_bytes: Option<Vec<u8>>,
}

impl DbTraceData {
    /// Create a new defined data unit.
    pub fn new(
        offset: u64,
        length: u32,
        snap: i64,
        data_type_name: impl Into<String>,
    ) -> Self {
        Self {
            base: AbstractCodeUnit {
                offset,
                length,
                snap,
                thread_id: 0,
                kind: CodeUnitKind::Data,
                unit_type: CodeUnitType::Data,
                is_overlay: false,
                space_name: "ram".into(),
            },
            data_type_name: data_type_name.into(),
            category_path: "/".into(),
            num_components: 0,
            is_user_defined: true,
            value_bytes: None,
        }
    }

    /// Check if this is a composite data type (struct, union).
    pub fn is_composite(&self) -> bool {
        self.num_components > 0
    }

    /// Get the parent data unit, if this is a component.
    pub fn parent_offset(&self) -> Option<u64> {
        None // Components override this
    }
}

/// An array element component within a parent data unit.
#[derive(Debug, Clone)]
pub struct DbTraceDataArrayElement {
    /// The base code unit for this component.
    pub base: AbstractCodeUnit,
    /// The offset of the parent data unit.
    pub parent_offset: u64,
    /// The index within the array.
    pub element_index: u32,
    /// The data type name of the element.
    pub element_data_type: String,
    /// The byte offset within the parent.
    pub offset_in_parent: u32,
}

impl DbTraceDataArrayElement {
    /// Create a new array element component.
    pub fn new(
        offset: u64,
        length: u32,
        snap: i64,
        parent_offset: u64,
        element_index: u32,
        element_data_type: impl Into<String>,
        offset_in_parent: u32,
    ) -> Self {
        Self {
            base: AbstractCodeUnit {
                offset,
                length,
                snap,
                thread_id: 0,
                kind: CodeUnitKind::DataComponent,
                unit_type: CodeUnitType::Data,
                is_overlay: false,
                space_name: "ram".into(),
            },
            parent_offset,
            element_index,
            element_data_type: element_data_type.into(),
            offset_in_parent,
        }
    }

    /// Get the parent offset.
    pub fn parent_offset(&self) -> u64 {
        self.parent_offset
    }
}

/// A composite field component within a parent struct/union data unit.
#[derive(Debug, Clone)]
pub struct DbTraceDataCompositeField {
    /// The base code unit for this component.
    pub base: AbstractCodeUnit,
    /// The offset of the parent data unit.
    pub parent_offset: u64,
    /// The field name within the composite type.
    pub field_name: String,
    /// The field ordinal (index).
    pub field_ordinal: u32,
    /// The data type name of the field.
    pub field_data_type: String,
    /// The byte offset within the parent.
    pub offset_in_parent: u32,
}

impl DbTraceDataCompositeField {
    /// Create a new composite field component.
    pub fn new(
        offset: u64,
        length: u32,
        snap: i64,
        parent_offset: u64,
        field_name: impl Into<String>,
        field_ordinal: u32,
        field_data_type: impl Into<String>,
        offset_in_parent: u32,
    ) -> Self {
        Self {
            base: AbstractCodeUnit {
                offset,
                length,
                snap,
                thread_id: 0,
                kind: CodeUnitKind::DataComponent,
                unit_type: CodeUnitType::Data,
                is_overlay: false,
                space_name: "ram".into(),
            },
            parent_offset,
            field_name: field_name.into(),
            field_ordinal,
            field_data_type: field_data_type.into(),
            offset_in_parent,
        }
    }

    /// Get the parent offset.
    pub fn parent_offset(&self) -> u64 {
        self.parent_offset
    }
}

/// A trait for anything that can be used as a code unit reference.
pub trait CodeUnitRef {
    /// Get the offset of this code unit.
    fn offset(&self) -> u64;
    /// Get the length in bytes.
    fn length(&self) -> u32;
    /// Get the kind.
    fn kind(&self) -> CodeUnitKind;
    /// Get the snap.
    fn snap(&self) -> i64;
}

impl CodeUnitRef for AbstractCodeUnit {
    fn offset(&self) -> u64 { self.offset }
    fn length(&self) -> u32 { self.length }
    fn kind(&self) -> CodeUnitKind { self.kind }
    fn snap(&self) -> i64 { self.snap }
}

impl CodeUnitRef for DbTraceData {
    fn offset(&self) -> u64 { self.base.offset }
    fn length(&self) -> u32 { self.base.length }
    fn kind(&self) -> CodeUnitKind { self.base.kind }
    fn snap(&self) -> i64 { self.base.snap }
}

impl CodeUnitRef for DbTraceInstruction {
    fn offset(&self) -> u64 { self.base.offset }
    fn length(&self) -> u32 { self.base.length }
    fn kind(&self) -> CodeUnitKind { self.base.kind }
    fn snap(&self) -> i64 { self.base.snap }
}

/// Instruction code unit (re-exported here for trait impl).
use super::instruction::DbTraceInstruction;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abstract_code_unit_basics() {
        let unit = AbstractCodeUnit {
            offset: 0x1000,
            length: 4,
            snap: 0,
            thread_id: 0,
            kind: CodeUnitKind::Instruction,
            unit_type: CodeUnitType::Instruction,
            is_overlay: false,
            space_name: "ram".into(),
        };

        assert_eq!(unit.max_offset(), 0x1003);
        assert!(unit.contains_offset(0x1002));
        assert!(!unit.contains_offset(0x1004));
        assert!(unit.is_instruction());
        assert!(!unit.is_data());
    }

    #[test]
    fn test_db_trace_data() {
        let data = DbTraceData::new(0x2000, 4, 10, "dword");
        assert_eq!(data.base.offset, 0x2000);
        assert_eq!(data.data_type_name, "dword");
        assert!(!data.is_composite());
    }

    #[test]
    fn test_array_element() {
        let elem = DbTraceDataArrayElement::new(0x3004, 4, 0, 0x3000, 1, "dword", 4);
        assert_eq!(elem.parent_offset(), 0x3000);
        assert_eq!(elem.element_index, 1);
    }

    #[test]
    fn test_composite_field() {
        let field = DbTraceDataCompositeField::new(
            0x4008, 8, 0, 0x4000, "timestamp", 2, "longlong", 8,
        );
        assert_eq!(field.field_name, "timestamp");
        assert_eq!(field.offset_in_parent, 8);
    }

    #[test]
    fn test_code_unit_ref_trait() {
        let data = DbTraceData::new(0x1000, 4, 5, "dword");
        assert_eq!(data.offset(), 0x1000);
        assert_eq!(data.length(), 4);
        assert_eq!(data.snap(), 5);
    }
}
