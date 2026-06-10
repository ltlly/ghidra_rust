//! LF_NESTTYPE -- concrete Nested Type type record.
//!
//! Ports Ghidra's `NestedTypeMsType` (PDB_ID = 0x1510) Java class.
//!
//! Represents a nested type declaration within a composite type
//! (struct/class/union) in the PDB type stream. This is a leaf record
//! that appears inside an `LF_FIELDLIST`. It associates a name with
//! a type record number for a type defined inside another type.
//!
//! # Binary Layout (LF_NESTTYPE / 0x1510)
//!
//! ```text
//! +0  u16   padding           2 bytes of documented padding
//! +2  u32   nestedType        Type index of the nested type definition
//! +6  StringNt name           Null-terminated type name
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

/// Concrete PDB nested type record (`LF_NESTTYPE`).
///
/// This is the Rust equivalent of Ghidra's `NestedTypeMsType`. It stores
/// the record number of the nested type definition and its name.
///
/// Corresponds to the Java `NestedTypeMsType` class and its parent
/// `AbstractNestedTypeMsType`.
#[derive(Debug, Clone)]
pub struct LfNesttype {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the nested type definition.
    pub nested_type_record_number: RecordNumber,
    /// Type name.
    pub name: String,
}

impl LfNesttype {
    /// Create a new nested type record.
    pub fn new(
        nested_type_record_number: RecordNumber,
        name: String,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            nested_type_record_number,
            name,
        }
    }

    /// Create from raw parsed field values.
    ///
    /// Note: the Java implementation reads 2 bytes of padding before
    /// the type index. This constructor takes the already-parsed values.
    pub fn from_parsed(
        nested_type_index: u32,
        name: String,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(nested_type_index),
            name,
        )
    }

    /// Get the record number of the nested type definition.
    ///
    /// Mirrors Java `AbstractNestedTypeMsType.getNestedTypeDefinitionRecordNumber()`.
    pub fn nested_type_definition_record_number(&self) -> RecordNumber {
        self.nested_type_record_number
    }
}

impl AbstractMsType for LfNesttype {
    fn name(&self) -> &str {
        &self.name
    }

    fn pdb_id(&self) -> u32 {
        0x1510 // LF_NESTTYPE
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java:
        //   builder.append(name);
        //   pdb.getTypeRecord(nestedTypeDefinitionRecordNumber).emit(builder, Bind.NONE);
        let mut result = String::new();
        result.push_str(&self.name);
        result.push(' ');
        result.push_str(&self.nested_type_record_number.to_string());
        result
    }
}

impl fmt::Display for LfNesttype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_nesttype() -> LfNesttype {
        LfNesttype::new(
            RecordNumber::type_record(0x1001),
            "InnerClass".to_string(),
        )
    }

    #[test]
    fn test_nesttype_basic() {
        let nt = make_test_nesttype();
        assert_eq!(nt.name(), "InnerClass");
        assert_eq!(nt.pdb_id(), 0x1510);
        assert_eq!(
            nt.nested_type_record_number,
            RecordNumber::type_record(0x1001)
        );
    }

    #[test]
    fn test_nesttype_from_parsed() {
        let nt = LfNesttype::from_parsed(0x2001, "MyEnum".to_string());
        assert_eq!(nt.name(), "MyEnum");
        assert_eq!(
            nt.nested_type_record_number,
            RecordNumber::type_record(0x2001)
        );
    }

    #[test]
    fn test_nesttype_emit() {
        let nt = make_test_nesttype();
        let emitted = nt.emit(Bind::NONE);
        assert!(emitted.contains("InnerClass"));
        assert!(emitted.contains("0x1001"));
    }

    #[test]
    fn test_nesttype_record_number() {
        let mut nt = make_test_nesttype();
        assert!(nt.record_number().is_no_type());
        nt.set_record_number(RecordNumber::type_record(0x3000));
        assert_eq!(nt.record_number().index(), 0x3000);
    }

    #[test]
    fn test_nesttype_display() {
        let nt = make_test_nesttype();
        let display = format!("{}", nt);
        assert!(display.contains("InnerClass"));
        assert!(display.contains("0x1001"));
    }

    #[test]
    fn test_nesttype_nested_type_definition_record_number() {
        let nt = LfNesttype::new(
            RecordNumber::type_record(0x4000),
            "Nested".to_string(),
        );
        assert_eq!(
            nt.nested_type_definition_record_number(),
            RecordNumber::type_record(0x4000)
        );
    }

    #[test]
    fn test_nesttype_empty_name() {
        let nt = LfNesttype::new(
            RecordNumber::type_record(0x1001),
            String::new(),
        );
        assert!(nt.name().is_empty());
    }
}
