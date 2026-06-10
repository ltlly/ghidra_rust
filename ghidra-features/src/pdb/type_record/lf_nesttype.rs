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
use super::{MsTypeField, RecordNumber};
use crate::pdb::pdb_byte_reader::PdbByteReader;
use crate::pdb::pdb_exception::PdbException;

/// Concrete PDB nested type record (`LF_NESTTYPE`).
///
/// This is the Rust equivalent of Ghidra's `NestedTypeMsType`. It stores
/// the record number of the nested type definition and its name.
///
/// Corresponds to the Java `NestedTypeMsType` class and its parent
/// `AbstractNestedTypeMsType`.
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Parse an `LF_NESTTYPE` record from raw bytes (payload after leaf ID).
    ///
    /// Mirrors the Java `NestedTypeMsType(AbstractPdb, PdbByteReader)` constructor.
    /// The `data` slice should start at the `padding` field (after the
    /// 2-byte leaf ID).
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u16   padding           2 bytes of documented padding (skipped)
    /// +2  u32   nestedType        Type index of the nested type definition
    /// +6  StringNt name           Null-terminated type name
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 6 {
            return Err(format!(
                "LF_NESTTYPE payload too short: need >= 6 bytes, got {}",
                data.len()
            ));
        }
        // Skip 2 bytes of padding at offset 0.
        let nested_type_ti = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        let name = if data.len() > 6 {
            crate::pdb::pdb_byte_reader::parse_null_terminated_string(&data[6..])
        } else {
            String::new()
        };
        Ok(Self::from_parsed(nested_type_ti, name))
    }

    /// Parse an `LF_NESTTYPE` record from a [`PdbByteReader`].
    ///
    /// Mirrors the Java `NestedTypeMsType(AbstractPdb, PdbByteReader)` constructor.
    /// Skips 2 bytes of padding, reads the nested type record number (32-bit),
    /// and a null-terminated name string, then aligns to 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PdbException`] if the reader does not have enough data.
    pub fn parse_from_reader(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        reader.skip(2)?; // padding
        let nested_type_ti = reader.read_u32()?;
        let name = reader.read_cstring()?;
        reader.align(4);
        Ok(Self::from_parsed(nested_type_ti, name))
    }

    /// Get the record number of the nested type definition.
    ///
    /// Mirrors Java `AbstractNestedTypeMsType.getNestedTypeDefinitionRecordNumber()`.
    pub fn nested_type_definition_record_number(&self) -> RecordNumber {
        self.nested_type_record_number
    }

    /// Get the name of this nested type.
    ///
    /// Mirrors Java `AbstractNestedTypeMsType.getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Whether the nested type record number references a valid type.
    pub fn has_valid_nested_type(&self) -> bool {
        !self.nested_type_record_number.is_no_type()
    }

    /// Convert this nested type into a [`FieldListEntry::NestedType`].
    ///
    /// This is useful when constructing or manipulating field lists
    /// programmatically.
    pub fn to_field_list_entry(&self) -> super::abstract_field_list_ms_type::FieldListEntry {
        super::abstract_field_list_ms_type::FieldListEntry::NestedType {
            type_record: self.nested_type_record_number,
            name: self.name.clone(),
        }
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

impl MsTypeField for LfNesttype {}

impl Default for LfNesttype {
    fn default() -> Self {
        Self::new(RecordNumber::NO_TYPE, String::new())
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

    #[test]
    fn test_nesttype_parse() {
        // LF_NESTTYPE payload: padding=0x0000, nestedType=0x1001, name="InnerClass"
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000u16.to_le_bytes()); // padding
        data.extend_from_slice(&0x1001u32.to_le_bytes()); // nestedType
        data.extend_from_slice(b"InnerClass\0");           // name

        let nt = LfNesttype::parse(&data).unwrap();
        assert_eq!(nt.name(), "InnerClass");
        assert_eq!(nt.pdb_id(), 0x1510);
        assert_eq!(
            nt.nested_type_record_number,
            RecordNumber::type_record(0x1001)
        );
    }

    #[test]
    fn test_nesttype_parse_with_nonzero_padding() {
        // The padding field should be skipped regardless of its value.
        let mut data = Vec::new();
        data.extend_from_slice(&0xABCDu16.to_le_bytes()); // non-zero padding
        data.extend_from_slice(&0x2000u32.to_le_bytes()); // nestedType
        data.extend_from_slice(b"MyType\0");

        let nt = LfNesttype::parse(&data).unwrap();
        assert_eq!(nt.name(), "MyType");
        assert_eq!(
            nt.nested_type_record_number,
            RecordNumber::type_record(0x2000)
        );
    }

    #[test]
    fn test_nesttype_parse_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000u16.to_le_bytes());
        data.extend_from_slice(&0x1001u32.to_le_bytes());
        data.push(0); // empty null-terminated string

        let nt = LfNesttype::parse(&data).unwrap();
        assert!(nt.name().is_empty());
    }

    #[test]
    fn test_nesttype_parse_no_name_bytes() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000u16.to_le_bytes());
        data.extend_from_slice(&0x1001u32.to_le_bytes());

        let nt = LfNesttype::parse(&data).unwrap();
        assert!(nt.name().is_empty());
    }

    #[test]
    fn test_nesttype_parse_too_short() {
        let data = [0u8; 4];
        assert!(LfNesttype::parse(&data).is_err());
    }

    #[test]
    fn test_nesttype_has_valid_nested_type() {
        let nt = make_test_nesttype();
        assert!(nt.has_valid_nested_type());

        let nt2 = LfNesttype::new(
            RecordNumber::NO_TYPE,
            "bad".to_string(),
        );
        assert!(!nt2.has_valid_nested_type());
    }

    #[test]
    fn test_nesttype_eq() {
        let nt1 = make_test_nesttype();
        let nt2 = make_test_nesttype();
        assert_eq!(nt1, nt2);

        let nt3 = LfNesttype::new(
            RecordNumber::type_record(0x1001),
            "Different".to_string(),
        );
        assert_ne!(nt1, nt3);
    }

    #[test]
    fn test_nesttype_emit_format() {
        let nt = make_test_nesttype();
        let emitted = nt.emit(Bind::NONE);
        // Format: "InnerClass 0x1001"
        assert!(emitted.starts_with("InnerClass "));
    }

    #[test]
    fn test_nesttype_to_field_list_entry() {
        let nt = make_test_nesttype();
        let entry = nt.to_field_list_entry();
        match entry {
            super::super::abstract_field_list_ms_type::FieldListEntry::NestedType {
                type_record,
                name,
            } => {
                assert_eq!(type_record, RecordNumber::type_record(0x1001));
                assert_eq!(name, "InnerClass");
            }
            _ => panic!("Expected NestedType variant"),
        }
    }

    #[test]
    fn test_nesttype_default() {
        let nt = LfNesttype::default();
        assert!(nt.name().is_empty());
        assert!(nt.record_number().is_no_type());
    }

    #[test]
    fn test_nesttype_parse_from_reader() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000u16.to_le_bytes()); // padding
        data.extend_from_slice(&0x1001u32.to_le_bytes()); // nestedType
        data.extend_from_slice(b"InnerClass\0");           // name

        let mut reader = PdbByteReader::new(&data);
        let nt = LfNesttype::parse_from_reader(&mut reader).unwrap();
        assert_eq!(nt.name(), "InnerClass");
        assert_eq!(nt.pdb_id(), 0x1510);
        assert_eq!(
            nt.nested_type_record_number,
            RecordNumber::type_record(0x1001)
        );
    }

    #[test]
    fn test_nesttype_parse_from_reader_aligns() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000u16.to_le_bytes()); // padding
        data.extend_from_slice(&0x2000u32.to_le_bytes()); // nestedType
        data.extend_from_slice(b"a\0");                    // name (2 bytes, total 8)
        // 8 is already aligned to 4

        let mut reader = PdbByteReader::new(&data);
        let nt = LfNesttype::parse_from_reader(&mut reader).unwrap();
        assert_eq!(nt.name(), "a");
        assert_eq!(reader.position(), 8); // aligned to 4
    }

    #[test]
    fn test_nesttype_parse_from_reader_too_short() {
        let data = [0u8; 4];
        let mut reader = PdbByteReader::new(&data);
        assert!(LfNesttype::parse_from_reader(&mut reader).is_err());
    }

    #[test]
    fn test_nesttype_get_name() {
        let nt = make_test_nesttype();
        assert_eq!(nt.get_name(), "InnerClass");
    }

    #[test]
    fn test_nesttype_get_name_empty() {
        let nt = LfNesttype::default();
        assert_eq!(nt.get_name(), "");
    }

    #[test]
    fn test_nesttype_clone() {
        let nt = make_test_nesttype();
        let nt2 = nt.clone();
        assert_eq!(nt, nt2);
    }

    #[test]
    fn test_nesttype_parse_long_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000u16.to_le_bytes()); // padding
        data.extend_from_slice(&0x5000u32.to_le_bytes()); // nestedType
        data.extend_from_slice(b"std::vector<int>::iterator\0");

        let nt = LfNesttype::parse(&data).unwrap();
        assert_eq!(nt.name(), "std::vector<int>::iterator");
        assert_eq!(
            nt.nested_type_record_number,
            RecordNumber::type_record(0x5000)
        );
    }

    #[test]
    fn test_nesttype_parse_from_reader_long_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000u16.to_le_bytes()); // padding
        data.extend_from_slice(&0x5000u32.to_le_bytes()); // nestedType
        data.extend_from_slice(b"MyNamespace::MyClass\0");

        let mut reader = PdbByteReader::new(&data);
        let nt = LfNesttype::parse_from_reader(&mut reader).unwrap();
        assert_eq!(nt.get_name(), "MyNamespace::MyClass");
        assert!(reader.position() > 0);
    }
}
