//! LF_STRUCTURE -- concrete Structure type record.
//!
//! Ports Ghidra's `StructureMsType` (PDB_ID = 0x1505) and
//! `AbstractStructureMsType` Java classes.
//!
//! Represents a C/C++ `struct` type in the PDB type stream.  Wraps
//! [`AbstractCompositeMsType`] with the type string set to `"struct"`.
//!
//! # Binary Layout (LF_STRUCTURE / 0x1505)
//!
//! ```text
//! +0  u16   count           Number of members
//! +2  MsProperty property   Property flags
//! +4  u32   fieldList       Type index of the LF_FIELDLIST
//! +8  u32   derivedFrom     Type index of the derived-from list
//! +12 u32   vshape          Type index of the VShape table
//! +16 Numeric size          Size in bytes (variable-length encoding)
//!     StringNt name         Null-terminated name
//!     StringNt mangledName  Null-terminated mangled name (optional)
//! ```

use std::fmt;

use super::abstract_composite_ms_type::AbstractCompositeMsType;
use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::ms_property::MsProperty;
use super::RecordNumber;

/// Concrete PDB structure type record (`LF_STRUCTURE`).
///
/// This is the Rust equivalent of Ghidra's `StructureMsType`.  It delegates
/// all composite fields and behaviour to the embedded
/// [`AbstractCompositeMsType`], overriding only the type string to
/// `"struct"` and the PDB ID to `0x1505`.
#[derive(Debug, Clone)]
pub struct LfStructure {
    /// The underlying composite data (count, field list, size, name, etc.).
    pub composite: AbstractCompositeMsType,
}

impl LfStructure {
    /// Create a new structure type record.
    ///
    /// # Parameters
    ///
    /// * `count` - Number of field members (-1 if unknown).
    /// * `field_list_record_number` - Record number of the LF_FIELDLIST.
    /// * `derived_from_list_record_number` - Record number of the derived-from list.
    /// * `vshape_table_record_number` - Record number of the VShape table.
    /// * `size` - Size of the structure in bytes.
    /// * `property` - Property flags.
    /// * `name` - Human-readable name (e.g. `"MyStruct"`).
    /// * `mangled_name` - Mangled/decorated name (may be empty).
    pub fn new(
        count: i32,
        field_list_record_number: RecordNumber,
        derived_from_list_record_number: RecordNumber,
        vshape_table_record_number: RecordNumber,
        size: u64,
        property: MsProperty,
        name: String,
        mangled_name: String,
    ) -> Self {
        Self {
            composite: AbstractCompositeMsType::new(
                count,
                field_list_record_number,
                derived_from_list_record_number,
                vshape_table_record_number,
                size,
                property,
                name,
                mangled_name,
                "struct",
            ),
        }
    }

    /// Create from raw parsed field values.
    ///
    /// This is the typical constructor used after deserializing the binary
    /// PDB type record.  Record numbers are constructed from raw type indices.
    pub fn from_parsed(
        count: u16,
        property: MsProperty,
        field_list_type_index: u32,
        derived_type_index: u32,
        vshape_type_index: u32,
        size: u64,
        name: String,
        mangled_name: Option<String>,
    ) -> Self {
        Self::new(
            count as i32,
            RecordNumber::type_record(field_list_type_index),
            RecordNumber::type_record(derived_type_index),
            RecordNumber::type_record(vshape_type_index),
            size,
            property,
            name,
            mangled_name.unwrap_or_default(),
        )
    }
}

impl AbstractMsType for LfStructure {
    fn name(&self) -> &str {
        self.composite.name()
    }

    fn pdb_id(&self) -> u32 {
        0x1505 // LF_STRUCTURE
    }

    fn record_number(&self) -> RecordNumber {
        self.composite.record_number()
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.composite.set_record_number(record_number);
    }

    fn emit(&self, _bind: Bind) -> String {
        self.composite.emit(Bind::NONE)
    }
}

impl fmt::Display for LfStructure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_structure() -> LfStructure {
        LfStructure::new(
            3,
            RecordNumber::type_record(0x1001),
            RecordNumber::type_record(0x1002),
            RecordNumber::type_record(0x1003),
            24,
            MsProperty::empty(),
            "Point3D".to_string(),
            String::new(),
        )
    }

    #[test]
    fn test_structure_basic() {
        let s = make_test_structure();
        assert_eq!(s.name(), "Point3D");
        assert_eq!(s.pdb_id(), 0x1505);
        assert_eq!(s.composite.type_string(), "struct");
        assert_eq!(s.composite.get_size(), 24);
        assert_eq!(s.composite.num_elements(), 3);
    }

    #[test]
    fn test_structure_from_parsed() {
        let s = LfStructure::from_parsed(
            5,
            MsProperty::empty(),
            0x1001,
            0,
            0,
            40,
            "Vec3".to_string(),
            None,
        );

        assert_eq!(s.name(), "Vec3");
        assert_eq!(s.composite.type_string(), "struct");
        assert!(s.composite.mangled_name().is_empty());
    }

    #[test]
    fn test_structure_from_parsed_with_mangled() {
        let s = LfStructure::from_parsed(
            2,
            MsProperty::PACKED,
            0x1001,
            0,
            0,
            8,
            "Packed".to_string(),
            Some(".?AUPacked@@".to_string()),
        );

        assert_eq!(s.composite.mangled_name(), ".?AUPacked@@");
        assert!(s.composite.property.contains(MsProperty::PACKED));
    }

    #[test]
    fn test_structure_emit() {
        let s = make_test_structure();
        let emitted = s.emit(Bind::NONE);
        assert!(emitted.starts_with("struct Point3D<"));
        assert!(emitted.contains("3,"));
        assert!(emitted.contains("0x1001"));
    }

    #[test]
    fn test_structure_record_number() {
        let mut s = make_test_structure();
        assert!(s.record_number().is_no_type());
        s.set_record_number(RecordNumber::type_record(0x3000));
        assert_eq!(s.record_number().index(), 0x3000);
    }

    #[test]
    fn test_structure_display() {
        let s = make_test_structure();
        let display = format!("{}", s);
        assert!(display.contains("struct"));
        assert!(display.contains("Point3D"));
    }

    #[test]
    fn test_structure_forward_ref() {
        let s = LfStructure::new(
            0,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            0,
            MsProperty::FORWARD_REF,
            "FwdStruct".to_string(),
            String::new(),
        );
        assert!(s.composite.is_forward_ref());
    }

    #[test]
    fn test_structure_nested() {
        let s = LfStructure::new(
            1,
            RecordNumber::type_record(0x1001),
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            4,
            MsProperty::NESTED,
            "Inner".to_string(),
            String::new(),
        );
        assert!(s.composite.is_nested());
    }
}
