//! LF_CLASS -- concrete Class type record.
//!
//! Ports Ghidra's `ClassMsType` (PDB_ID = 0x1504) and
//! `AbstractClassMsType` Java classes.
//!
//! Represents a C++ `class` type in the PDB type stream.  Wraps
//! [`AbstractCompositeMsType`] with the type string set to `"class"`.
//!
//! # Binary Layout (LF_CLASS / 0x1504)
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

use super::abstract_class_ms_type::AbstractClassMsType;
use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::ms_property::{Hfa, Mocom, MsProperty};
use super::RecordNumber;

/// Concrete PDB class type record (`LF_CLASS`).
///
/// This is the Rust equivalent of Ghidra's `ClassMsType`.  It delegates
/// all composite fields and behaviour to the embedded
/// [`AbstractClassMsType`], overriding only the PDB ID to `0x1504`.
///
/// `LF_CLASS` has the same binary layout as `LF_STRUCTURE` (0x1505) and
/// `LF_UNION` (0x1506) but uses the `"class"` type string and a different
/// PDB ID constant.
#[derive(Debug, Clone)]
pub struct LfClass {
    /// The underlying class data (composite with type_string = "class").
    pub class_data: AbstractClassMsType,
}

impl LfClass {
    /// Create a new class type record.
    ///
    /// # Parameters
    ///
    /// * `count` - Number of field members (-1 if unknown).
    /// * `field_list_record_number` - Record number of the LF_FIELDLIST.
    /// * `derived_from_list_record_number` - Record number of the derived-from list.
    /// * `vshape_table_record_number` - Record number of the VShape table.
    /// * `size` - Size of the class in bytes.
    /// * `property` - Property flags.
    /// * `name` - Human-readable name (e.g. `"MyClass"`).
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
            class_data: AbstractClassMsType::new(
                count,
                field_list_record_number,
                derived_from_list_record_number,
                vshape_table_record_number,
                size,
                property,
                name,
                mangled_name,
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
        Self {
            class_data: AbstractClassMsType::from_parsed(
                count,
                property,
                field_list_type_index,
                derived_type_index,
                vshape_type_index,
                size,
                name,
                mangled_name,
            ),
        }
    }

    /// Parse an `LF_CLASS` record from raw bytes (payload after leaf ID).
    ///
    /// Mirrors the Java `ClassMsType(AbstractPdb, PdbByteReader)` constructor.
    /// The `data` slice should start at the `count` field (after the 2-byte leaf ID).
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 16 {
            return Err(format!(
                "LF_CLASS payload too short: need >= 16 bytes, got {}",
                data.len()
            ));
        }
        let count = u16::from_le_bytes([data[0], data[1]]);
        let property = MsProperty::from_u16(u16::from_le_bytes([data[2], data[3]]));
        let field_list_ti = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let derived_ti = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let vshape_ti = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

        let (size, next) = crate::pdb::pdb_byte_reader::parse_numeric(data, 16);

        let (name, mangled_name) = if next < data.len() {
            let (n, after_n) = crate::pdb::pdb_byte_reader::read_null_terminated_string(data, next);
            let mn = if after_n < data.len() && data[after_n] != 0 {
                crate::pdb::pdb_byte_reader::parse_null_terminated_string(&data[after_n..])
            } else {
                String::new()
            };
            (n, if mn.is_empty() { None } else { Some(mn) })
        } else {
            (String::new(), None)
        };

        Ok(Self::from_parsed(count, property, field_list_ti, derived_ti, vshape_ti, size, name, mangled_name))
    }

    // =========================================================================
    // Property-based accessors
    // =========================================================================

    /// Whether this class is scoped.
    pub fn is_scoped(&self) -> bool {
        self.class_data.composite.property.contains(MsProperty::SCOPED)
    }

    /// Whether this class has a unique name.
    pub fn has_unique_name(&self) -> bool {
        self.class_data.composite.property.contains(MsProperty::HAS_UNIQUE_NAME)
    }

    /// Whether this class is sealed (cannot be inherited).
    pub fn is_sealed(&self) -> bool {
        self.class_data.composite.property.contains(MsProperty::SEALED)
    }

    /// Whether this class is packed.
    pub fn is_packed(&self) -> bool {
        self.class_data.composite.property.contains(MsProperty::PACKED)
    }

    /// Whether this class has overloaded operators.
    pub fn has_overloaded_ops(&self) -> bool {
        self.class_data.composite.property.contains(MsProperty::OVERLOADED_OPS)
    }

    /// Whether this class has overloaded assignment operators.
    pub fn has_overloaded_assign(&self) -> bool {
        self.class_data.composite.property.contains(MsProperty::OVLD_ASSIGN)
    }

    /// Whether this class has casting operators.
    pub fn has_casting_ops(&self) -> bool {
        self.class_data.composite.property.contains(MsProperty::CASTING_OPS)
    }

    /// Whether this class has constructors/destructors.
    pub fn has_ctor_dtor(&self) -> bool {
        self.class_data.composite.property.contains(MsProperty::CTOR)
    }

    /// Whether this class contains nested types.
    pub fn contains_nested(&self) -> bool {
        self.class_data.composite.contains_nested()
    }

    /// Get the HFA classification.
    pub fn hfa(&self) -> Hfa {
        self.class_data.composite.property.hfa()
    }

    /// Get the Mocom classification.
    pub fn mocom(&self) -> Mocom {
        self.class_data.composite.property.mocom()
    }

    /// Get the size of this class in bytes.
    pub fn get_size(&self) -> u64 {
        self.class_data.composite.get_size()
    }

    /// Get the number of field elements.
    pub fn get_count(&self) -> i32 {
        self.class_data.composite.num_elements()
    }

    /// Get the field list record number.
    pub fn get_field_list_record_number(&self) -> RecordNumber {
        self.class_data.composite.field_list_record_number
    }

    /// Get the derived-from list record number.
    pub fn get_derived_from_record_number(&self) -> RecordNumber {
        self.class_data.composite.derived_from_list_record_number
    }

    /// Get the VShape table record number.
    pub fn get_vshape_record_number(&self) -> RecordNumber {
        self.class_data.composite.vshape_table_record_number
    }

    /// Get the property flags.
    pub fn property(&self) -> MsProperty {
        self.class_data.composite.property
    }

    /// Get the mangled name, if any.
    pub fn mangled_name(&self) -> &str {
        self.class_data.composite.mangled_name()
    }
}

impl AbstractMsType for LfClass {
    fn name(&self) -> &str {
        self.class_data.name()
    }

    fn pdb_id(&self) -> u32 {
        0x1504 // LF_CLASS
    }

    fn record_number(&self) -> RecordNumber {
        self.class_data.record_number()
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.class_data.set_record_number(record_number);
    }

    fn emit(&self, _bind: Bind) -> String {
        self.class_data.emit(Bind::NONE)
    }
}

impl fmt::Display for LfClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_class() -> LfClass {
        LfClass::new(
            5,
            RecordNumber::type_record(0x1001),
            RecordNumber::type_record(0x0000),
            RecordNumber::type_record(0x1003),
            32,
            MsProperty::NESTED | MsProperty::CTOR,
            "MyClass".to_string(),
            String::new(),
        )
    }

    #[test]
    fn test_class_basic() {
        let c = make_test_class();
        assert_eq!(c.name(), "MyClass");
        assert_eq!(c.pdb_id(), 0x1504);
        assert_eq!(c.class_data.composite.type_string(), "class");
        assert_eq!(c.class_data.composite.get_size(), 32);
        assert_eq!(c.class_data.composite.num_elements(), 5);
    }

    #[test]
    fn test_class_from_parsed() {
        let c = LfClass::from_parsed(
            3,
            MsProperty::empty(),
            0x1001,
            0,
            0,
            16,
            "SimpleClass".to_string(),
            Some(".?AVSimpleClass@@".to_string()),
        );

        assert_eq!(c.name(), "SimpleClass");
        assert_eq!(c.class_data.composite.mangled_name(), ".?AVSimpleClass@@");
        assert_eq!(c.class_data.composite.type_string(), "class");
    }

    #[test]
    fn test_class_from_parsed_no_mangled() {
        let c = LfClass::from_parsed(
            2,
            MsProperty::empty(),
            0x1001,
            0,
            0,
            8,
            "PlainClass".to_string(),
            None,
        );
        assert_eq!(c.name(), "PlainClass");
        assert!(c.class_data.composite.mangled_name().is_empty());
    }

    #[test]
    fn test_class_emit() {
        let c = make_test_class();
        let emitted = c.emit(Bind::NONE);
        assert!(emitted.starts_with("class MyClass<"));
        assert!(emitted.contains("isnested"));
        assert!(emitted.contains("ctor"));
    }

    #[test]
    fn test_class_record_number() {
        let mut c = make_test_class();
        assert!(c.record_number().is_no_type());
        c.set_record_number(RecordNumber::type_record(0x3000));
        assert_eq!(c.record_number().index(), 0x3000);
    }

    #[test]
    fn test_class_display() {
        let c = make_test_class();
        let display = format!("{}", c);
        assert!(display.contains("class"));
        assert!(display.contains("MyClass"));
    }

    #[test]
    fn test_class_forward_ref() {
        let c = LfClass::new(
            0,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            0,
            MsProperty::FORWARD_REF,
            "FwdClass".to_string(),
            String::new(),
        );
        assert!(c.class_data.composite.is_forward_ref());
    }

    #[test]
    fn test_class_nested() {
        let c = LfClass::new(
            1,
            RecordNumber::type_record(0x1001),
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            4,
            MsProperty::NESTED,
            "InnerClass".to_string(),
            String::new(),
        );
        assert!(c.class_data.composite.is_nested());
    }

    #[test]
    fn test_class_with_derived_from() {
        let c = LfClass::new(
            3,
            RecordNumber::type_record(0x1001),
            RecordNumber::type_record(0x2001),
            RecordNumber::NO_TYPE,
            24,
            MsProperty::empty(),
            "Derived".to_string(),
            String::new(),
        );
        assert_eq!(
            c.class_data.composite.derived_from_list_record_number,
            RecordNumber::type_record(0x2001)
        );
    }

    #[test]
    fn test_class_with_vshape() {
        let c = LfClass::new(
            3,
            RecordNumber::type_record(0x1001),
            RecordNumber::type_record(0x2001),
            RecordNumber::type_record(0x3001),
            24,
            MsProperty::empty(),
            "VTable".to_string(),
            String::new(),
        );
        assert_eq!(
            c.class_data.composite.vshape_table_record_number,
            RecordNumber::type_record(0x3001)
        );
    }

    #[test]
    fn test_class_empty_name() {
        let c = LfClass::new(
            0,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            0,
            MsProperty::empty(),
            String::new(),
            String::new(),
        );
        assert!(c.name().is_empty());
    }

    #[test]
    fn test_class_scoped() {
        let c = LfClass::new(
            2,
            RecordNumber::type_record(0x1001),
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            16,
            MsProperty::SCOPED,
            "ScopedClass".to_string(),
            String::new(),
        );
        assert!(c.class_data.composite.property.contains(MsProperty::SCOPED));
    }

    #[test]
    fn test_class_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&5u16.to_le_bytes());       // count
        data.extend_from_slice(&0u16.to_le_bytes());       // property
        data.extend_from_slice(&0x1001u32.to_le_bytes());  // fieldList
        data.extend_from_slice(&0u32.to_le_bytes());       // derivedFrom
        data.extend_from_slice(&0u32.to_le_bytes());       // vshape
        data.extend_from_slice(&32u16.to_le_bytes());      // size
        data.extend_from_slice(b"Cls\0");

        let c = LfClass::parse(&data).unwrap();
        assert_eq!(c.name(), "Cls");
        assert_eq!(c.get_count(), 5);
        assert_eq!(c.get_size(), 32);
        assert_eq!(c.pdb_id(), 0x1504);
    }

    #[test]
    fn test_class_parse_with_mangled() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0x2000u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&16u16.to_le_bytes());
        data.extend_from_slice(b"MyClass\0");
        data.extend_from_slice(b".?AVMyClass@@\0");

        let c = LfClass::parse(&data).unwrap();
        assert_eq!(c.name(), "MyClass");
        assert_eq!(c.mangled_name(), ".?AVMyClass@@");
    }

    #[test]
    fn test_class_parse_too_short() {
        let data = [0u8; 10];
        assert!(LfClass::parse(&data).is_err());
    }

    #[test]
    fn test_class_is_scoped() {
        let mut c = make_test_class();
        assert!(!c.is_scoped());
        c.class_data.composite.property |= MsProperty::SCOPED;
        assert!(c.is_scoped());
    }

    #[test]
    fn test_class_has_unique_name() {
        let mut c = make_test_class();
        assert!(!c.has_unique_name());
        c.class_data.composite.property |= MsProperty::HAS_UNIQUE_NAME;
        assert!(c.has_unique_name());
    }

    #[test]
    fn test_class_is_sealed() {
        let mut c = make_test_class();
        assert!(!c.is_sealed());
        c.class_data.composite.property |= MsProperty::SEALED;
        assert!(c.is_sealed());
    }

    #[test]
    fn test_class_is_packed() {
        let mut c = make_test_class();
        assert!(!c.is_packed());
        c.class_data.composite.property |= MsProperty::PACKED;
        assert!(c.is_packed());
    }

    #[test]
    fn test_class_has_overloaded_ops() {
        let mut c = make_test_class();
        assert!(!c.has_overloaded_ops());
        c.class_data.composite.property |= MsProperty::OVERLOADED_OPS;
        assert!(c.has_overloaded_ops());
    }

    #[test]
    fn test_class_has_casting_ops() {
        let mut c = make_test_class();
        assert!(!c.has_casting_ops());
        c.class_data.composite.property |= MsProperty::CASTING_OPS;
        assert!(c.has_casting_ops());
    }

    #[test]
    fn test_class_has_ctor_dtor() {
        let c = make_test_class();
        assert!(c.has_ctor_dtor()); // CTOR was set in make_test_class
    }

    #[test]
    fn test_class_hfa() {
        let c = make_test_class();
        assert_eq!(c.hfa(), Hfa::NONE);
    }

    #[test]
    fn test_class_mocom() {
        let c = make_test_class();
        assert_eq!(c.mocom(), Mocom::NONE);
    }

    #[test]
    fn test_class_property_accessor() {
        let c = make_test_class();
        assert!(c.property().contains(MsProperty::NESTED));
        assert!(c.property().contains(MsProperty::CTOR));
    }

    #[test]
    fn test_class_get_count() {
        let c = make_test_class();
        assert_eq!(c.get_count(), 5);
    }

    #[test]
    fn test_class_get_size() {
        let c = make_test_class();
        assert_eq!(c.get_size(), 32);
    }

    #[test]
    fn test_class_get_record_numbers() {
        let c = make_test_class();
        assert_eq!(c.get_field_list_record_number().index(), 0x1001);
        assert_eq!(c.get_derived_from_record_number().index(), 0x0000);
        assert_eq!(c.get_vshape_record_number().index(), 0x1003);
    }

    #[test]
    fn test_class_contains_nested() {
        let mut c = make_test_class();
        assert!(!c.contains_nested());
        c.class_data.composite.property |= MsProperty::CONTAINS_NESTED;
        assert!(c.contains_nested());
    }

    #[test]
    fn test_class_mangled_name_accessor() {
        let c = make_test_class();
        assert!(c.mangled_name().is_empty());
    }
}
