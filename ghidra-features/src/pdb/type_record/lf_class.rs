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
use super::ms_property::MsProperty;
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
}
