//! Abstract Class MS Type -- C++ class type record.
//!
//! Ports Ghidra's `AbstractClassMsType` Java class.
//!
//! Represents C++ class types (`LF_CLASS`).  Inherits all composite
//! behavior from [`AbstractCompositeMsType`] and sets the type string
//! to `"class"`.

use std::fmt;

use super::abstract_composite_ms_type::AbstractCompositeMsType;
use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::ms_property::MsProperty;
use super::RecordNumber;

/// A PDB class type record.
///
/// In the Java hierarchy this is a direct subclass of `AbstractCompositeMsType`
/// that only overrides `getTypeString()` to return `"class"`.
#[derive(Debug, Clone)]
pub struct AbstractClassMsType {
    /// The underlying composite data.
    pub composite: AbstractCompositeMsType,
}

impl AbstractClassMsType {
    /// Create a new class type record.
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
                "class",
            ),
        }
    }

    /// Create from a parsed `ClassType` record.
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

impl AbstractMsType for AbstractClassMsType {
    fn name(&self) -> &str {
        self.composite.name()
    }

    fn pdb_id(&self) -> u32 {
        0x0004 // LF_CLASS
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

impl fmt::Display for AbstractClassMsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_class() -> AbstractClassMsType {
        AbstractClassMsType::new(
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
        assert_eq!(c.pdb_id(), 0x0004);
        assert_eq!(c.composite.type_string(), "class");
        assert_eq!(c.composite.get_size(), 32);
        assert_eq!(c.composite.num_elements(), 5);
    }

    #[test]
    fn test_class_from_parsed() {
        let c = AbstractClassMsType::from_parsed(
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
        assert_eq!(c.composite.mangled_name(), ".?AVSimpleClass@@");
        assert_eq!(c.composite.type_string(), "class");
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
        let c = AbstractClassMsType::new(
            0,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            0,
            MsProperty::FORWARD_REF,
            "FwdClass".to_string(),
            String::new(),
        );
        assert!(c.composite.is_forward_ref());
    }
}
