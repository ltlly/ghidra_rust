//! Abstract Enum MS Type -- enumeration type record.
//!
//! Ports Ghidra's `AbstractEnumMsType` Java class.
//!
//! Represents PDB enum types (`LF_ENUM`).  Inherits the "complex" type
//! fields (count, field list, property, name, mangled name) and adds an
//! `underlying_type_record_number` for the underlying integral type.

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::ms_property::MsProperty;
use super::RecordNumber;

/// Abstract base for PDB enum type records.
///
/// In the Java hierarchy this extends `AbstractComplexMsType` directly,
/// adding the `underlyingRecordNumber` field.  We flatten the hierarchy
/// here since Rust traits do not carry data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstractEnumMsType {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Number of enumerators (-1 if not applicable).
    pub count: i32,
    /// Record number of the field descriptor list (holds enumerate records).
    pub field_list_record_number: RecordNumber,
    /// Property flags for this enum.
    pub property: MsProperty,
    /// The human-readable name of the enum.
    pub name: String,
    /// The mangled name (may be empty).
    pub mangled_name: String,
    /// Record number of the underlying integral type (e.g., int, unsigned int).
    pub underlying_type_record_number: RecordNumber,
}

impl AbstractEnumMsType {
    /// Create a new enum type record.
    pub fn new(
        count: i32,
        field_list_record_number: RecordNumber,
        property: MsProperty,
        name: String,
        mangled_name: String,
        underlying_type_record_number: RecordNumber,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            count,
            field_list_record_number,
            property,
            name,
            mangled_name,
            underlying_type_record_number,
        }
    }

    /// Create from a parsed `EnumType` record.
    pub fn from_parsed(
        count: u16,
        property: MsProperty,
        underlying_type_index: u32,
        field_list_type_index: u32,
        name: String,
        mangled_name: Option<String>,
    ) -> Self {
        Self::new(
            count as i32,
            RecordNumber::type_record(field_list_type_index),
            property,
            name,
            mangled_name.unwrap_or_default(),
            RecordNumber::type_record(underlying_type_index),
        )
    }

    /// Get the number of enumerators.
    pub fn num_elements(&self) -> i32 {
        self.count
    }

    /// Get the field descriptor list record number.
    pub fn field_descriptor_list_record_number(&self) -> RecordNumber {
        self.field_list_record_number
    }

    /// Get the mangled name, if any.
    pub fn mangled_name(&self) -> &str {
        &self.mangled_name
    }

    /// Whether this is a forward reference.
    pub fn is_forward_ref(&self) -> bool {
        self.property.contains(MsProperty::FORWARD_REF)
    }
}

impl AbstractMsType for AbstractEnumMsType {
    fn name(&self) -> &str {
        &self.name
    }

    fn pdb_id(&self) -> u32 {
        0x0007 // LF_ENUM
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        let mut result = String::new();

        // Type string + name.
        result.push_str("enum ");
        result.push_str(&self.name);

        // Angle-bracket metadata: <count,underlyingType,property>.
        result.push('<');
        if self.count != -1 {
            result.push_str(&self.count.to_string());
            result.push(',');
        }
        result.push_str(&self.underlying_type_record_number.to_string());
        result.push(',');
        result.push_str(&format!("{}", self.property));
        result.push('>');

        // Field list reference.
        if !self.field_list_record_number.is_no_type() {
            result.push_str(&self.field_list_record_number.to_string());
        }

        result.push(' ');
        result
    }
}

impl fmt::Display for AbstractEnumMsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_enum() -> AbstractEnumMsType {
        AbstractEnumMsType::new(
            4,
            RecordNumber::type_record(0x1001),
            MsProperty::empty(),
            "Color".to_string(),
            String::new(),
            RecordNumber::type_record(0x0074), // int
        )
    }

    #[test]
    fn test_enum_basic() {
        let e = make_test_enum();
        assert_eq!(e.name(), "Color");
        assert_eq!(e.pdb_id(), 0x0007);
        assert_eq!(e.num_elements(), 4);
        assert_eq!(e.underlying_type_record_number, RecordNumber::type_record(0x0074));
    }

    #[test]
    fn test_enum_from_parsed() {
        let e = AbstractEnumMsType::from_parsed(
            3,
            MsProperty::NESTED,
            0x0075,
            0x1002,
            "Status".to_string(),
            Some(".AW4Status@@".to_string()),
        );

        assert_eq!(e.name(), "Status");
        assert_eq!(e.mangled_name(), ".AW4Status@@");
        assert_eq!(e.underlying_type_record_number, RecordNumber::type_record(0x0075));
        assert!(e.property.contains(MsProperty::NESTED));
    }

    #[test]
    fn test_enum_emit() {
        let e = make_test_enum();
        let emitted = e.emit(Bind::NONE);
        assert!(emitted.starts_with("enum Color<"));
        assert!(emitted.contains("4,"));
        assert!(emitted.contains("0x0074"));
        assert!(emitted.contains("none")); // empty property
        assert!(emitted.contains("0x1001")); // field list
    }

    #[test]
    fn test_enum_emit_no_field_list() {
        let e = AbstractEnumMsType::new(
            -1,
            RecordNumber::NO_TYPE,
            MsProperty::FORWARD_REF,
            "FwdEnum".to_string(),
            String::new(),
            RecordNumber::type_record(0x0074),
        );
        let emitted = e.emit(Bind::NONE);
        assert!(emitted.starts_with("enum FwdEnum<"));
        assert!(!emitted.contains("0x1001"));
        assert!(e.is_forward_ref());
    }

    #[test]
    fn test_enum_record_number() {
        let mut e = make_test_enum();
        assert!(e.record_number().is_no_type());
        e.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(e.record_number().index(), 0x2000);
    }

    #[test]
    fn test_enum_display() {
        let e = make_test_enum();
        let display = format!("{}", e);
        assert!(display.contains("enum"));
        assert!(display.contains("Color"));
    }

    #[test]
    fn test_enum_nested() {
        let e = AbstractEnumMsType::new(
            2,
            RecordNumber::type_record(0x1001),
            MsProperty::NESTED,
            "Inner".to_string(),
            String::new(),
            RecordNumber::type_record(0x0074),
        );
        let emitted = e.emit(Bind::NONE);
        assert!(emitted.contains("isnested"));
    }
}
