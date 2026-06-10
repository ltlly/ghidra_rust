//! LF_ENUM -- concrete Enum type record.
//!
//! Ports Ghidra's `EnumMsType` (PDB_ID = 0x1507) Java class.
//!
//! Represents a C/C++ enumeration type in the PDB type stream. Wraps
//! [`AbstractEnumMsType`] and provides the PDB ID for the MsType
//! variant (32-bit type indices, NT-format strings).
//!
//! # Binary Layout (LF_ENUM / 0x1507)
//!
//! ```text
//! +0  u16   count            Number of enumerators
//! +2  MsProperty property    Property flags
//! +4  u32   underlyingType   Type index of the underlying integral type
//! +8  u32   fieldList        Type index of the LF_FIELDLIST
//! +12 StringNt name          Null-terminated name
//!     StringNt mangledName   Null-terminated mangled name (optional)
//! ```

use std::fmt;

use super::abstract_enum_ms_type::AbstractEnumMsType;
use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::ms_property::MsProperty;
use super::RecordNumber;

/// Concrete PDB enum type record (`LF_ENUM`).
///
/// This is the Rust equivalent of Ghidra's `EnumMsType`. It delegates all
/// enum fields and behaviour to the embedded [`AbstractEnumMsType`],
/// overriding only the PDB ID to `0x1507` for the MsType variant.
#[derive(Debug, Clone)]
pub struct LfEnum {
    /// The underlying enum data (count, field list, underlying type, name, etc.).
    pub enum_data: AbstractEnumMsType,
}

impl LfEnum {
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
            enum_data: AbstractEnumMsType::new(
                count,
                field_list_record_number,
                property,
                name,
                mangled_name,
                underlying_type_record_number,
            ),
        }
    }

    /// Create from raw parsed field values.
    pub fn from_parsed(
        count: u16,
        property: MsProperty,
        underlying_type_index: u32,
        field_list_type_index: u32,
        name: String,
        mangled_name: Option<String>,
    ) -> Self {
        Self {
            enum_data: AbstractEnumMsType::from_parsed(
                count,
                property,
                underlying_type_index,
                field_list_type_index,
                name,
                mangled_name,
            ),
        }
    }
}

impl AbstractMsType for LfEnum {
    fn name(&self) -> &str {
        self.enum_data.name()
    }

    fn pdb_id(&self) -> u32 {
        0x1507 // LF_ENUM (MsType variant)
    }

    fn record_number(&self) -> RecordNumber {
        self.enum_data.record_number()
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.enum_data.set_record_number(record_number);
    }

    fn emit(&self, bind: Bind) -> String {
        self.enum_data.emit(bind)
    }
}

impl fmt::Display for LfEnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_enum() -> LfEnum {
        LfEnum::new(
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
        assert_eq!(e.pdb_id(), 0x1507);
        assert_eq!(e.enum_data.num_elements(), 4);
        assert_eq!(
            e.enum_data.underlying_type_record_number,
            RecordNumber::type_record(0x0074)
        );
    }

    #[test]
    fn test_enum_from_parsed() {
        let e = LfEnum::from_parsed(
            3,
            MsProperty::NESTED,
            0x0075,
            0x1002,
            "Status".to_string(),
            Some(".AW4Status@@".to_string()),
        );

        assert_eq!(e.name(), "Status");
        assert_eq!(e.enum_data.mangled_name(), ".AW4Status@@");
        assert_eq!(
            e.enum_data.underlying_type_record_number,
            RecordNumber::type_record(0x0075)
        );
        assert!(e.enum_data.property.contains(MsProperty::NESTED));
    }

    #[test]
    fn test_enum_from_parsed_no_mangled() {
        let e = LfEnum::from_parsed(
            2,
            MsProperty::empty(),
            0x0074,
            0x1001,
            "Simple".to_string(),
            None,
        );
        assert!(e.enum_data.mangled_name().is_empty());
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
    fn test_enum_forward_ref() {
        let e = LfEnum::new(
            -1,
            RecordNumber::NO_TYPE,
            MsProperty::FORWARD_REF,
            "FwdEnum".to_string(),
            String::new(),
            RecordNumber::type_record(0x0074),
        );
        assert!(e.enum_data.is_forward_ref());
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
        let e = LfEnum::new(
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
