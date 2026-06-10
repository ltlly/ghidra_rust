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
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Parse an `LF_ENUM` record from raw bytes (payload after leaf ID).
    ///
    /// Mirrors the Java `EnumMsType(AbstractPdb, PdbByteReader)` constructor.
    /// The `data` slice should start at the `count` field.
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u16   count
    /// +2  u16   property
    /// +4  u32   underlyingType type index
    /// +8  u32   fieldList type index
    /// +12 StringNt name
    ///     StringNt mangledName (optional)
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 12 {
            return Err(format!(
                "LF_ENUM payload too short: need >= 12 bytes, got {}",
                data.len()
            ));
        }
        let count = u16::from_le_bytes([data[0], data[1]]);
        let property = MsProperty::from_u16(u16::from_le_bytes([data[2], data[3]]));
        let underlying_ti = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let field_list_ti = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

        let (name, mangled_name) = if 12 < data.len() {
            let (n, after_n) = crate::pdb::pdb_byte_reader::read_null_terminated_string(data, 12);
            let mn = if after_n < data.len() && data[after_n] != 0 {
                crate::pdb::pdb_byte_reader::parse_null_terminated_string(&data[after_n..])
            } else {
                String::new()
            };
            (n, if mn.is_empty() { None } else { Some(mn) })
        } else {
            (String::new(), None)
        };

        Ok(Self::from_parsed(count, property, underlying_ti, field_list_ti, name, mangled_name))
    }

    // =========================================================================
    // Property-based accessors
    // =========================================================================

    /// Whether this enum is a forward reference.
    pub fn is_forward_ref(&self) -> bool {
        self.enum_data.is_forward_ref()
    }

    /// Whether this enum is scoped (C++11 `enum class`).
    pub fn is_scoped(&self) -> bool {
        self.enum_data.property.contains(MsProperty::SCOPED)
    }

    /// Whether this enum has a unique name.
    pub fn has_unique_name(&self) -> bool {
        self.enum_data.property.contains(MsProperty::HAS_UNIQUE_NAME)
    }

    /// Whether this enum is nested inside another type.
    pub fn is_nested(&self) -> bool {
        self.enum_data.property.contains(MsProperty::NESTED)
    }

    /// Get the underlying type record number.
    pub fn get_underlying_type_record_number(&self) -> RecordNumber {
        self.enum_data.underlying_type_record_number
    }

    /// Get the field list record number.
    pub fn get_field_list_record_number(&self) -> RecordNumber {
        self.enum_data.field_list_record_number
    }

    /// Get the number of enumerators.
    pub fn get_count(&self) -> i32 {
        self.enum_data.num_elements()
    }

    /// Get the property flags.
    pub fn property(&self) -> MsProperty {
        self.enum_data.property
    }

    /// Get the mangled name, if any.
    pub fn mangled_name(&self) -> &str {
        self.enum_data.mangled_name()
    }

    /// Get the type string for this type ("enum").
    ///
    /// Mirrors Java `AbstractComplexMsType.getTypeString()`.
    pub fn type_name(&self) -> &'static str {
        "enum"
    }

    /// Get the number of enumerators in this enum.
    ///
    /// This is an alias for `get_count()` that provides a more
    /// semantically specific name for enum types.
    pub fn get_num_enumerators(&self) -> i32 {
        self.enum_data.num_elements()
    }

    /// Whether this enum has an underlying type assigned.
    ///
    /// Returns `true` if `underlying_type_record_number` is not `NO_TYPE`.
    pub fn has_underlying_type(&self) -> bool {
        !self.enum_data.underlying_type_record_number.is_no_type()
    }

    /// Whether this enum has a field list assigned.
    ///
    /// Returns `true` if `field_list_record_number` is not `NO_TYPE`.
    pub fn has_field_list(&self) -> bool {
        !self.enum_data.field_list_record_number.is_no_type()
    }

    /// Whether this enum is a forward reference.
    ///
    /// Forward references are placeholders for types whose full definition
    /// appears elsewhere in the type stream. This is an alias for
    /// [`is_forward_ref`](Self::is_forward_ref).
    pub fn is_forward_ref_check(&self) -> bool {
        self.enum_data.is_forward_ref()
    }

    /// Whether the property flags are empty (no special properties).
    pub fn has_no_properties(&self) -> bool {
        self.enum_data.property.is_empty()
    }

    /// Get the number of enumerators that are known (not -1/unknown).
    ///
    /// Returns `Some(count)` if the count is >= 0, `None` if the count
    /// is -1 (meaning the enumerator count is unknown, e.g. for a forward ref).
    pub fn known_enumerator_count(&self) -> Option<u32> {
        if self.enum_data.count >= 0 {
            Some(self.enum_data.count as u32)
        } else {
            None
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

    #[test]
    fn test_enum_parse() {
        // LF_ENUM payload: count=4, property=0, underlyingType=0x0074,
        // fieldList=0x1001, name="Color"
        let mut data = Vec::new();
        data.extend_from_slice(&4u16.to_le_bytes());       // count
        data.extend_from_slice(&0u16.to_le_bytes());       // property
        data.extend_from_slice(&0x0074u32.to_le_bytes());  // underlyingType
        data.extend_from_slice(&0x1001u32.to_le_bytes());  // fieldList
        data.extend_from_slice(b"Color\0");

        let e = LfEnum::parse(&data).unwrap();
        assert_eq!(e.name(), "Color");
        assert_eq!(e.get_count(), 4);
        assert_eq!(e.get_underlying_type_record_number().index(), 0x0074);
        assert_eq!(e.get_field_list_record_number().index(), 0x1001);
        assert_eq!(e.pdb_id(), 0x1507);
    }

    #[test]
    fn test_enum_parse_with_mangled() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0x0075u32.to_le_bytes());
        data.extend_from_slice(&0x1002u32.to_le_bytes());
        data.extend_from_slice(b"Status\0");
        data.extend_from_slice(b".AW4Status@@\0");

        let e = LfEnum::parse(&data).unwrap();
        assert_eq!(e.name(), "Status");
        assert_eq!(e.mangled_name(), ".AW4Status@@");
    }

    #[test]
    fn test_enum_parse_too_short() {
        let data = [0u8; 8];
        assert!(LfEnum::parse(&data).is_err());
    }

    #[test]
    fn test_enum_is_scoped() {
        let mut e = make_test_enum();
        assert!(!e.is_scoped());
        e.enum_data.property |= MsProperty::SCOPED;
        assert!(e.is_scoped());
    }

    #[test]
    fn test_enum_has_unique_name() {
        let mut e = make_test_enum();
        assert!(!e.has_unique_name());
        e.enum_data.property |= MsProperty::HAS_UNIQUE_NAME;
        assert!(e.has_unique_name());
    }

    #[test]
    fn test_enum_is_nested_accessor() {
        let mut e = make_test_enum();
        assert!(!e.is_nested());
        e.enum_data.property |= MsProperty::NESTED;
        assert!(e.is_nested());
    }

    #[test]
    fn test_enum_get_underlying_type() {
        let e = make_test_enum();
        assert_eq!(
            e.get_underlying_type_record_number(),
            RecordNumber::type_record(0x0074)
        );
    }

    #[test]
    fn test_enum_get_field_list() {
        let e = make_test_enum();
        assert_eq!(
            e.get_field_list_record_number(),
            RecordNumber::type_record(0x1001)
        );
    }

    #[test]
    fn test_enum_get_count() {
        let e = make_test_enum();
        assert_eq!(e.get_count(), 4);
    }

    #[test]
    fn test_enum_property_accessor() {
        let e = make_test_enum();
        assert_eq!(e.property(), MsProperty::empty());
    }

    #[test]
    fn test_enum_mangled_name_accessor() {
        let e = make_test_enum();
        assert!(e.mangled_name().is_empty());
    }

    #[test]
    fn test_enum_type_name() {
        let e = make_test_enum();
        assert_eq!(e.type_name(), "enum");
    }

    #[test]
    fn test_enum_get_num_enumerators() {
        let e = make_test_enum();
        assert_eq!(e.get_num_enumerators(), 4);
    }

    #[test]
    fn test_enum_has_underlying_type() {
        let e = make_test_enum();
        assert!(e.has_underlying_type());

        let e2 = LfEnum::new(
            2,
            RecordNumber::type_record(0x1001),
            MsProperty::empty(),
            "NoUnderlying".to_string(),
            String::new(),
            RecordNumber::NO_TYPE,
        );
        assert!(!e2.has_underlying_type());
    }

    #[test]
    fn test_enum_has_field_list() {
        let e = make_test_enum();
        assert!(e.has_field_list());

        let e2 = LfEnum::new(
            -1,
            RecordNumber::NO_TYPE,
            MsProperty::FORWARD_REF,
            "FwdEnum".to_string(),
            String::new(),
            RecordNumber::type_record(0x0074),
        );
        assert!(!e2.has_field_list());
    }

    #[test]
    fn test_enum_is_forward_ref_check() {
        let e = make_test_enum();
        assert!(!e.is_forward_ref_check());

        let e2 = LfEnum::new(
            -1,
            RecordNumber::NO_TYPE,
            MsProperty::FORWARD_REF,
            "FwdEnum".to_string(),
            String::new(),
            RecordNumber::type_record(0x0074),
        );
        assert!(e2.is_forward_ref_check());
    }

    #[test]
    fn test_enum_has_no_properties() {
        let e = make_test_enum();
        assert!(e.has_no_properties());

        let mut e2 = make_test_enum();
        e2.enum_data.property |= MsProperty::NESTED;
        assert!(!e2.has_no_properties());
    }

    #[test]
    fn test_enum_known_enumerator_count() {
        let e = make_test_enum();
        assert_eq!(e.known_enumerator_count(), Some(4));

        let e2 = LfEnum::new(
            -1,
            RecordNumber::NO_TYPE,
            MsProperty::FORWARD_REF,
            "FwdEnum".to_string(),
            String::new(),
            RecordNumber::type_record(0x0074),
        );
        assert_eq!(e2.known_enumerator_count(), None);
    }

    #[test]
    fn test_enum_eq() {
        let e1 = make_test_enum();
        let e2 = make_test_enum();
        assert_eq!(e1, e2);

        let e3 = LfEnum::new(
            4,
            RecordNumber::type_record(0x1001),
            MsProperty::empty(),
            "Different".to_string(),
            String::new(),
            RecordNumber::type_record(0x0074),
        );
        assert_ne!(e1, e3);
    }

    #[test]
    fn test_enum_scoped_enum_class() {
        // C++11 enum class
        let e = LfEnum::new(
            3,
            RecordNumber::type_record(0x1001),
            MsProperty::SCOPED | MsProperty::NESTED,
            "Color".to_string(),
            String::new(),
            RecordNumber::type_record(0x0074),
        );
        assert!(e.is_scoped());
        assert!(e.is_nested());
        assert_eq!(e.get_num_enumerators(), 3);
    }

    #[test]
    fn test_enum_with_unique_name() {
        let e = LfEnum::new(
            2,
            RecordNumber::type_record(0x1001),
            MsProperty::HAS_UNIQUE_NAME,
            "MyEnum".to_string(),
            ".AW4MyEnum@@".to_string(),
            RecordNumber::type_record(0x0074),
        );
        assert!(e.has_unique_name());
        assert_eq!(e.mangled_name(), ".AW4MyEnum@@");
    }

    #[test]
    fn test_enum_zero_enumerators() {
        let e = LfEnum::new(
            0,
            RecordNumber::type_record(0x1001),
            MsProperty::empty(),
            "EmptyEnum".to_string(),
            String::new(),
            RecordNumber::type_record(0x0074),
        );
        assert_eq!(e.get_count(), 0);
        assert_eq!(e.get_num_enumerators(), 0);
        assert_eq!(e.known_enumerator_count(), Some(0));
    }
}
