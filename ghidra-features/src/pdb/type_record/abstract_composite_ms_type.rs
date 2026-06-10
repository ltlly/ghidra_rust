//! Abstract Composite MS Type -- base for struct/class/union type records.
//!
//! Ports Ghidra's `AbstractCompositeMsType` Java class.
//!
//! This is the shared base for `AbstractClassMsType`, `AbstractStructureMsType`,
//! and `AbstractUnionMsType`. It captures the fields common to all composite
//! types: count, field list, derived-from list, vshape table, size, name,
//! mangled name, and property flags.

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::ms_property::MsProperty;
use super::RecordNumber;

/// Abstract base for composite (struct/class/union) PDB type records.
///
/// Extends the concept of `AbstractComplexMsType` from the Java hierarchy
/// with the additional composite-specific fields: `derived_from_list`,
/// `vshape_table`, and `size`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstractCompositeMsType {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Number of field elements (-1 if not applicable).
    pub count: i32,
    /// Record number of the field descriptor list.
    pub field_list_record_number: RecordNumber,
    /// Record number of the derived-from list. Zero if none.
    /// Not used by union types.
    pub derived_from_list_record_number: RecordNumber,
    /// Record number of the VShape table.
    /// Not used by union types.
    pub vshape_table_record_number: RecordNumber,
    /// Size of this composite in bytes.
    pub size: u64,
    /// Property flags for this composite.
    pub property: MsProperty,
    /// The human-readable name of this composite.
    pub name: String,
    /// The mangled name (may be empty).
    pub mangled_name: String,
    /// The type string (e.g., "class", "struct", "union").  Set by subclasses.
    type_string: &'static str,
}

impl AbstractCompositeMsType {
    /// Create a new composite type record.
    pub fn new(
        count: i32,
        field_list_record_number: RecordNumber,
        derived_from_list_record_number: RecordNumber,
        vshape_table_record_number: RecordNumber,
        size: u64,
        property: MsProperty,
        name: String,
        mangled_name: String,
        type_string: &'static str,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            count,
            field_list_record_number,
            derived_from_list_record_number,
            vshape_table_record_number,
            size,
            property,
            name,
            mangled_name,
            type_string,
        }
    }

    /// Get the type string for this composite ("class", "struct", or "union").
    pub fn type_string(&self) -> &'static str {
        self.type_string
    }

    /// Get the number of field elements.
    pub fn num_elements(&self) -> i32 {
        self.count
    }

    /// Get the field descriptor list record number.
    pub fn field_descriptor_list_record_number(&self) -> RecordNumber {
        self.field_list_record_number
    }

    /// Get the derived-from list record number.
    pub fn derived_from_list_record_number(&self) -> RecordNumber {
        self.derived_from_list_record_number
    }

    /// Get the VShape table record number.
    pub fn vshape_table_record_number(&self) -> RecordNumber {
        self.vshape_table_record_number
    }

    /// Get the size of this composite.
    pub fn get_size(&self) -> u64 {
        self.size
    }

    /// Get the mangled name, if any.
    pub fn mangled_name(&self) -> &str {
        &self.mangled_name
    }

    /// Whether this is a forward reference.
    pub fn is_forward_ref(&self) -> bool {
        self.property.contains(MsProperty::FORWARD_REF)
    }

    /// Whether this composite is nested inside another type.
    pub fn is_nested(&self) -> bool {
        self.property.contains(MsProperty::NESTED)
    }

    /// Whether this composite contains nested types.
    pub fn contains_nested(&self) -> bool {
        self.property.contains(MsProperty::CONTAINS_NESTED)
    }
}

impl AbstractMsType for AbstractCompositeMsType {
    fn name(&self) -> &str {
        &self.name
    }

    fn pdb_id(&self) -> u32 {
        // Returns the base composite pdb_id; subclasses override.
        0x0004 // LF_CLASS as default
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        let mut result = String::new();

        // Type string + space + name.
        result.push_str(self.type_string);
        result.push(' ');
        result.push_str(&self.name);

        // Angle-bracket metadata: <count,property>.
        result.push('<');
        if self.count != -1 {
            result.push_str(&self.count.to_string());
            result.push(',');
        }
        result.push_str(&format!("{}", self.property));
        result.push('>');

        // Field list reference.
        // In the full implementation, if the field list type is a NoType
        // primitive, we emit "{}" instead.
        if self.field_list_record_number.is_no_type() {
            result.push_str("{}");
        } else {
            result.push_str(&self.field_list_record_number.to_string());
        }

        result.push(' ');
        result
    }
}

impl fmt::Display for AbstractCompositeMsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_composite() -> AbstractCompositeMsType {
        AbstractCompositeMsType::new(
            3,
            RecordNumber::type_record(0x1001),
            RecordNumber::type_record(0x1002),
            RecordNumber::type_record(0x1003),
            16,
            MsProperty::NESTED,
            "MyStruct".to_string(),
            String::new(),
            "struct",
        )
    }

    #[test]
    fn test_composite_basic() {
        let c = make_test_composite();
        assert_eq!(c.name(), "MyStruct");
        assert_eq!(c.type_string(), "struct");
        assert_eq!(c.num_elements(), 3);
        assert_eq!(c.get_size(), 16);
        assert!(c.is_nested());
        assert!(!c.is_forward_ref());
    }

    #[test]
    fn test_composite_record_number() {
        let mut c = make_test_composite();
        assert!(c.record_number().is_no_type());
        c.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(c.record_number().index(), 0x2000);
    }

    #[test]
    fn test_composite_emit() {
        let c = make_test_composite();
        let emitted = c.emit(Bind::NONE);
        assert!(emitted.starts_with("struct MyStruct<"));
        assert!(emitted.contains("3,"));
        assert!(emitted.contains("isnested"));
        assert!(emitted.contains("0x1001"));
    }

    #[test]
    fn test_composite_emit_no_field_list() {
        let c = AbstractCompositeMsType::new(
            -1,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            0,
            MsProperty::FORWARD_REF,
            "FwdRef".to_string(),
            String::new(),
            "class",
        );
        let emitted = c.emit(Bind::NONE);
        assert!(emitted.contains("{}"));
        assert!(emitted.contains("fwdref"));
    }

    #[test]
    fn test_composite_display() {
        let c = make_test_composite();
        let display = format!("{}", c);
        assert!(display.contains("struct"));
        assert!(display.contains("MyStruct"));
    }

    #[test]
    fn test_composite_forward_ref() {
        let c = AbstractCompositeMsType::new(
            0,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            0,
            MsProperty::FORWARD_REF,
            "Fwd".to_string(),
            String::new(),
            "struct",
        );
        assert!(c.is_forward_ref());
        assert!(!c.is_nested());
    }

    #[test]
    fn test_composite_mangled_name() {
        let mut c = make_test_composite();
        assert!(c.mangled_name().is_empty());
        c.mangled_name = ".?AVMyStruct@@".to_string();
        assert_eq!(c.mangled_name(), ".?AVMyStruct@@");
    }
}
