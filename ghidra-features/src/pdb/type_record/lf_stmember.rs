//! LF_STMEMBER -- concrete Static Member type record.
//!
//! Ports Ghidra's `StaticMemberMsType` (PDB_ID = 0x150E) Java class.
//!
//! Represents a static data member within a composite type
//! (struct/class/union) in the PDB type stream. This is a leaf record
//! that appears inside an `LF_FIELDLIST`.
//!
//! # Binary Layout (LF_STMEMBER / 0x150E)
//!
//! ```text
//! +0  u16   attributes       Member access and property flags
//! +2  u32   type             Type index of the member's data type
//! +6  StringNt name          Null-terminated member name
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::lf_member::MemberAttributes;
use super::RecordNumber;

/// Concrete PDB static member type record (`LF_STMEMBER`).
///
/// This is the Rust equivalent of Ghidra's `StaticMemberMsType`. It stores
/// a static data member's type, access protection, and name. Unlike
/// [`LfMember`], a static member has no byte offset within the containing
/// composite since static members are stored globally.
///
/// Corresponds to the Java `StaticMemberMsType` class and its parent
/// `AbstractStaticMemberMsType`.
#[derive(Debug, Clone)]
pub struct LfStmember {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the member's data type.
    pub type_record_number: RecordNumber,
    /// Member attributes (access, property flags).
    pub attributes: MemberAttributes,
    /// Member name.
    pub name: String,
}

impl LfStmember {
    /// Create a new static member type record.
    pub fn new(
        type_record_number: RecordNumber,
        attributes: MemberAttributes,
        name: String,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            type_record_number,
            attributes,
            name,
        }
    }

    /// Create from raw parsed field values.
    ///
    /// This is the typical constructor used after deserializing the binary
    /// PDB type record. The `attributes_raw` value is parsed into
    /// [`MemberAttributes`] following the same bit layout as LF_MEMBER.
    pub fn from_parsed(
        attributes_raw: u16,
        type_index: u32,
        name: String,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(type_index),
            MemberAttributes::from_u16(attributes_raw),
            name,
        )
    }

    /// Create a simple public static member.
    pub fn public_static_member(
        type_index: u32,
        name: String,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(type_index),
            MemberAttributes::public_member(),
            name,
        )
    }

    /// Get the record number of the member's data type.
    ///
    /// Mirrors Java `AbstractStaticMemberMsType.getFieldTypeRecordNumber()`.
    pub fn field_type_record_number(&self) -> RecordNumber {
        self.type_record_number
    }

    /// Get the member attributes.
    pub fn attribute(&self) -> &MemberAttributes {
        &self.attributes
    }

    /// Get the access protection level.
    pub fn access(&self) -> super::lf_member::AccessProtection {
        self.attributes.access
    }
}

impl AbstractMsType for LfStmember {
    fn name(&self) -> &str {
        &self.name
    }

    fn pdb_id(&self) -> u32 {
        0x150E // LF_STMEMBER
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        let mut result = String::new();

        // Emit attributes (access + property + modifiers).
        // Mirrors Java: builder.append(attribute); builder.append(": ");
        result.push_str(&self.attributes.emit_string());
        result.push_str(": ");

        // Emit the member name.
        result.push_str(&self.name);

        // Emit the type reference.
        result.push(' ');
        result.push_str(&self.type_record_number.to_string());

        result
    }
}

impl fmt::Display for LfStmember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_stmember() -> LfStmember {
        LfStmember::public_static_member(
            0x0074, // int
            "count".to_string(),
        )
    }

    #[test]
    fn test_stmember_basic() {
        let m = make_test_stmember();
        assert_eq!(m.name(), "count");
        assert_eq!(m.pdb_id(), 0x150E);
        assert_eq!(m.attributes.access, super::super::lf_member::AccessProtection::Public);
    }

    #[test]
    fn test_stmember_from_parsed() {
        let m = LfStmember::from_parsed(0x0003, 0x0074, "s_count".to_string());
        assert_eq!(m.name(), "s_count");
        assert_eq!(
            m.type_record_number,
            RecordNumber::type_record(0x0074)
        );
        assert_eq!(m.attributes.access, super::super::lf_member::AccessProtection::Public);
    }

    #[test]
    fn test_stmember_from_parsed_private() {
        let m = LfStmember::from_parsed(0x0001, 0x0074, "secret".to_string());
        assert_eq!(m.attributes.access, super::super::lf_member::AccessProtection::Private);
    }

    #[test]
    fn test_stmember_emit() {
        let m = make_test_stmember();
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.contains("0x0074"));
        assert!(emitted.contains("count"));
        assert!(emitted.contains("public"));
    }

    #[test]
    fn test_stmember_emit_contains_attributes() {
        let m = make_test_stmember();
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.starts_with("public: "));
    }

    #[test]
    fn test_stmember_record_number() {
        let mut m = make_test_stmember();
        assert!(m.record_number().is_no_type());
        m.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(m.record_number().index(), 0x2000);
    }

    #[test]
    fn test_stmember_display() {
        let m = make_test_stmember();
        let display = format!("{}", m);
        assert!(display.contains("count"));
        assert!(display.contains("0x0074"));
        assert!(display.contains("public"));
    }

    #[test]
    fn test_stmember_field_type_record_number() {
        let m = make_test_stmember();
        assert_eq!(
            m.field_type_record_number(),
            RecordNumber::type_record(0x0074)
        );
    }

    #[test]
    fn test_stmember_access() {
        let m = LfStmember::from_parsed(0x0001, 0x0074, "x".to_string());
        assert_eq!(m.access(), super::super::lf_member::AccessProtection::Private);
    }

    #[test]
    fn test_stmember_attribute() {
        let m = make_test_stmember();
        let attr = m.attribute();
        assert_eq!(attr.access, super::super::lf_member::AccessProtection::Public);
        assert_eq!(attr.property, super::super::lf_member::MemberProperty::Blank);
    }
}
