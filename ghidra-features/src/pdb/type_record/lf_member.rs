//! LF_MEMBER -- concrete Member type record.
//!
//! Ports Ghidra's `MemberMsType` (PDB_ID = 0x150D) Java class.
//!
//! Represents a non-static data member within a composite type
//! (struct/class/union) in the PDB type stream. This is a leaf record
//! that appears inside an `LF_FIELDLIST`.
//!
//! # Binary Layout (LF_MEMBER / 0x150D)
//!
//! ```text
//! +0  u16   attributes       Member access and property flags
//! +2  u32   type             Type index of the member's data type
//! +6  Numeric offset         Byte offset within the containing composite
//!     StringNt name          Null-terminated member name
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

/// Member access protection levels.
///
/// Parsed from bits 0-1 of the member attributes. Corresponds to the
/// Java `AccessProtection` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AccessProtection {
    /// No access specified.
    None = 0,
    /// Private access.
    Private = 1,
    /// Protected access.
    Protected = 2,
    /// Public access.
    Public = 3,
}

impl AccessProtection {
    /// Parse from a 2-bit value.
    pub fn from_value(val: u16) -> Self {
        match val & 0x03 {
            0 => Self::None,
            1 => Self::Private,
            2 => Self::Protected,
            3 => Self::Public,
            _ => Self::None,
        }
    }

    /// The label string for display.
    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Private => "private",
            Self::Protected => "protected",
            Self::Public => "public",
        }
    }
}

impl fmt::Display for AccessProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Member property flags.
///
/// Parsed from the member attributes word. These flags describe
/// characteristics of the member (e.g., whether it is a compiler-generated
/// pseudo-field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemberAttributes {
    /// Access protection level.
    pub access: AccessProtection,
    /// Whether this member is a compiler-generated pseudo-field (e.g., padding).
    pub is_pseudo: bool,
    /// Whether this member does not contribute to the class's size/layout.
    pub no_inherit: bool,
    /// Whether this member is not constructible.
    pub no_construct: bool,
}

impl MemberAttributes {
    /// Create from a raw 16-bit attributes value.
    pub fn from_u16(val: u16) -> Self {
        Self {
            access: AccessProtection::from_value(val),
            is_pseudo: (val & 0x04) != 0,
            no_inherit: (val & 0x08) != 0,
            no_construct: (val & 0x10) != 0,
        }
    }

    /// Create a simple public member attribute.
    pub fn public_member() -> Self {
        Self {
            access: AccessProtection::Public,
            is_pseudo: false,
            no_inherit: false,
            no_construct: false,
        }
    }
}

impl fmt::Display for MemberAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.access)
    }
}

/// Concrete PDB member type record (`LF_MEMBER`).
///
/// This is the Rust equivalent of Ghidra's `MemberMsType`. It stores a
/// non-static data member's type, byte offset, access protection, and name.
#[derive(Debug, Clone)]
pub struct LfMember {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the member's data type.
    pub type_record_number: RecordNumber,
    /// Byte offset of this member within the containing composite.
    pub offset: u32,
    /// Member attributes (access, pseudo, no-inherit, no-construct).
    pub attributes: MemberAttributes,
    /// Member name.
    pub name: String,
}

impl LfMember {
    /// Create a new member type record.
    pub fn new(
        type_record_number: RecordNumber,
        offset: u32,
        attributes: MemberAttributes,
        name: String,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            type_record_number,
            offset,
            attributes,
            name,
        }
    }

    /// Create from raw parsed field values.
    pub fn from_parsed(
        attributes_raw: u16,
        type_index: u32,
        offset: u32,
        name: String,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(type_index),
            offset,
            MemberAttributes::from_u16(attributes_raw),
            name,
        )
    }

    /// Create a simple public member.
    pub fn public_member(
        type_index: u32,
        offset: u32,
        name: String,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(type_index),
            offset,
            MemberAttributes::public_member(),
            name,
        )
    }
}

impl AbstractMsType for LfMember {
    fn name(&self) -> &str {
        &self.name
    }

    fn pdb_id(&self) -> u32 {
        0x150D // LF_MEMBER
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        let mut result = String::new();

        // Emit the type reference.
        result.push_str(&self.type_record_number.to_string());
        result.push(' ');

        // Emit the member name.
        result.push_str(&self.name);

        // Emit the offset.
        result.push_str(&format!(" @ {}", self.offset));

        // Emit access if not public.
        if self.attributes.access != AccessProtection::Public {
            result.push_str(&format!(" [{}]", self.attributes.access));
        }

        result.push(' ');
        result
    }
}

impl fmt::Display for LfMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_member() -> LfMember {
        LfMember::public_member(
            0x0074, // int
            0,      // offset 0
            "x".to_string(),
        )
    }

    #[test]
    fn test_access_protection_from_value() {
        assert_eq!(AccessProtection::from_value(0), AccessProtection::None);
        assert_eq!(AccessProtection::from_value(1), AccessProtection::Private);
        assert_eq!(AccessProtection::from_value(2), AccessProtection::Protected);
        assert_eq!(AccessProtection::from_value(3), AccessProtection::Public);
    }

    #[test]
    fn test_access_protection_display() {
        assert_eq!(format!("{}", AccessProtection::Public), "public");
        assert_eq!(format!("{}", AccessProtection::Private), "private");
        assert_eq!(format!("{}", AccessProtection::Protected), "protected");
    }

    #[test]
    fn test_member_attributes_public() {
        let attrs = MemberAttributes::from_u16(0x0003); // bits 0-1 = 3 = public
        assert_eq!(attrs.access, AccessProtection::Public);
        assert!(!attrs.is_pseudo);
        assert!(!attrs.no_inherit);
        assert!(!attrs.no_construct);
    }

    #[test]
    fn test_member_attributes_pseudo() {
        let attrs = MemberAttributes::from_u16(0x0007); // public + pseudo (bit 2)
        assert_eq!(attrs.access, AccessProtection::Public);
        assert!(attrs.is_pseudo);
    }

    #[test]
    fn test_member_attributes_no_inherit() {
        let attrs = MemberAttributes::from_u16(0x000B); // public + no-inherit (bit 3)
        assert_eq!(attrs.access, AccessProtection::Public);
        assert!(attrs.no_inherit);
    }

    #[test]
    fn test_member_attributes_no_construct() {
        let attrs = MemberAttributes::from_u16(0x0013); // public + no-construct (bit 4)
        assert_eq!(attrs.access, AccessProtection::Public);
        assert!(attrs.no_construct);
    }

    #[test]
    fn test_member_basic() {
        let m = make_test_member();
        assert_eq!(m.name(), "x");
        assert_eq!(m.pdb_id(), 0x150D);
        assert_eq!(m.offset, 0);
        assert_eq!(m.attributes.access, AccessProtection::Public);
    }

    #[test]
    fn test_member_from_parsed() {
        let m = LfMember::from_parsed(0x0003, 0x0074, 4, "y".to_string());
        assert_eq!(m.name(), "y");
        assert_eq!(m.offset, 4);
        assert_eq!(
            m.type_record_number,
            RecordNumber::type_record(0x0074)
        );
        assert_eq!(m.attributes.access, AccessProtection::Public);
    }

    #[test]
    fn test_member_from_parsed_private() {
        let m = LfMember::from_parsed(0x0001, 0x0074, 8, "secret".to_string());
        assert_eq!(m.attributes.access, AccessProtection::Private);
    }

    #[test]
    fn test_member_emit() {
        let m = make_test_member();
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.contains("0x0074"));
        assert!(emitted.contains("x"));
        assert!(emitted.contains("@ 0"));
    }

    #[test]
    fn test_member_emit_private() {
        let m = LfMember::from_parsed(0x0001, 0x0074, 8, "secret".to_string());
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.contains("[private]"));
    }

    #[test]
    fn test_member_emit_public_no_access_shown() {
        // Public members should not show access in emit.
        let m = make_test_member();
        let emitted = m.emit(Bind::NONE);
        assert!(!emitted.contains("[public]"));
    }

    #[test]
    fn test_member_record_number() {
        let mut m = make_test_member();
        assert!(m.record_number().is_no_type());
        m.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(m.record_number().index(), 0x2000);
    }

    #[test]
    fn test_member_display() {
        let m = make_test_member();
        let display = format!("{}", m);
        assert!(display.contains("x"));
        assert!(display.contains("0x0074"));
    }

    #[test]
    fn test_member_struct_example() {
        // Simulate: struct Point { int x; float y; };
        let x = LfMember::public_member(0x0074, 0, "x".to_string());
        let y = LfMember::public_member(0x0040, 4, "y".to_string());

        assert_eq!(x.offset, 0);
        assert_eq!(y.offset, 4);
        assert_eq!(x.type_record_number, RecordNumber::type_record(0x0074));
        assert_eq!(y.type_record_number, RecordNumber::type_record(0x0040));
    }

    #[test]
    fn test_member_with_constructor_attribute() {
        // Simulate a member with pseudo flag (compiler-generated padding).
        let m = LfMember::new(
            RecordNumber::type_record(0x0074),
            0,
            MemberAttributes {
                access: AccessProtection::Public,
                is_pseudo: true,
                no_inherit: false,
                no_construct: false,
            },
            "__padding".to_string(),
        );
        assert!(m.attributes.is_pseudo);
    }
}
