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
/// Parsed from bits 2-4 of the member attributes word. Corresponds to
/// the Java `ClassFieldMsAttributes.Property` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MemberProperty {
    /// No property specified.
    Blank = 0,
    /// Virtual member.
    Virtual = 1,
    /// Static member.
    Static = 2,
    /// Friend declaration.
    Friend = 3,
    /// Introducing virtual function (vftable slot).
    Intro = 4,
    /// Pure virtual function.
    Pure = 5,
    /// Introducing pure virtual function.
    IntroPure = 6,
    /// Reserved / unused.
    Reserved = 7,
}

impl MemberProperty {
    /// Parse from a 3-bit value.
    pub fn from_value(val: u16) -> Self {
        match (val >> 2) & 0x07 {
            0 => Self::Blank,
            1 => Self::Virtual,
            2 => Self::Static,
            3 => Self::Friend,
            4 => Self::Intro,
            5 => Self::Pure,
            6 => Self::IntroPure,
            7 => Self::Reserved,
            _ => Self::Blank,
        }
    }

    /// The label string for display.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Blank => "",
            Self::Virtual => "virtual",
            Self::Static => "static",
            Self::Friend => "friend",
            Self::Intro => "<intro>",
            Self::Pure => "<pure>",
            Self::IntroPure => "<intro,pure>",
            Self::Reserved => "",
        }
    }

    /// Whether this property represents any kind of virtual function.
    pub fn is_virtual(&self) -> bool {
        matches!(self, Self::Virtual | Self::Intro | Self::Pure | Self::IntroPure)
    }
}

impl fmt::Display for MemberProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Member class field attributes.
///
/// Parsed from the full 16-bit attributes word in LF_MEMBER and related
/// records. Corresponds to the Java `ClassFieldMsAttributes` class which
/// contains access level, property flags, and several boolean modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemberAttributes {
    /// Access protection level (bits 0-1).
    pub access: AccessProtection,
    /// Property classification (bits 2-4).
    pub property: MemberProperty,
    /// Whether this member is a compiler-generated pseudo-field (bit 5).
    /// Corresponds to Java `compilerGenerateFunctionDoesNotExist`.
    pub is_pseudo: bool,
    /// Whether this member cannot be inherited (bit 6).
    pub no_inherit: bool,
    /// Whether this member is not constructible (bit 7).
    pub no_construct: bool,
    /// Whether a compiler-generated function exists (bit 8).
    /// Corresponds to Java `compilerGenerateFunctionDoesExist`.
    pub compiler_generated_exists: bool,
    /// Whether this member cannot be overridden (bit 9).
    pub cannot_be_overridden: bool,
}

impl MemberAttributes {
    /// Create from a raw 16-bit attributes value.
    ///
    /// Layout matches Java `ClassFieldMsAttributes.processAttributes()`:
    /// ```text
    /// bits 0-1: Access
    /// bits 2-4: Property
    /// bit  5:   compilerGenerateFunctionDoesNotExist (pseudo)
    /// bit  6:   cannotBeInherited
    /// bit  7:   cannotBeConstructed
    /// bit  8:   compilerGenerateFunctionDoesExist
    /// bit  9:   cannotBeOverridden
    /// ```
    pub fn from_u16(val: u16) -> Self {
        Self {
            access: AccessProtection::from_value(val),
            property: MemberProperty::from_value(val),
            is_pseudo: (val & 0x0020) != 0,
            no_inherit: (val & 0x0040) != 0,
            no_construct: (val & 0x0080) != 0,
            compiler_generated_exists: (val & 0x0100) != 0,
            cannot_be_overridden: (val & 0x0200) != 0,
        }
    }

    /// Create a simple public member attribute.
    pub fn public_member() -> Self {
        Self {
            access: AccessProtection::Public,
            property: MemberProperty::Blank,
            is_pseudo: false,
            no_inherit: false,
            no_construct: false,
            compiler_generated_exists: false,
            cannot_be_overridden: false,
        }
    }

    /// Emit the attributes as a formatted string matching the Java output.
    ///
    /// Format: `<access> <property>[<pseudo,noinherit,noconstruct>]`
    pub fn emit_string(&self) -> String {
        let mut result = String::new();
        result.push_str(self.access.label());

        let prop_label = self.property.label();
        if !prop_label.is_empty() {
            if !result.is_empty() {
                result.push(' ');
            }
            result.push_str(prop_label);
        }

        if self.is_pseudo || self.no_inherit || self.no_construct {
            let mut ds = super::DelimiterState::new("<", ", ");
            result.push_str(ds.out(self.is_pseudo));
            if self.is_pseudo {
                result.push_str("pseudo");
            }
            result.push_str(ds.out(self.no_inherit));
            if self.no_inherit {
                result.push_str("noinherit");
            }
            result.push_str(ds.out(self.no_construct));
            if self.no_construct {
                result.push_str("noconstruct");
            }
            result.push('>');
        }

        result
    }
}

impl fmt::Display for MemberAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit_string())
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

    /// Get the record number of the member's data type.
    ///
    /// Mirrors Java `AbstractMemberMsType.getFieldTypeRecordNumber()`.
    pub fn field_type_record_number(&self) -> RecordNumber {
        self.type_record_number
    }

    /// Get the byte offset within the containing composite.
    ///
    /// Mirrors Java `AbstractMemberMsType.getOffset()`.
    pub fn byte_offset(&self) -> u32 {
        self.offset
    }

    /// Get the member attributes.
    ///
    /// Mirrors Java `AbstractMemberMsType.getAttribute()`.
    pub fn attribute(&self) -> &MemberAttributes {
        &self.attributes
    }

    /// Get the access protection level.
    pub fn access(&self) -> AccessProtection {
        self.attributes.access
    }

    /// Get the member property classification.
    pub fn property(&self) -> MemberProperty {
        self.attributes.property
    }

    /// Whether this is a static member.
    pub fn is_static(&self) -> bool {
        self.attributes.property == MemberProperty::Static
    }

    /// Whether this is a virtual member.
    pub fn is_virtual(&self) -> bool {
        self.attributes.property.is_virtual()
    }

    /// Whether this is a compiler-generated pseudo-field.
    pub fn is_pseudo(&self) -> bool {
        self.attributes.is_pseudo
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

        // Emit attributes (access + property + modifiers).
        // Mirrors Java: builder.append(attribute); builder.append(": ");
        result.push_str(&self.attributes.emit_string());
        result.push_str(": ");

        // Emit the member name.
        result.push_str(&self.name);

        // Emit the type reference.
        // Mirrors Java: pdb.getTypeRecord(fieldTypeRecordNumber).emit(myBuilder, Bind.NONE)
        result.push(' ');
        result.push_str(&self.type_record_number.to_string());

        // Emit the offset.
        // Mirrors Java: builder.append("<@").append(offset).append(">")
        result.push_str(&format!("<@{}>", self.offset));

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
        assert_eq!(attrs.property, MemberProperty::Blank);
        assert!(!attrs.is_pseudo);
        assert!(!attrs.no_inherit);
        assert!(!attrs.no_construct);
        assert!(!attrs.compiler_generated_exists);
        assert!(!attrs.cannot_be_overridden);
    }

    #[test]
    fn test_member_attributes_pseudo() {
        // bit 5 = 0x0020
        let attrs = MemberAttributes::from_u16(0x0023); // public + pseudo (bit 5)
        assert_eq!(attrs.access, AccessProtection::Public);
        assert!(attrs.is_pseudo);
    }

    #[test]
    fn test_member_attributes_no_inherit() {
        // bit 6 = 0x0040
        let attrs = MemberAttributes::from_u16(0x0043); // public + no-inherit (bit 6)
        assert_eq!(attrs.access, AccessProtection::Public);
        assert!(attrs.no_inherit);
    }

    #[test]
    fn test_member_attributes_no_construct() {
        // bit 7 = 0x0080
        let attrs = MemberAttributes::from_u16(0x0083); // public + no-construct (bit 7)
        assert_eq!(attrs.access, AccessProtection::Public);
        assert!(attrs.no_construct);
    }

    #[test]
    fn test_member_attributes_compiler_generated_exists() {
        // bit 8 = 0x0100
        let attrs = MemberAttributes::from_u16(0x0103); // public + compiler_gen_exists (bit 8)
        assert_eq!(attrs.access, AccessProtection::Public);
        assert!(attrs.compiler_generated_exists);
    }

    #[test]
    fn test_member_attributes_cannot_be_overridden() {
        // bit 9 = 0x0200
        let attrs = MemberAttributes::from_u16(0x0203); // public + cannot_be_overridden (bit 9)
        assert_eq!(attrs.access, AccessProtection::Public);
        assert!(attrs.cannot_be_overridden);
    }

    #[test]
    fn test_member_property_virtual() {
        // property bits 2-4 = 1 (virtual) => val = 0x0004
        let attrs = MemberAttributes::from_u16(0x0007); // public + virtual
        assert_eq!(attrs.property, MemberProperty::Virtual);
        assert!(attrs.property.is_virtual());
    }

    #[test]
    fn test_member_property_static() {
        // property bits 2-4 = 2 (static) => val = 0x0008
        let attrs = MemberAttributes::from_u16(0x000B); // public + static
        assert_eq!(attrs.property, MemberProperty::Static);
        assert!(!attrs.property.is_virtual());
    }

    #[test]
    fn test_member_property_friend() {
        // property bits 2-4 = 3 (friend) => val = 0x000C
        let attrs = MemberAttributes::from_u16(0x000F); // public + friend
        assert_eq!(attrs.property, MemberProperty::Friend);
    }

    #[test]
    fn test_member_property_intro() {
        // property bits 2-4 = 4 (intro) => val = 0x0010
        let attrs = MemberAttributes::from_u16(0x0013); // public + intro
        assert_eq!(attrs.property, MemberProperty::Intro);
        assert!(attrs.property.is_virtual());
    }

    #[test]
    fn test_member_property_pure() {
        // property bits 2-4 = 5 (pure) => val = 0x0014
        let attrs = MemberAttributes::from_u16(0x0017); // public + pure
        assert_eq!(attrs.property, MemberProperty::Pure);
        assert!(attrs.property.is_virtual());
    }

    #[test]
    fn test_member_property_intro_pure() {
        // property bits 2-4 = 6 (intro_pure) => val = 0x0018
        let attrs = MemberAttributes::from_u16(0x001B); // public + intro_pure
        assert_eq!(attrs.property, MemberProperty::IntroPure);
        assert!(attrs.property.is_virtual());
    }

    #[test]
    fn test_member_property_display() {
        assert_eq!(format!("{}", MemberProperty::Virtual), "virtual");
        assert_eq!(format!("{}", MemberProperty::Static), "static");
        assert_eq!(format!("{}", MemberProperty::IntroPure), "<intro,pure>");
        assert_eq!(format!("{}", MemberProperty::Blank), "");
    }

    #[test]
    fn test_member_attributes_emit_string() {
        let attrs = MemberAttributes::public_member();
        assert_eq!(attrs.emit_string(), "public");

        let attrs = MemberAttributes::from_u16(0x0001); // private
        assert_eq!(attrs.emit_string(), "private");

        // public + static
        let attrs = MemberAttributes::from_u16(0x000B);
        assert!(attrs.emit_string().contains("public"));
        assert!(attrs.emit_string().contains("static"));
    }

    #[test]
    fn test_member_attributes_emit_with_pseudo() {
        // public + pseudo (bit 5)
        let attrs = MemberAttributes::from_u16(0x0023);
        let emitted = attrs.emit_string();
        assert!(emitted.contains("<pseudo>"));
    }

    #[test]
    fn test_member_attributes_emit_with_multiple_modifiers() {
        // public + pseudo (bit 5) + noinherit (bit 6) + noconstruct (bit 7)
        let attrs = MemberAttributes::from_u16(0x00E3);
        let emitted = attrs.emit_string();
        assert!(emitted.contains("<pseudo"));
        assert!(emitted.contains("noinherit"));
        assert!(emitted.contains("noconstruct"));
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
        assert!(emitted.contains("<@0>"));
        assert!(emitted.contains("public"));
    }

    #[test]
    fn test_member_emit_private() {
        let m = LfMember::from_parsed(0x0001, 0x0074, 8, "secret".to_string());
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.contains("private"));
        assert!(emitted.contains("<@8>"));
    }

    #[test]
    fn test_member_emit_contains_attributes() {
        // Public members show "public: " prefix.
        let m = make_test_member();
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.starts_with("public: "));
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
                property: MemberProperty::Blank,
                is_pseudo: true,
                no_inherit: false,
                no_construct: false,
                compiler_generated_exists: false,
                cannot_be_overridden: false,
            },
            "__padding".to_string(),
        );
        assert!(m.attributes.is_pseudo);
    }

    #[test]
    fn test_member_accessors() {
        let m = make_test_member();
        assert_eq!(m.field_type_record_number(), RecordNumber::type_record(0x0074));
        assert_eq!(m.byte_offset(), 0);
        assert_eq!(m.access(), AccessProtection::Public);
        assert_eq!(m.property(), MemberProperty::Blank);
        assert!(!m.is_static());
        assert!(!m.is_virtual());
        assert!(!m.is_pseudo());
    }

    #[test]
    fn test_member_is_static() {
        let m = LfMember::new(
            RecordNumber::type_record(0x0074),
            0,
            MemberAttributes::from_u16(0x000B), // public + static
            "count".to_string(),
        );
        assert!(m.is_static());
        assert!(!m.is_virtual());
    }

    #[test]
    fn test_member_is_virtual() {
        let m = LfMember::new(
            RecordNumber::type_record(0x0074),
            0,
            MemberAttributes::from_u16(0x0007), // public + virtual
            "vfunc".to_string(),
        );
        assert!(m.is_virtual());
        assert!(!m.is_static());
    }

    #[test]
    fn test_member_emit_virtual() {
        let m = LfMember::new(
            RecordNumber::type_record(0x0074),
            0,
            MemberAttributes::from_u16(0x0007), // public + virtual
            "vfunc".to_string(),
        );
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.contains("virtual"));
    }

    #[test]
    fn test_member_emit_static() {
        let m = LfMember::new(
            RecordNumber::type_record(0x0074),
            0,
            MemberAttributes::from_u16(0x000B), // public + static
            "count".to_string(),
        );
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.contains("static"));
    }

    #[test]
    fn test_member_display_contains_attributes() {
        let m = make_test_member();
        let display = format!("{}", m);
        assert!(display.contains("public"));
        assert!(display.contains("x"));
    }
}
