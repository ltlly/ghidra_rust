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
use super::lf_member::{AccessProtection, MemberAttributes};
use super::{MsTypeField, RecordNumber};
use crate::pdb::pdb_byte_reader::PdbByteReader;
use crate::pdb::pdb_exception::PdbException;

/// Concrete PDB static member type record (`LF_STMEMBER`).
///
/// This is the Rust equivalent of Ghidra's `StaticMemberMsType`. It stores
/// a static data member's type, access protection, and name. Unlike
/// [`LfMember`](super::lf_member::LfMember), a static member has no byte
/// offset within the containing composite since static members are stored
/// globally.
///
/// Corresponds to the Java `StaticMemberMsType` class and its parent
/// `AbstractStaticMemberMsType`.
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Parse an `LF_STMEMBER` record from raw bytes (payload after leaf ID).
    ///
    /// Mirrors the Java `StaticMemberMsType(AbstractPdb, PdbByteReader)` constructor.
    /// The `data` slice should start at the `attributes` field (after the
    /// 2-byte leaf ID).
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u16   attributes       Member access and property flags
    /// +2  u32   type             Type index of the member's data type
    /// +6  StringNt name          Null-terminated member name
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 6 {
            return Err(format!(
                "LF_STMEMBER payload too short: need >= 6 bytes, got {}",
                data.len()
            ));
        }
        let attributes_raw = u16::from_le_bytes([data[0], data[1]]);
        let type_index = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        let name = if data.len() > 6 {
            crate::pdb::pdb_byte_reader::parse_null_terminated_string(&data[6..])
        } else {
            String::new()
        };
        Ok(Self::from_parsed(attributes_raw, type_index, name))
    }

    /// Parse an `LF_STMEMBER` record from a [`PdbByteReader`].
    ///
    /// Mirrors the Java `StaticMemberMsType(AbstractPdb, PdbByteReader)` constructor.
    /// Reads attributes, type record number (32-bit), and a null-terminated name
    /// string, then aligns to 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PdbException`] if the reader does not have enough data.
    pub fn parse_from_reader(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let attributes_raw = reader.read_u16()?;
        let type_index = reader.read_u32()?;
        let name = reader.read_cstring()?;
        reader.align(4);
        Ok(Self::from_parsed(attributes_raw, type_index, name))
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

    /// Create a simple private static member.
    pub fn private_static_member(
        type_index: u32,
        name: String,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(type_index),
            MemberAttributes {
                access: super::lf_member::AccessProtection::Private,
                ..MemberAttributes::public_member()
            },
            name,
        )
    }

    /// Create a simple protected static member.
    pub fn protected_static_member(
        type_index: u32,
        name: String,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(type_index),
            MemberAttributes {
                access: super::lf_member::AccessProtection::Protected,
                ..MemberAttributes::public_member()
            },
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
    pub fn access(&self) -> AccessProtection {
        self.attributes.access
    }

    /// Get the member property classification.
    pub fn property(&self) -> super::lf_member::MemberProperty {
        self.attributes.property
    }

    /// Whether the type record number references a valid type.
    pub fn has_valid_type(&self) -> bool {
        !self.type_record_number.is_no_type()
    }

    /// Whether this is a static member (always `true` for `LF_STMEMBER`).
    ///
    /// Provided for API symmetry with [`LfMember`](super::lf_member::LfMember).
    pub fn is_static(&self) -> bool {
        true
    }

    /// Whether this is a compiler-generated pseudo-field.
    ///
    /// Mirrors Java `ClassFieldMsAttributes.compilerGenerateFunctionDoesNotExist`.
    pub fn is_compiler_generated(&self) -> bool {
        self.attributes.is_pseudo
    }

    /// Whether this member cannot be inherited.
    ///
    /// Mirrors Java `ClassFieldMsAttributes.cannotBeInherited`.
    pub fn is_no_inherit(&self) -> bool {
        self.attributes.no_inherit
    }

    /// Whether this member cannot be constructed.
    ///
    /// Mirrors Java `ClassFieldMsAttributes.cannotBeConstructed`.
    pub fn is_no_construct(&self) -> bool {
        self.attributes.no_construct
    }

    /// Whether a compiler-generated function exists for this member.
    ///
    /// Mirrors Java `ClassFieldMsAttributes.compilerGenerateFunctionDoesExist`.
    pub fn compiler_generated_exists(&self) -> bool {
        self.attributes.compiler_generated_exists
    }

    /// Whether this member cannot be overridden.
    ///
    /// Mirrors Java `ClassFieldMsAttributes.cannotBeOverridden`.
    pub fn cannot_be_overridden(&self) -> bool {
        self.attributes.cannot_be_overridden
    }

    /// Convert this static member into a [`FieldListEntry::StaticMember`].
    ///
    /// This is useful when constructing or manipulating field lists
    /// programmatically.
    pub fn to_field_list_entry(&self) -> super::abstract_field_list_ms_type::FieldListEntry {
        super::abstract_field_list_ms_type::FieldListEntry::StaticMember {
            type_record: self.type_record_number,
            access: self.attributes.access as u16,
            name: self.name.clone(),
        }
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
        // Mirrors Java AbstractStaticMemberMsType.emit():
        //   builder.append(name);
        //   pdb.getTypeRecord(fieldTypeRecordNumber).emit(builder, Bind.NONE);
        //   StringBuilder myBuilder = new StringBuilder();
        //   myBuilder.append(attributes);
        //   myBuilder.append(": ");
        //   builder.insert(0, myBuilder);
        let mut body = String::new();
        body.push_str(&self.name);
        body.push(' ');
        body.push_str(&self.type_record_number.to_string());

        let mut prefix = String::new();
        prefix.push_str(&self.attributes.emit_string());
        prefix.push_str(": ");

        prefix.push_str(&body);
        prefix
    }
}

impl MsTypeField for LfStmember {}

impl Default for LfStmember {
    fn default() -> Self {
        Self::new(
            RecordNumber::NO_TYPE,
            super::lf_member::MemberAttributes::public_member(),
            String::new(),
        )
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
        assert_eq!(m.attributes.access, AccessProtection::Public);
    }

    #[test]
    fn test_stmember_from_parsed() {
        let m = LfStmember::from_parsed(0x0003, 0x0074, "s_count".to_string());
        assert_eq!(m.name(), "s_count");
        assert_eq!(
            m.type_record_number,
            RecordNumber::type_record(0x0074)
        );
        assert_eq!(m.attributes.access, AccessProtection::Public);
    }

    #[test]
    fn test_stmember_from_parsed_private() {
        let m = LfStmember::from_parsed(0x0001, 0x0074, "secret".to_string());
        assert_eq!(m.attributes.access, AccessProtection::Private);
    }

    #[test]
    fn test_stmember_from_parsed_protected() {
        let m = LfStmember::from_parsed(0x0002, 0x0074, "guarded".to_string());
        assert_eq!(m.attributes.access, AccessProtection::Protected);
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
        assert_eq!(m.access(), AccessProtection::Private);
    }

    #[test]
    fn test_stmember_attribute() {
        let m = make_test_stmember();
        let attr = m.attribute();
        assert_eq!(attr.access, AccessProtection::Public);
        assert_eq!(attr.property, super::super::lf_member::MemberProperty::Blank);
    }

    #[test]
    fn test_stmember_parse() {
        // LF_STMEMBER payload: attributes=0x0003(public), type=0x0074(int), name="count"
        let mut data = Vec::new();
        data.extend_from_slice(&0x0003u16.to_le_bytes()); // attributes
        data.extend_from_slice(&0x0074u32.to_le_bytes()); // type
        data.extend_from_slice(b"count\0");                // name

        let m = LfStmember::parse(&data).unwrap();
        assert_eq!(m.name(), "count");
        assert_eq!(m.pdb_id(), 0x150E);
        assert_eq!(m.type_record_number, RecordNumber::type_record(0x0074));
        assert_eq!(m.access(), AccessProtection::Public);
    }

    #[test]
    fn test_stmember_parse_private() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0001u16.to_le_bytes()); // private
        data.extend_from_slice(&0x0030u32.to_le_bytes()); // bool
        data.extend_from_slice(b"s_flag\0");

        let m = LfStmember::parse(&data).unwrap();
        assert_eq!(m.name(), "s_flag");
        assert_eq!(m.access(), AccessProtection::Private);
    }

    #[test]
    fn test_stmember_parse_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0003u16.to_le_bytes());
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.push(0); // empty null-terminated string

        let m = LfStmember::parse(&data).unwrap();
        assert!(m.name().is_empty());
    }

    #[test]
    fn test_stmember_parse_no_name_bytes() {
        // Exactly 6 bytes, no room for name
        let mut data = Vec::new();
        data.extend_from_slice(&0x0003u16.to_le_bytes());
        data.extend_from_slice(&0x0074u32.to_le_bytes());

        let m = LfStmember::parse(&data).unwrap();
        assert!(m.name().is_empty());
    }

    #[test]
    fn test_stmember_parse_too_short() {
        let data = [0u8; 4];
        assert!(LfStmember::parse(&data).is_err());
    }

    #[test]
    fn test_stmember_property() {
        let m = LfStmember::from_parsed(0x000B, 0x0074, "x".to_string());
        // 0x000B = public + static (bits 2-4 = 2)
        assert_eq!(m.property(), super::super::lf_member::MemberProperty::Static);
    }

    #[test]
    fn test_stmember_has_valid_type() {
        let m = make_test_stmember();
        assert!(m.has_valid_type());

        let m2 = LfStmember::new(
            RecordNumber::NO_TYPE,
            MemberAttributes::public_member(),
            "bad".to_string(),
        );
        assert!(!m2.has_valid_type());
    }

    #[test]
    fn test_stmember_eq() {
        let m1 = make_test_stmember();
        let m2 = make_test_stmember();
        assert_eq!(m1, m2);

        let m3 = LfStmember::public_static_member(0x0074, "other".to_string());
        assert_ne!(m1, m3);
    }

    #[test]
    fn test_stmember_empty_name() {
        let m = LfStmember::new(
            RecordNumber::type_record(0x0074),
            MemberAttributes::public_member(),
            String::new(),
        );
        assert!(m.name().is_empty());
    }

    #[test]
    fn test_stmember_emit_private() {
        let m = LfStmember::from_parsed(0x0001, 0x0074, "secret".to_string());
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.starts_with("private: "));
        assert!(emitted.contains("secret"));
    }

    #[test]
    fn test_stmember_is_static() {
        let m = make_test_stmember();
        assert!(m.is_static());
    }

    #[test]
    fn test_stmember_to_field_list_entry() {
        let m = make_test_stmember();
        let entry = m.to_field_list_entry();
        match entry {
            super::super::abstract_field_list_ms_type::FieldListEntry::StaticMember {
                type_record,
                access,
                name,
            } => {
                assert_eq!(type_record, RecordNumber::type_record(0x0074));
                assert_eq!(access, 3); // public
                assert_eq!(name, "count");
            }
            _ => panic!("Expected StaticMember variant"),
        }
    }

    #[test]
    fn test_stmember_default() {
        let m = LfStmember::default();
        assert!(m.name().is_empty());
        assert!(m.record_number().is_no_type());
        assert!(m.is_static());
    }

    #[test]
    fn test_stmember_parse_from_reader() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0003u16.to_le_bytes()); // attributes (public)
        data.extend_from_slice(&0x0074u32.to_le_bytes()); // type
        data.extend_from_slice(b"count\0");                // name
        // align4: "count\0" is 6 bytes from offset 6, total 12 bytes, already aligned

        let mut reader = PdbByteReader::new(&data);
        let m = LfStmember::parse_from_reader(&mut reader).unwrap();
        assert_eq!(m.name(), "count");
        assert_eq!(m.pdb_id(), 0x150E);
        assert_eq!(m.type_record_number, RecordNumber::type_record(0x0074));
        assert_eq!(m.access(), AccessProtection::Public);
    }

    #[test]
    fn test_stmember_parse_from_reader_aligns() {
        // Name "ab" (3 bytes with null) after 6 fixed bytes = 9 total, needs padding to 12
        let mut data = Vec::new();
        data.extend_from_slice(&0x0003u16.to_le_bytes());
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.extend_from_slice(b"ab\0"); // 3 bytes, total = 9
        data.push(0); // padding byte, total = 10
        data.push(0); // padding byte, total = 11
        data.push(0); // padding byte, total = 12

        let mut reader = PdbByteReader::new(&data);
        let m = LfStmember::parse_from_reader(&mut reader).unwrap();
        assert_eq!(m.name(), "ab");
        assert_eq!(reader.position(), 12); // aligned to 4
    }

    #[test]
    fn test_stmember_parse_from_reader_too_short() {
        let data = [0u8; 4];
        let mut reader = PdbByteReader::new(&data);
        assert!(LfStmember::parse_from_reader(&mut reader).is_err());
    }

    #[test]
    fn test_stmember_private_static_member() {
        let m = LfStmember::private_static_member(0x0074, "secret".to_string());
        assert_eq!(m.name(), "secret");
        assert_eq!(m.access(), AccessProtection::Private);
        assert_eq!(m.type_record_number, RecordNumber::type_record(0x0074));
        assert!(m.is_static());
    }

    #[test]
    fn test_stmember_protected_static_member() {
        let m = LfStmember::protected_static_member(0x0074, "guarded".to_string());
        assert_eq!(m.name(), "guarded");
        assert_eq!(m.access(), AccessProtection::Protected);
    }

    #[test]
    fn test_stmember_emit_private_static() {
        // Use from_parsed with static property (bits 2-4 = 2 for static, bits 0-1 = 1 for private)
        // 0x0009 = private (1) | static (2 << 2) = 1 + 8 = 9
        let m = LfStmember::from_parsed(0x0009, 0x0074, "secret".to_string());
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.starts_with("private static: "));
        assert!(emitted.contains("secret"));
        assert!(emitted.contains("0x0074"));
    }

    #[test]
    fn test_stmember_emit_protected_static() {
        // 0x000A = protected (2) | static (2 << 2) = 2 + 8 = 10
        let m = LfStmember::from_parsed(0x000A, 0x0074, "guarded".to_string());
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.starts_with("protected static: "));
        assert!(emitted.contains("guarded"));
    }

    #[test]
    fn test_stmember_private_static_member_access() {
        let m = LfStmember::private_static_member(0x0074, "secret".to_string());
        assert_eq!(m.access(), AccessProtection::Private);
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.starts_with("private: "));
        assert!(emitted.contains("secret"));
    }

    #[test]
    fn test_stmember_protected_static_member_access() {
        let m = LfStmember::protected_static_member(0x0074, "guarded".to_string());
        assert_eq!(m.access(), AccessProtection::Protected);
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.starts_with("protected: "));
        assert!(emitted.contains("guarded"));
    }

    #[test]
    fn test_stmember_clone() {
        let m = make_test_stmember();
        let m2 = m.clone();
        assert_eq!(m, m2);
    }

    #[test]
    fn test_stmember_is_compiler_generated() {
        // bit 5 = 0x0020
        let m = LfStmember::from_parsed(0x0023, 0x0074, "pad".to_string());
        assert!(m.is_compiler_generated());

        let m2 = make_test_stmember();
        assert!(!m2.is_compiler_generated());
    }

    #[test]
    fn test_stmember_is_no_inherit() {
        // bit 6 = 0x0040
        let m = LfStmember::from_parsed(0x0043, 0x0074, "x".to_string());
        assert!(m.is_no_inherit());
        assert!(!m.is_compiler_generated());
    }

    #[test]
    fn test_stmember_is_no_construct() {
        // bit 7 = 0x0080
        let m = LfStmember::from_parsed(0x0083, 0x0074, "x".to_string());
        assert!(m.is_no_construct());
    }

    #[test]
    fn test_stmember_compiler_generated_exists() {
        // bit 8 = 0x0100
        let m = LfStmember::from_parsed(0x0103, 0x0074, "x".to_string());
        assert!(m.compiler_generated_exists());
        assert!(!m.is_compiler_generated()); // different bit
    }

    #[test]
    fn test_stmember_cannot_be_overridden() {
        // bit 9 = 0x0200
        let m = LfStmember::from_parsed(0x0203, 0x0074, "x".to_string());
        assert!(m.cannot_be_overridden());
    }

    #[test]
    fn test_stmember_all_modifier_bits() {
        // All modifier bits set: pseudo(5) + noinherit(6) + noconstruct(7)
        // = 0x0020 + 0x0040 + 0x0080 = 0x00E0
        // Plus public(3) = 0x00E3
        let m = LfStmember::from_parsed(0x00E3, 0x0074, "x".to_string());
        assert!(m.is_compiler_generated());
        assert!(m.is_no_inherit());
        assert!(m.is_no_construct());
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.contains("<pseudo"));
        assert!(emitted.contains("noinherit"));
        assert!(emitted.contains("noconstruct"));
    }

    #[test]
    fn test_stmember_parse_roundtrip() {
        // Ensure parse -> emit -> parse roundtrip preserves data
        let mut data = Vec::new();
        data.extend_from_slice(&0x0003u16.to_le_bytes()); // public
        data.extend_from_slice(&0x0074u32.to_le_bytes()); // type
        data.extend_from_slice(b"myField\0");

        let m = LfStmember::parse(&data).unwrap();
        assert_eq!(m.name(), "myField");
        assert_eq!(m.type_record_number, RecordNumber::type_record(0x0074));
        assert_eq!(m.access(), AccessProtection::Public);
        assert!(m.is_static());
    }

    #[test]
    fn test_stmember_parse_from_reader_with_modifiers() {
        // public + static + pseudo (0x002B)
        let mut data = Vec::new();
        data.extend_from_slice(&0x002Bu16.to_le_bytes());
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.extend_from_slice(b"__pad\0");

        let mut reader = PdbByteReader::new(&data);
        let m = LfStmember::parse_from_reader(&mut reader).unwrap();
        assert_eq!(m.name(), "__pad");
        assert!(m.is_compiler_generated());
        assert_eq!(m.property(), super::super::lf_member::MemberProperty::Static);
    }
}
