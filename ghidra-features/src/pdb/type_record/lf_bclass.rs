//! LF_BCLASS -- concrete Base Class type record.
//!
//! Ports Ghidra's `BaseClassMsType` (PDB_ID = 0x1400) Java class.
//!
//! Represents a direct (non-virtual) base class within a composite type
//! (struct/class/union) in the PDB type stream. This is a leaf record
//! that appears inside an `LF_FIELDLIST`.
//!
//! # Binary Layout (LF_BCLASS / 0x1400)
//!
//! ```text
//! +0  u16   attributes        Access protection flags
//! +2  u32   baseClass         Type index of the base class type
//! +6  Numeric offset          Byte offset of base within derived class
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::lf_member::{AccessProtection, MemberAttributes};
use super::{MsTypeField, RecordNumber};
use crate::pdb::pdb_byte_reader::PdbByteReader;
use crate::pdb::pdb_exception::PdbException;

/// Concrete PDB base class type record (`LF_BCLASS`).
///
/// This is the Rust equivalent of Ghidra's `BaseClassMsType`. It stores
/// the base class type record number, its byte offset within the derived
/// class, and access protection attributes.
///
/// This record type represents a direct (non-virtual) base class. For
/// virtual base classes, `LF_VBCLASS` (0x1514) and `LF_IVBCLASS`
/// (0x1515) are used instead.
///
/// Corresponds to the Java `BaseClassMsType` class and its parent
/// `AbstractBaseClassMsType`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfBclass {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the base class type.
    pub base_class_record_number: RecordNumber,
    /// Byte offset of the base class within the derived class.
    pub offset: u32,
    /// Member attributes (access protection).
    pub attributes: MemberAttributes,
}

impl LfBclass {
    /// Create a new base class type record.
    pub fn new(
        base_class_record_number: RecordNumber,
        offset: u32,
        attributes: MemberAttributes,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            base_class_record_number,
            offset,
            attributes,
        }
    }

    /// Create from raw parsed field values.
    pub fn from_parsed(
        attributes_raw: u16,
        base_class_type_index: u32,
        offset: u32,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(base_class_type_index),
            offset,
            MemberAttributes::from_u16(attributes_raw),
        )
    }

    /// Parse an `LF_BCLASS` record from raw bytes (payload after leaf ID).
    ///
    /// Mirrors the Java `BaseClassMsType(AbstractPdb, PdbByteReader)` constructor.
    /// The `data` slice should start at the `attributes` field (after the
    /// 2-byte leaf ID).
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u16   attributes        Access protection flags
    /// +2  u32   baseClass         Type index of the base class type
    /// +6  Numeric offset          Byte offset of base within derived class
    /// ```
    ///
    /// The offset field uses PDB numeric encoding: if the first u16 is
    /// < 0x8000, it is the value itself (2 bytes consumed). Otherwise it
    /// indicates the byte width of the following integer (0x8000=u16,
    /// 0x8001=u32, etc.).
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 6 {
            return Err(format!(
                "LF_BCLASS payload too short: need >= 6 bytes, got {}",
                data.len()
            ));
        }
        let attributes_raw = u16::from_le_bytes([data[0], data[1]]);
        let base_class_ti = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);

        let (offset, _next) = crate::pdb::pdb_byte_reader::parse_numeric(data, 6);

        Ok(Self::from_parsed(attributes_raw, base_class_ti, offset as u32))
    }

    /// Parse an `LF_BCLASS` record from a [`PdbByteReader`].
    ///
    /// Mirrors the Java `BaseClassMsType(AbstractPdb, PdbByteReader)` constructor.
    /// Reads attributes, base class record number (32-bit), a PDB numeric offset,
    /// then aligns to 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PdbException`] if the reader does not have enough data or the
    /// numeric is not integral.
    pub fn parse_from_reader(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let attributes_raw = reader.read_u16()?;
        let base_class_ti = reader.read_u32()?;
        let offset = Self::read_numeric(reader)?;
        reader.align(4);
        Ok(Self::from_parsed(attributes_raw, base_class_ti, offset as u32))
    }

    /// Read a PDB numeric value from the reader.
    ///
    /// Small values (< 0x8000) are stored directly as u16. Larger values use
    /// a variant tag byte to indicate the actual width.
    fn read_numeric(reader: &mut PdbByteReader) -> Result<u64, PdbException> {
        let low = reader.read_u16()?;
        if low < 0x8000 {
            return Ok(low as u64);
        }
        let variant = reader.read_u8()?;
        match variant {
            0x00 => Ok(reader.read_u16()? as u64),
            0x01 => Ok(reader.read_i16()? as u64),
            0x02 => Ok(reader.read_u32()? as u64),
            0x03 => Ok(reader.read_i32()? as u64),
            0x10 => Ok(reader.read_u64()?),
            _ => Ok(low as u64),
        }
    }

    /// Create a simple public base class.
    pub fn public_base(
        base_class_type_index: u32,
        offset: u32,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(base_class_type_index),
            offset,
            MemberAttributes::public_member(),
        )
    }

    /// Get the record number of the base class type.
    ///
    /// Mirrors Java `AbstractBaseClassMsType.getBaseClassRecordNumber()`.
    pub fn base_class_record_number(&self) -> RecordNumber {
        self.base_class_record_number
    }

    /// Get the byte offset of the base within the derived class.
    ///
    /// Mirrors Java `AbstractBaseClassMsType.getOffset()`.
    pub fn byte_offset(&self) -> u32 {
        self.offset
    }

    /// Get the byte offset of the base within the derived class (u64).
    ///
    /// Mirrors Java `AbstractBaseClassMsType.getOffset()` which returns
    /// `BigInteger`. Returns as u64 for convenience with large offsets.
    pub fn offset_value(&self) -> u64 {
        self.offset as u64
    }

    /// Get the member attributes.
    pub fn attribute(&self) -> &MemberAttributes {
        &self.attributes
    }

    /// Get the access protection level.
    pub fn access(&self) -> AccessProtection {
        self.attributes.access
    }

    /// Whether the base class record number references a valid type.
    pub fn has_valid_base_class(&self) -> bool {
        !self.base_class_record_number.is_no_type()
    }

    /// Whether this is a direct (non-virtual) base class.
    ///
    /// Always returns `true` for `LF_BCLASS`. Virtual base classes use
    /// `LF_VBCLASS` or `LF_IVBCLASS` instead.
    pub fn is_direct(&self) -> bool {
        true
    }

    /// Whether this is a virtual base class.
    ///
    /// Always returns `false` for `LF_BCLASS`.
    pub fn is_virtual_base(&self) -> bool {
        false
    }

    /// Whether this is an indirect virtual base class.
    ///
    /// Always returns `false` for `LF_BCLASS`.
    pub fn is_indirect_virtual_base(&self) -> bool {
        false
    }

    /// Get the name of this base class.
    ///
    /// Base class records do not carry their own name; the name is resolved
    /// from the referenced base class type record. Returns `""`.
    /// Provided for API symmetry with other field-list sub-records.
    pub fn get_name(&self) -> &str {
        ""
    }

    /// Convert this base class into a [`FieldListEntry::BaseClass`].
    ///
    /// This is useful when constructing or manipulating field lists
    /// programmatically.
    pub fn to_field_list_entry(&self) -> super::abstract_field_list_ms_type::FieldListEntry {
        super::abstract_field_list_ms_type::FieldListEntry::BaseClass {
            type_record: self.base_class_record_number,
            offset: self.offset,
            access: self.attributes.access as u16,
        }
    }
}

impl AbstractMsType for LfBclass {
    fn name(&self) -> &str {
        // Base class records don't carry their own name; the name comes
        // from the referenced type record.
        ""
    }

    fn pdb_id(&self) -> u32 {
        0x1400 // LF_BCLASS
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java:
        //   attribute.emit(builder);
        //   builder.append(":");
        //   builder.append(pdb.getTypeRecord(baseClassRecordNumber));
        //   builder.append("<@");
        //   builder.append(offset);
        //   builder.append(">");
        let mut result = String::new();
        result.push_str(&self.attributes.emit_string());
        result.push(':');
        result.push_str(&self.base_class_record_number.to_string());
        result.push_str(&format!("<@{}>", self.offset));
        result
    }
}

impl MsTypeField for LfBclass {}

impl Default for LfBclass {
    fn default() -> Self {
        Self::new(
            RecordNumber::NO_TYPE,
            0,
            super::lf_member::MemberAttributes::public_member(),
        )
    }
}

impl fmt::Display for LfBclass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_bclass() -> LfBclass {
        LfBclass::public_base(
            0x1000,
            0,
        )
    }

    #[test]
    fn test_bclass_basic() {
        let bc = make_test_bclass();
        assert_eq!(bc.pdb_id(), 0x1400);
        assert_eq!(
            bc.base_class_record_number,
            RecordNumber::type_record(0x1000)
        );
        assert_eq!(bc.offset, 0);
        assert_eq!(bc.access(), AccessProtection::Public);
    }

    #[test]
    fn test_bclass_from_parsed() {
        let bc = LfBclass::from_parsed(0x0003, 0x1000, 8);
        assert_eq!(
            bc.base_class_record_number(),
            RecordNumber::type_record(0x1000)
        );
        assert_eq!(bc.byte_offset(), 8);
        assert_eq!(bc.access(), AccessProtection::Public);
    }

    #[test]
    fn test_bclass_from_parsed_private() {
        let bc = LfBclass::from_parsed(0x0001, 0x1000, 0);
        assert_eq!(bc.access(), AccessProtection::Private);
    }

    #[test]
    fn test_bclass_from_parsed_protected() {
        let bc = LfBclass::from_parsed(0x0002, 0x1000, 4);
        assert_eq!(bc.access(), AccessProtection::Protected);
    }

    #[test]
    fn test_bclass_emit() {
        let bc = make_test_bclass();
        let emitted = bc.emit(Bind::NONE);
        assert!(emitted.contains("public"));
        assert!(emitted.contains("0x1000"));
        assert!(emitted.contains("<@0>"));
    }

    #[test]
    fn test_bclass_emit_with_offset() {
        let bc = LfBclass::from_parsed(0x0003, 0x1000, 16);
        let emitted = bc.emit(Bind::NONE);
        assert!(emitted.contains("<@16>"));
    }

    #[test]
    fn test_bclass_emit_format() {
        let bc = LfBclass::from_parsed(0x0003, 0x1000, 8);
        let emitted = bc.emit(Bind::NONE);
        // Format: "public:0x1000<@8>"
        assert!(emitted.starts_with("public:"));
    }

    #[test]
    fn test_bclass_record_number() {
        let mut bc = make_test_bclass();
        assert!(bc.record_number().is_no_type());
        bc.set_record_number(RecordNumber::type_record(0x3000));
        assert_eq!(bc.record_number().index(), 0x3000);
    }

    #[test]
    fn test_bclass_display() {
        let bc = make_test_bclass();
        let display = format!("{}", bc);
        assert!(display.contains("public"));
        assert!(display.contains("0x1000"));
        assert!(display.contains("<@0>"));
    }

    #[test]
    fn test_bclass_name_is_empty() {
        let bc = make_test_bclass();
        assert_eq!(bc.name(), "");
    }

    #[test]
    fn test_bclass_attribute() {
        let bc = make_test_bclass();
        let attr = bc.attribute();
        assert_eq!(attr.access, AccessProtection::Public);
        assert_eq!(attr.property, super::super::lf_member::MemberProperty::Blank);
    }

    #[test]
    fn test_bclass_byte_offset() {
        let bc = LfBclass::from_parsed(0x0003, 0x1000, 32);
        assert_eq!(bc.byte_offset(), 32);
    }

    #[test]
    fn test_bclass_base_class_record_number() {
        let bc = LfBclass::new(
            RecordNumber::type_record(0x2000),
            0,
            MemberAttributes::public_member(),
        );
        assert_eq!(
            bc.base_class_record_number(),
            RecordNumber::type_record(0x2000)
        );
    }

    #[test]
    fn test_bclass_parse() {
        // LF_BCLASS payload: attributes=0x0003(public), baseClass=0x1000, offset=8
        let mut data = Vec::new();
        data.extend_from_slice(&0x0003u16.to_le_bytes()); // attributes
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // baseClass
        data.extend_from_slice(&8u16.to_le_bytes());      // offset (numeric: < 0x8000 so literal)

        let bc = LfBclass::parse(&data).unwrap();
        assert_eq!(bc.pdb_id(), 0x1400);
        assert_eq!(
            bc.base_class_record_number(),
            RecordNumber::type_record(0x1000)
        );
        assert_eq!(bc.byte_offset(), 8);
        assert_eq!(bc.access(), AccessProtection::Public);
    }

    #[test]
    fn test_bclass_parse_zero_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0003u16.to_le_bytes());
        data.extend_from_slice(&0x2000u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // offset = 0

        let bc = LfBclass::parse(&data).unwrap();
        assert_eq!(bc.byte_offset(), 0);
        assert_eq!(
            bc.base_class_record_number(),
            RecordNumber::type_record(0x2000)
        );
    }

    #[test]
    fn test_bclass_parse_private() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0001u16.to_le_bytes()); // private
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());

        let bc = LfBclass::parse(&data).unwrap();
        assert_eq!(bc.access(), AccessProtection::Private);
    }

    #[test]
    fn test_bclass_parse_too_short() {
        let data = [0u8; 4];
        assert!(LfBclass::parse(&data).is_err());
    }

    #[test]
    fn test_bclass_has_valid_base_class() {
        let bc = make_test_bclass();
        assert!(bc.has_valid_base_class());

        let bc2 = LfBclass::new(
            RecordNumber::NO_TYPE,
            0,
            MemberAttributes::public_member(),
        );
        assert!(!bc2.has_valid_base_class());
    }

    #[test]
    fn test_bclass_eq() {
        let bc1 = make_test_bclass();
        let bc2 = make_test_bclass();
        assert_eq!(bc1, bc2);

        let bc3 = LfBclass::public_base(0x2000, 0);
        assert_ne!(bc1, bc3);
    }

    #[test]
    fn test_bclass_is_direct() {
        let bc = make_test_bclass();
        assert!(bc.is_direct());
        assert!(!bc.is_virtual_base());
        assert!(!bc.is_indirect_virtual_base());
    }

    #[test]
    fn test_bclass_to_field_list_entry() {
        let bc = LfBclass::from_parsed(0x0003, 0x1000, 8);
        let entry = bc.to_field_list_entry();
        match entry {
            super::super::abstract_field_list_ms_type::FieldListEntry::BaseClass {
                type_record,
                offset,
                access,
            } => {
                assert_eq!(type_record, RecordNumber::type_record(0x1000));
                assert_eq!(offset, 8);
                assert_eq!(access, 3); // public
            }
            _ => panic!("Expected BaseClass variant"),
        }
    }

    #[test]
    fn test_bclass_default() {
        let bc = LfBclass::default();
        assert!(bc.record_number().is_no_type());
        assert!(bc.is_direct());
        assert_eq!(bc.byte_offset(), 0);
    }

    #[test]
    fn test_bclass_parse_from_reader() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0003u16.to_le_bytes()); // attributes (public)
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // baseClass
        data.extend_from_slice(&8u16.to_le_bytes());      // offset (numeric: < 0x8000)

        let mut reader = PdbByteReader::new(&data);
        let bc = LfBclass::parse_from_reader(&mut reader).unwrap();
        assert_eq!(bc.pdb_id(), 0x1400);
        assert_eq!(
            bc.base_class_record_number(),
            RecordNumber::type_record(0x1000)
        );
        assert_eq!(bc.byte_offset(), 8);
        assert_eq!(bc.access(), AccessProtection::Public);
    }

    #[test]
    fn test_bclass_parse_from_reader_large_offset() {
        // Offset > 0x8000: use numeric encoding with u32 variant
        let mut data = Vec::new();
        data.extend_from_slice(&0x0003u16.to_le_bytes()); // attributes
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // baseClass
        // Numeric: 0x8000 tag + variant 0x02 (u32) + value 0x12345678
        data.extend_from_slice(&0x8000u16.to_le_bytes()); // tag
        data.push(0x02);                                   // variant = u32
        data.extend_from_slice(&0x12345678u32.to_le_bytes()); // value

        let mut reader = PdbByteReader::new(&data);
        let bc = LfBclass::parse_from_reader(&mut reader).unwrap();
        assert_eq!(bc.byte_offset(), 0x12345678);
    }

    #[test]
    fn test_bclass_parse_from_reader_too_short() {
        let data = [0u8; 4];
        let mut reader = PdbByteReader::new(&data);
        assert!(LfBclass::parse_from_reader(&mut reader).is_err());
    }

    #[test]
    fn test_bclass_offset_value() {
        let bc = LfBclass::from_parsed(0x0003, 0x1000, 32);
        assert_eq!(bc.offset_value(), 32u64);
        assert_eq!(bc.offset_value(), bc.byte_offset() as u64);
    }

    #[test]
    fn test_bclass_clone() {
        let bc = make_test_bclass();
        let bc2 = bc.clone();
        assert_eq!(bc, bc2);
    }

    #[test]
    fn test_bclass_parse_large_offset_numeric() {
        // Offset encoded as 0x8000 tag + u32 variant (0x02) + value
        let mut data = Vec::new();
        data.extend_from_slice(&0x0003u16.to_le_bytes()); // access
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // baseClass
        data.extend_from_slice(&0x8000u16.to_le_bytes()); // numeric tag
        data.push(0x02);                                   // variant = u32
        data.extend_from_slice(&0x00010000u32.to_le_bytes()); // value = 65536

        let bc = LfBclass::parse(&data).unwrap();
        assert_eq!(bc.byte_offset(), 0x00010000);
    }

    #[test]
    fn test_bclass_parse_protected_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0002u16.to_le_bytes()); // protected
        data.extend_from_slice(&0x2000u32.to_le_bytes()); // baseClass
        data.extend_from_slice(&12u16.to_le_bytes());     // offset

        let bc = LfBclass::parse(&data).unwrap();
        assert_eq!(bc.access(), AccessProtection::Protected);
        assert_eq!(bc.byte_offset(), 12);
    }
}
