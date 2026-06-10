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
use super::RecordNumber;

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
#[derive(Debug, Clone)]
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

    /// Get the member attributes.
    pub fn attribute(&self) -> &MemberAttributes {
        &self.attributes
    }

    /// Get the access protection level.
    pub fn access(&self) -> AccessProtection {
        self.attributes.access
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
}
