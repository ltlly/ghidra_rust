//! LF_ONEMETHOD -- concrete Single Method type record.
//!
//! Ports Ghidra's `OneMethodMsType` (PDB_ID = 0x1511) Java class.
//!
//! Represents a single (non-overloaded) method within a composite type
//! (struct/class/union) in the PDB type stream. This is a leaf record
//! that appears inside an `LF_FIELDLIST`.
//!
//! # Binary Layout (LF_ONEMETHOD / 0x1511)
//!
//! ```text
//! +0  u16   attributes        Member access and property flags
//! +2  u32   procedureType     Type index of the method's procedure type
//! +6  u32   vftableOffset     VFTable offset (only if property is Intro/IntroPure)
//!     StringNt name           Null-terminated method name
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::lf_member::{MemberAttributes, MemberProperty};
use super::RecordNumber;

/// Concrete PDB single method type record (`LF_ONEMETHOD`).
///
/// This is the Rust equivalent of Ghidra's `OneMethodMsType`. It stores
/// a method's procedure type record number, its attributes (including
/// whether it is virtual/intro/pure), and its optional VFTable offset.
///
/// The VFTable offset is only meaningful when the method property is
/// `Intro` or `IntroPure` (i.e., the method introduces a new virtual
/// function slot). For non-intro methods, this field is set to -1.
///
/// Corresponds to the Java `OneMethodMsType` class and its parent
/// `AbstractOneMethodMsType`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfOnemethod {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the method's procedure/function type.
    pub procedure_type_record_number: RecordNumber,
    /// Offset in the VFTable if this is an introducing virtual method.
    /// Set to -1 for non-intro methods.
    pub vftable_offset: i32,
    /// Method attributes (access, property flags).
    pub attributes: MemberAttributes,
    /// Method name.
    pub name: String,
}

impl LfOnemethod {
    /// Create a new single method type record.
    pub fn new(
        procedure_type_record_number: RecordNumber,
        vftable_offset: i32,
        attributes: MemberAttributes,
        name: String,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            procedure_type_record_number,
            vftable_offset,
            attributes,
            name,
        }
    }

    /// Create from raw parsed field values.
    ///
    /// The `vftable_offset` should be provided as -1 for non-intro methods.
    /// The Java implementation conditionally reads this field based on the
    /// property value; this constructor expects the caller to have already
    /// determined the correct value.
    pub fn from_parsed(
        attributes_raw: u16,
        procedure_type_index: u32,
        vftable_offset: i32,
        name: String,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(procedure_type_index),
            vftable_offset,
            MemberAttributes::from_u16(attributes_raw),
            name,
        )
    }

    /// Parse an `LF_ONEMETHOD` record from raw bytes (payload after leaf ID).
    ///
    /// Mirrors the Java `OneMethodMsType(AbstractPdb, PdbByteReader)` constructor.
    /// The `data` slice should start at the `attributes` field (after the
    /// 2-byte leaf ID).
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u16   attributes        Member access and property flags
    /// +2  u32   procedureType     Type index of the method's procedure type
    /// +6  u32   vftableOffset     (conditional) VFTable offset
    ///     StringNt name           Null-terminated method name
    /// ```
    ///
    /// The VFTable offset (4 bytes at +6) is only present when the property
    /// is `Intro` (4) or `IntroPure` (6). The Java implementation reads it
    /// conditionally; this parse method follows the same logic.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 6 {
            return Err(format!(
                "LF_ONEMETHOD payload too short: need >= 6 bytes, got {}",
                data.len()
            ));
        }
        let attributes_raw = u16::from_le_bytes([data[0], data[1]]);
        let procedure_type_ti = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);

        let attrs = MemberAttributes::from_u16(attributes_raw);
        let is_intro = matches!(
            attrs.property,
            MemberProperty::Intro | MemberProperty::IntroPure
        );

        let (vftable_offset, name_offset) = if is_intro {
            if data.len() < 10 {
                return Err(format!(
                    "LF_ONEMETHOD payload too short for intro vftable offset: need >= 10, got {}",
                    data.len()
                ));
            }
            let offset = u32::from_le_bytes([data[6], data[7], data[8], data[9]]) as i32;
            (offset, 10)
        } else {
            (-1, 6)
        };

        let name = if name_offset < data.len() {
            crate::pdb::pdb_byte_reader::parse_null_terminated_string(&data[name_offset..])
        } else {
            String::new()
        };

        Ok(Self::new(
            RecordNumber::type_record(procedure_type_ti),
            vftable_offset,
            attrs,
            name,
        ))
    }

    /// Create a simple public method (non-virtual).
    pub fn public_method(
        procedure_type_index: u32,
        name: String,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(procedure_type_index),
            -1,
            MemberAttributes::public_member(),
            name,
        )
    }

    /// Get the record number of the procedure type.
    ///
    /// Mirrors Java `AbstractOneMethodMsType.getProcedureTypeRecordNumber()`.
    pub fn procedure_type_record_number(&self) -> RecordNumber {
        self.procedure_type_record_number
    }

    /// Get the VFTable offset.
    ///
    /// Returns -1 if this is not an introducing virtual method.
    /// Mirrors Java `AbstractOneMethodMsType.getOffsetInVFTableIfIntroVirtual()`.
    pub fn offset_in_vftable(&self) -> i32 {
        self.vftable_offset
    }

    /// Get the method attributes.
    pub fn attribute(&self) -> &MemberAttributes {
        &self.attributes
    }

    /// Get the access protection level.
    pub fn access(&self) -> super::lf_member::AccessProtection {
        self.attributes.access
    }

    /// Get the method property classification.
    pub fn property(&self) -> MemberProperty {
        self.attributes.property
    }

    /// Whether this is an introducing virtual method (has a VFTable slot).
    pub fn is_intro_virtual(&self) -> bool {
        matches!(
            self.attributes.property,
            MemberProperty::Intro | MemberProperty::IntroPure
        )
    }

    /// Whether this is a pure virtual method.
    pub fn is_pure_virtual(&self) -> bool {
        matches!(
            self.attributes.property,
            MemberProperty::Pure | MemberProperty::IntroPure
        )
    }

    /// Whether this is any kind of virtual method.
    pub fn is_virtual(&self) -> bool {
        self.attributes.property.is_virtual()
    }

    /// Whether the procedure type record number references a valid type.
    pub fn has_valid_procedure_type(&self) -> bool {
        !self.procedure_type_record_number.is_no_type()
    }

    /// Convert this single method into a [`FieldListEntry::OneMethod`].
    ///
    /// This is useful when constructing or manipulating field lists
    /// programmatically.
    pub fn to_field_list_entry(&self) -> super::abstract_field_list_ms_type::FieldListEntry {
        super::abstract_field_list_ms_type::FieldListEntry::OneMethod {
            type_record: self.procedure_type_record_number,
            vftable_offset: self.vftable_offset,
            access: self.attributes.access as u16,
            name: self.name.clone(),
        }
    }
}

impl AbstractMsType for LfOnemethod {
    fn name(&self) -> &str {
        &self.name
    }

    fn pdb_id(&self) -> u32 {
        0x1511 // LF_ONEMETHOD
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java:
        //   builder.append("<");
        //   builder.append(attributes);
        //   builder.append(": ");
        //   builder.append(pdb.getTypeRecord(procedureTypeRecordNumber));
        //   if (offsetInVFTableIfIntroVirtual != -1) {
        //       builder.append(",");
        //       builder.append(offsetInVFTableIfIntroVirtual);
        //   }
        //   builder.append(">");
        let mut result = String::new();
        result.push('<');
        result.push_str(&self.attributes.emit_string());
        result.push_str(": ");
        result.push_str(&self.procedure_type_record_number.to_string());
        if self.vftable_offset != -1 {
            result.push(',');
            result.push_str(&self.vftable_offset.to_string());
        }
        result.push('>');
        result
    }
}

impl Default for LfOnemethod {
    fn default() -> Self {
        Self::new(
            RecordNumber::NO_TYPE,
            -1,
            super::lf_member::MemberAttributes::public_member(),
            String::new(),
        )
    }
}

impl fmt::Display for LfOnemethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_onemethod() -> LfOnemethod {
        LfOnemethod::public_method(
            0x1011,
            "bar".to_string(),
        )
    }

    #[test]
    fn test_onemethod_basic() {
        let m = make_test_onemethod();
        assert_eq!(m.name(), "bar");
        assert_eq!(m.pdb_id(), 0x1511);
        assert_eq!(
            m.procedure_type_record_number(),
            RecordNumber::type_record(0x1011)
        );
        assert_eq!(m.vftable_offset, -1);
    }

    #[test]
    fn test_onemethod_from_parsed() {
        let m = LfOnemethod::from_parsed(0x0003, 0x1011, -1, "foo".to_string());
        assert_eq!(m.name(), "foo");
        assert_eq!(
            m.procedure_type_record_number(),
            RecordNumber::type_record(0x1011)
        );
        assert_eq!(m.attributes.access, super::super::lf_member::AccessProtection::Public);
    }

    #[test]
    fn test_onemethod_virtual() {
        let m = LfOnemethod::from_parsed(0x0007, 0x1011, 8, "vfunc".to_string());
        // 0x0007 = public + virtual (bits 2-4 = 1)
        assert!(m.is_virtual());
        assert!(!m.is_intro_virtual());
        assert_eq!(m.vftable_offset, 8);
    }

    #[test]
    fn test_onemethod_intro() {
        let m = LfOnemethod::from_parsed(0x0013, 0x1011, 16, "intro".to_string());
        // 0x0013 = public + intro (bits 2-4 = 4)
        assert!(m.is_intro_virtual());
        assert!(!m.is_pure_virtual());
        assert!(m.is_virtual());
        assert_eq!(m.vftable_offset, 16);
    }

    #[test]
    fn test_onemethod_intro_pure() {
        let m = LfOnemethod::from_parsed(0x001B, 0x1011, 24, "pure_intro".to_string());
        // 0x001B = public + intro_pure (bits 2-4 = 6)
        assert!(m.is_intro_virtual());
        assert!(m.is_pure_virtual());
        assert!(m.is_virtual());
        assert_eq!(m.vftable_offset, 24);
    }

    #[test]
    fn test_onemethod_pure() {
        let m = LfOnemethod::from_parsed(0x0017, 0x1011, -1, "pure".to_string());
        // 0x0017 = public + pure (bits 2-4 = 5)
        assert!(!m.is_intro_virtual());
        assert!(m.is_pure_virtual());
        assert!(m.is_virtual());
        assert_eq!(m.vftable_offset, -1);
    }

    #[test]
    fn test_onemethod_emit() {
        let m = make_test_onemethod();
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.starts_with('<'));
        assert!(emitted.contains("public"));
        assert!(emitted.contains("0x1011"));
        assert!(emitted.ends_with('>'));
    }

    #[test]
    fn test_onemethod_emit_with_vftable_offset() {
        let m = LfOnemethod::from_parsed(0x0013, 0x1011, 16, "intro".to_string());
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.contains(",16"));
    }

    #[test]
    fn test_onemethod_emit_without_vftable_offset() {
        let m = make_test_onemethod();
        let emitted = m.emit(Bind::NONE);
        // Non-intro methods should not have a comma + offset
        assert!(!emitted.contains(",-1"));
    }

    #[test]
    fn test_onemethod_record_number() {
        let mut m = make_test_onemethod();
        assert!(m.record_number().is_no_type());
        m.set_record_number(RecordNumber::type_record(0x3000));
        assert_eq!(m.record_number().index(), 0x3000);
    }

    #[test]
    fn test_onemethod_display() {
        let m = make_test_onemethod();
        let display = format!("{}", m);
        // The emit() method mirrors Java's AbstractOneMethodMsType which
        // outputs: <attributes: procedureTypeRecordNumber>
        // The name is accessed via name() but not included in emit().
        assert!(display.contains("public"));
        assert!(display.contains("0x1011"));
    }

    #[test]
    fn test_onemethod_attribute() {
        let m = make_test_onemethod();
        let attr = m.attribute();
        assert_eq!(attr.access, super::super::lf_member::AccessProtection::Public);
    }

    #[test]
    fn test_onemethod_access() {
        let m = LfOnemethod::from_parsed(0x0001, 0x1011, -1, "priv".to_string());
        assert_eq!(m.access(), super::super::lf_member::AccessProtection::Private);
    }

    #[test]
    fn test_onemethod_property() {
        let m = LfOnemethod::from_parsed(0x0007, 0x1011, 8, "virt".to_string());
        assert_eq!(m.property(), MemberProperty::Virtual);
    }

    #[test]
    fn test_onemethod_parse_non_virtual() {
        // LF_ONEMETHOD: attributes=0x0003(public), procedureType=0x1011, name="bar"
        let mut data = Vec::new();
        data.extend_from_slice(&0x0003u16.to_le_bytes());   // attributes
        data.extend_from_slice(&0x1011u32.to_le_bytes());   // procedureType
        data.extend_from_slice(b"bar\0");                    // name

        let m = LfOnemethod::parse(&data).unwrap();
        assert_eq!(m.name(), "bar");
        assert_eq!(m.pdb_id(), 0x1511);
        assert_eq!(
            m.procedure_type_record_number(),
            RecordNumber::type_record(0x1011)
        );
        assert_eq!(m.vftable_offset, -1);
        assert!(!m.is_virtual());
    }

    #[test]
    fn test_onemethod_parse_intro_virtual() {
        // LF_ONEMETHOD: attributes=0x0013(public+intro), procedureType=0x2000,
        //               vftableOffset=16, name="introFunc"
        let mut data = Vec::new();
        data.extend_from_slice(&0x0013u16.to_le_bytes());   // attributes (public + intro)
        data.extend_from_slice(&0x2000u32.to_le_bytes());   // procedureType
        data.extend_from_slice(&16u32.to_le_bytes());       // vftableOffset
        data.extend_from_slice(b"introFunc\0");              // name

        let m = LfOnemethod::parse(&data).unwrap();
        assert_eq!(m.name(), "introFunc");
        assert!(m.is_intro_virtual());
        assert!(m.is_virtual());
        assert_eq!(m.vftable_offset, 16);
        assert_eq!(
            m.procedure_type_record_number(),
            RecordNumber::type_record(0x2000)
        );
    }

    #[test]
    fn test_onemethod_parse_intro_pure() {
        // attributes=0x001B(public+intro_pure), procedureType=0x3000, vftableOffset=24
        let mut data = Vec::new();
        data.extend_from_slice(&0x001Bu16.to_le_bytes());
        data.extend_from_slice(&0x3000u32.to_le_bytes());
        data.extend_from_slice(&24u32.to_le_bytes());
        data.extend_from_slice(b"pureIntro\0");

        let m = LfOnemethod::parse(&data).unwrap();
        assert!(m.is_intro_virtual());
        assert!(m.is_pure_virtual());
        assert_eq!(m.vftable_offset, 24);
    }

    #[test]
    fn test_onemethod_parse_pure_non_intro() {
        // attributes=0x0017(public+pure), no vftable offset
        let mut data = Vec::new();
        data.extend_from_slice(&0x0017u16.to_le_bytes());
        data.extend_from_slice(&0x4000u32.to_le_bytes());
        data.extend_from_slice(b"pureFunc\0");

        let m = LfOnemethod::parse(&data).unwrap();
        assert!(m.is_pure_virtual());
        assert!(!m.is_intro_virtual());
        assert_eq!(m.vftable_offset, -1);
    }

    #[test]
    fn test_onemethod_parse_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0003u16.to_le_bytes());
        data.extend_from_slice(&0x1011u32.to_le_bytes());
        data.push(0);

        let m = LfOnemethod::parse(&data).unwrap();
        assert!(m.name().is_empty());
    }

    #[test]
    fn test_onemethod_parse_no_name_bytes() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0003u16.to_le_bytes());
        data.extend_from_slice(&0x1011u32.to_le_bytes());

        let m = LfOnemethod::parse(&data).unwrap();
        assert!(m.name().is_empty());
    }

    #[test]
    fn test_onemethod_parse_too_short() {
        let data = [0u8; 4];
        assert!(LfOnemethod::parse(&data).is_err());
    }

    #[test]
    fn test_onemethod_parse_intro_too_short() {
        // Intro virtual but not enough bytes for vftable offset
        let mut data = Vec::new();
        data.extend_from_slice(&0x0013u16.to_le_bytes()); // intro
        data.extend_from_slice(&0x2000u32.to_le_bytes()); // procedureType
        // Missing vftable offset bytes

        assert!(LfOnemethod::parse(&data).is_err());
    }

    #[test]
    fn test_onemethod_has_valid_procedure_type() {
        let m = make_test_onemethod();
        assert!(m.has_valid_procedure_type());

        let m2 = LfOnemethod::new(
            RecordNumber::NO_TYPE,
            -1,
            super::super::lf_member::MemberAttributes::public_member(),
            "bad".to_string(),
        );
        assert!(!m2.has_valid_procedure_type());
    }

    #[test]
    fn test_onemethod_eq() {
        let m1 = make_test_onemethod();
        let m2 = make_test_onemethod();
        assert_eq!(m1, m2);

        let m3 = LfOnemethod::public_method(0x1011, "different".to_string());
        assert_ne!(m1, m3);
    }

    #[test]
    fn test_onemethod_to_field_list_entry() {
        let m = make_test_onemethod();
        let entry = m.to_field_list_entry();
        match entry {
            super::super::abstract_field_list_ms_type::FieldListEntry::OneMethod {
                type_record,
                vftable_offset,
                access,
                name,
            } => {
                assert_eq!(type_record, RecordNumber::type_record(0x1011));
                assert_eq!(vftable_offset, -1);
                assert_eq!(access, 3); // public
                assert_eq!(name, "bar");
            }
            _ => panic!("Expected OneMethod variant"),
        }
    }

    #[test]
    fn test_onemethod_to_field_list_entry_intro() {
        let m = LfOnemethod::from_parsed(0x0013, 0x2000, 16, "intro".to_string());
        let entry = m.to_field_list_entry();
        match entry {
            super::super::abstract_field_list_ms_type::FieldListEntry::OneMethod {
                type_record,
                vftable_offset,
                ..
            } => {
                assert_eq!(type_record, RecordNumber::type_record(0x2000));
                assert_eq!(vftable_offset, 16);
            }
            _ => panic!("Expected OneMethod variant"),
        }
    }

    #[test]
    fn test_onemethod_default() {
        let m = LfOnemethod::default();
        assert!(m.name().is_empty());
        assert!(m.record_number().is_no_type());
        assert_eq!(m.vftable_offset, -1);
    }
}
