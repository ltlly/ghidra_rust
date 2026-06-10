//! LF_VFUNCTAB -- concrete Virtual Function Table Pointer type record.
//!
//! Ports Ghidra's `VirtualFunctionTablePointerMsType` (PDB_ID = 0x1409)
//! Java class.
//!
//! Represents a virtual function table (vftable) pointer within a composite
//! type (struct/class/union) in the PDB type stream. This is a leaf record
//! that appears inside an `LF_FIELDLIST`. It indicates that the composite
//! contains a vftable pointer at the specified location.
//!
//! # Binary Layout (LF_VFUNCTAB / 0x1409)
//!
//! ```text
//! +0  u16   padding           2 bytes of documented padding
//! +2  u32   vftableType       Type index of the vftable type
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::{MsTypeField, RecordNumber};
use crate::pdb::pdb_byte_reader::PdbByteReader;
use crate::pdb::pdb_exception::PdbException;

/// Concrete PDB virtual function table pointer type record (`LF_VFUNCTAB`).
///
/// This is the Rust equivalent of Ghidra's `VirtualFunctionTablePointerMsType`.
/// It stores the record number of the vftable type. The vftable type itself
/// is represented by `LF_VTSHAPE` records.
///
/// Note: Despite the name `LF_VFUNCTAB`, this record does not contain the
/// actual virtual function table. It represents a *pointer* to a vftable
/// that is embedded within the object layout. The actual vftable entries
/// are described by the referenced type record.
///
/// Corresponds to the Java `VirtualFunctionTablePointerMsType` class and
/// its parent `AbstractVirtualFunctionTablePointerMsType`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfVfunctab {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the vftable pointer type.
    pub vftable_type_record_number: RecordNumber,
}

impl LfVfunctab {
    /// Create a new vftable pointer type record.
    pub fn new(vftable_type_record_number: RecordNumber) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            vftable_type_record_number,
        }
    }

    /// Create from a raw type index.
    pub fn from_parsed(vftable_type_index: u32) -> Self {
        Self::new(RecordNumber::type_record(vftable_type_index))
    }

    /// Parse an `LF_VFUNCTAB` record from raw bytes (payload after leaf ID).
    ///
    /// Mirrors the Java `VirtualFunctionTablePointerMsType(AbstractPdb,
    /// PdbByteReader)` constructor. The `data` slice should start at the
    /// `padding` field (after the 2-byte leaf ID).
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u16   padding           2 bytes of documented padding (skipped)
    /// +2  u32   vftableType       Type index of the vftable type
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 6 {
            return Err(format!(
                "LF_VFUNCTAB payload too short: need >= 6 bytes, got {}",
                data.len()
            ));
        }
        // Skip 2 bytes of padding at offset 0.
        let vftable_ti = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        Ok(Self::from_parsed(vftable_ti))
    }

    /// Parse an `LF_VFUNCTAB` record from a [`PdbByteReader`].
    ///
    /// Mirrors the Java `VirtualFunctionTablePointerMsType(AbstractPdb, PdbByteReader)`
    /// constructor. Skips 2 bytes of padding, reads the vftable type record number
    /// (32-bit), then aligns to 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PdbException`] if the reader does not have enough data.
    pub fn parse_from_reader(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        reader.skip(2)?; // padding
        let vftable_ti = reader.read_u32()?;
        reader.align(4);
        Ok(Self::from_parsed(vftable_ti))
    }

    /// Get the record number of the vftable pointer type.
    ///
    /// Mirrors Java `AbstractVirtualFunctionTablePointerMsType.getPointerTypeRecordNumber()`.
    pub fn pointer_type_record_number(&self) -> RecordNumber {
        self.vftable_type_record_number
    }

    /// Get the record number of the vftable pointer type (alias).
    ///
    /// Alias for [`pointer_type_record_number()`](Self::pointer_type_record_number).
    pub fn get_pointer_type_record_number(&self) -> RecordNumber {
        self.vftable_type_record_number
    }

    /// Get the pointer offset.
    ///
    /// Mirrors Java `AbstractVirtualFunctionTablePointerMsType.getOffset()`.
    /// Always returns 0 for the base `LF_VFUNCTAB` record. Subclasses
    /// (like `VirtualFunctionTablePointerWithOffsetMsType`) override this.
    pub fn offset(&self) -> u32 {
        0
    }

    /// Whether the vftable type record number references a valid type.
    pub fn has_valid_vftable_type(&self) -> bool {
        !self.vftable_type_record_number.is_no_type()
    }

    /// Convert this vftable pointer into a [`FieldListEntry::VfTablePointer`].
    ///
    /// This is useful when constructing or manipulating field lists
    /// programmatically.
    pub fn to_field_list_entry(&self) -> super::abstract_field_list_ms_type::FieldListEntry {
        super::abstract_field_list_ms_type::FieldListEntry::VfTablePointer {
            type_record: self.vftable_type_record_number,
        }
    }
}

impl AbstractMsType for LfVfunctab {
    fn name(&self) -> &str {
        ""
    }

    fn pdb_id(&self) -> u32 {
        0x1409 // LF_VFUNCTAB
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java:
        //   builder.append("VFTablePtr: ");
        //   builder.append(pdb.getTypeRecord(pointerTypeRecordNumber));
        let mut result = String::new();
        result.push_str("VFTablePtr: ");
        result.push_str(&self.vftable_type_record_number.to_string());
        result
    }
}

impl MsTypeField for LfVfunctab {}

impl Default for LfVfunctab {
    fn default() -> Self {
        Self::new(RecordNumber::NO_TYPE)
    }
}

impl fmt::Display for LfVfunctab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

/// LF_VFUNCOFF -- concrete Virtual Function Offset type record.
///
/// Ports Ghidra's `VirtualFunctionTablePointerWithOffsetMsType`
/// (PDB_ID = 0x140C) Java class.
///
/// Represents a virtual function table pointer with an explicit byte offset
/// within the composite. Unlike [`LfVfunctab`], this record carries an
/// offset field that indicates where the vftable pointer lives in the
/// object layout.
///
/// # Binary Layout (LF_VFUNCOFF / 0x140C)
///
/// ```text
/// +0  u32   vftableType       Type index of the vftable type
/// +4  u32   offsetInVFTable   Byte offset in the vftable
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfVfuncoff {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the vftable type.
    pub vftable_type_record_number: RecordNumber,
    /// Byte offset of the virtual function in the vftable.
    pub offset_in_vftable: u32,
}

impl LfVfuncoff {
    /// Create a new vfuncoff type record.
    pub fn new(vftable_type_record_number: RecordNumber, offset_in_vftable: u32) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            vftable_type_record_number,
            offset_in_vftable,
        }
    }

    /// Create from raw parsed field values.
    pub fn from_parsed(vftable_type_index: u32, offset_in_vftable: u32) -> Self {
        Self::new(RecordNumber::type_record(vftable_type_index), offset_in_vftable)
    }

    /// Parse an `LF_VFUNCOFF` record from raw bytes (payload after leaf ID).
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u32   vftableType       Type index of the vftable type
    /// +4  u32   offsetInVFTable   Byte offset in the vftable
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 8 {
            return Err(format!(
                "LF_VFUNCOFF payload too short: need >= 8 bytes, got {}",
                data.len()
            ));
        }
        let vftable_ti = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        Ok(Self::from_parsed(vftable_ti, offset))
    }

    /// Parse an `LF_VFUNCOFF` record from a [`PdbByteReader`].
    ///
    /// Mirrors the Java `VirtualFunctionTablePointerWithOffsetMsType(AbstractPdb,
    /// PdbByteReader)` constructor. Reads the vftable type record number (32-bit)
    /// and the offset in the vftable (i32).
    ///
    /// # Errors
    ///
    /// Returns [`PdbException`] if the reader does not have enough data.
    pub fn parse_from_reader(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let vftable_ti = reader.read_u32()?;
        let offset = reader.read_i32()? as u32;
        Ok(Self::from_parsed(vftable_ti, offset))
    }

    /// Get the record number of the vftable type.
    pub fn pointer_type_record_number(&self) -> RecordNumber {
        self.vftable_type_record_number
    }

    /// Get the record number of the vftable type (alias).
    ///
    /// Alias for [`pointer_type_record_number()`](Self::pointer_type_record_number).
    pub fn get_pointer_type_record_number(&self) -> RecordNumber {
        self.vftable_type_record_number
    }

    /// Get the byte offset in the vftable.
    pub fn offset(&self) -> u32 {
        self.offset_in_vftable
    }

    /// Whether the vftable type record number references a valid type.
    pub fn has_valid_vftable_type(&self) -> bool {
        !self.vftable_type_record_number.is_no_type()
    }

    /// Convert this vfuncoff into a [`FieldListEntry::VfFuncOffset`].
    pub fn to_field_list_entry(&self) -> super::abstract_field_list_ms_type::FieldListEntry {
        super::abstract_field_list_ms_type::FieldListEntry::VfFuncOffset {
            type_record: self.vftable_type_record_number,
            vftable_offset: self.offset_in_vftable,
        }
    }
}

impl AbstractMsType for LfVfuncoff {
    fn name(&self) -> &str {
        ""
    }

    fn pdb_id(&self) -> u32 {
        0x140C // LF_VFUNCOFF
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java AbstractVirtualFunctionTablePointerWithOffsetMsType.emit():
        //   builder.append("VFTablePtr<off=");
        //   builder.append(offset);
        //   builder.append(">: ");
        //   builder.append(pdb.getTypeRecord(pointerTypeRecordNumber));
        let mut result = String::new();
        result.push_str("VFTablePtr<off=");
        result.push_str(&self.offset_in_vftable.to_string());
        result.push_str(">: ");
        result.push_str(&self.vftable_type_record_number.to_string());
        result
    }
}

impl MsTypeField for LfVfuncoff {}

impl fmt::Display for LfVfuncoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_vfunctab() -> LfVfunctab {
        LfVfunctab::new(RecordNumber::type_record(0x3001))
    }

    #[test]
    fn test_vfunctab_basic() {
        let vt = make_test_vfunctab();
        assert_eq!(vt.pdb_id(), 0x1409);
        assert_eq!(
            vt.vftable_type_record_number,
            RecordNumber::type_record(0x3001)
        );
    }

    #[test]
    fn test_vfunctab_from_parsed() {
        let vt = LfVfunctab::from_parsed(0x4001);
        assert_eq!(
            vt.vftable_type_record_number,
            RecordNumber::type_record(0x4001)
        );
    }

    #[test]
    fn test_vfunctab_emit() {
        let vt = make_test_vfunctab();
        let emitted = vt.emit(Bind::NONE);
        assert!(emitted.contains("VFTablePtr:"));
        assert!(emitted.contains("0x3001"));
    }

    #[test]
    fn test_vfunctab_emit_format() {
        let vt = LfVfunctab::from_parsed(0x4001);
        let emitted = vt.emit(Bind::NONE);
        assert!(emitted.starts_with("VFTablePtr: "));
        assert!(emitted.contains("0x4001"));
    }

    #[test]
    fn test_vfunctab_record_number() {
        let mut vt = make_test_vfunctab();
        assert!(vt.record_number().is_no_type());
        vt.set_record_number(RecordNumber::type_record(0x5000));
        assert_eq!(vt.record_number().index(), 0x5000);
    }

    #[test]
    fn test_vfunctab_display() {
        let vt = make_test_vfunctab();
        let display = format!("{}", vt);
        assert!(display.contains("VFTablePtr"));
        assert!(display.contains("0x3001"));
    }

    #[test]
    fn test_vfunctab_name_is_empty() {
        let vt = make_test_vfunctab();
        assert_eq!(vt.name(), "");
    }

    #[test]
    fn test_vfunctab_pointer_type_record_number() {
        let vt = LfVfunctab::new(RecordNumber::type_record(0x6000));
        assert_eq!(
            vt.pointer_type_record_number(),
            RecordNumber::type_record(0x6000)
        );
    }

    #[test]
    fn test_vfunctab_from_parsed_zero() {
        let vt = LfVfunctab::from_parsed(0);
        assert_eq!(
            vt.vftable_type_record_number,
            RecordNumber::type_record(0)
        );
    }

    #[test]
    fn test_vfunctab_parse() {
        // LF_VFUNCTAB payload: padding=0x0000, vftableType=0x3001
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000u16.to_le_bytes()); // padding
        data.extend_from_slice(&0x3001u32.to_le_bytes()); // vftableType

        let vt = LfVfunctab::parse(&data).unwrap();
        assert_eq!(vt.pdb_id(), 0x1409);
        assert_eq!(
            vt.vftable_type_record_number,
            RecordNumber::type_record(0x3001)
        );
    }

    #[test]
    fn test_vfunctab_parse_with_nonzero_padding() {
        // The padding field should be skipped regardless of its value.
        let mut data = Vec::new();
        data.extend_from_slice(&0xABCDu16.to_le_bytes()); // non-zero padding
        data.extend_from_slice(&0x4001u32.to_le_bytes()); // vftableType

        let vt = LfVfunctab::parse(&data).unwrap();
        assert_eq!(
            vt.vftable_type_record_number,
            RecordNumber::type_record(0x4001)
        );
    }

    #[test]
    fn test_vfunctab_parse_too_short() {
        let data = [0u8; 4];
        assert!(LfVfunctab::parse(&data).is_err());
    }

    #[test]
    fn test_vfunctab_offset() {
        // Base LF_VFUNCTAB always returns offset 0.
        let vt = make_test_vfunctab();
        assert_eq!(vt.offset(), 0);
    }

    #[test]
    fn test_vfunctab_has_valid_vftable_type() {
        let vt = make_test_vfunctab();
        assert!(vt.has_valid_vftable_type());

        let vt2 = LfVfunctab::new(RecordNumber::NO_TYPE);
        assert!(!vt2.has_valid_vftable_type());
    }

    #[test]
    fn test_vfunctab_eq() {
        let vt1 = make_test_vfunctab();
        let vt2 = make_test_vfunctab();
        assert_eq!(vt1, vt2);

        let vt3 = LfVfunctab::new(RecordNumber::type_record(0x4000));
        assert_ne!(vt1, vt3);
    }

    #[test]
    fn test_vfunctab_to_field_list_entry() {
        let vt = make_test_vfunctab();
        let entry = vt.to_field_list_entry();
        match entry {
            super::super::abstract_field_list_ms_type::FieldListEntry::VfTablePointer {
                type_record,
            } => {
                assert_eq!(type_record, RecordNumber::type_record(0x3001));
            }
            _ => panic!("Expected VfTablePointer variant"),
        }
    }

    #[test]
    fn test_vfunctab_default() {
        let vt = LfVfunctab::default();
        assert!(vt.record_number().is_no_type());
        assert!(!vt.has_valid_vftable_type());
    }

    // =========================================================================
    // LfVfuncoff tests
    // =========================================================================

    #[test]
    fn test_vfuncoff_basic() {
        let vo = LfVfuncoff::new(RecordNumber::type_record(0x3001), 16);
        assert_eq!(vo.pdb_id(), 0x140C);
        assert_eq!(
            vo.vftable_type_record_number,
            RecordNumber::type_record(0x3001)
        );
        assert_eq!(vo.offset_in_vftable, 16);
    }

    #[test]
    fn test_vfuncoff_from_parsed() {
        let vo = LfVfuncoff::from_parsed(0x4001, 24);
        assert_eq!(
            vo.vftable_type_record_number,
            RecordNumber::type_record(0x4001)
        );
        assert_eq!(vo.offset(), 24);
    }

    #[test]
    fn test_vfuncoff_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x3001u32.to_le_bytes()); // vftableType
        data.extend_from_slice(&16u32.to_le_bytes());     // offsetInVFTable

        let vo = LfVfuncoff::parse(&data).unwrap();
        assert_eq!(vo.pdb_id(), 0x140C);
        assert_eq!(
            vo.vftable_type_record_number,
            RecordNumber::type_record(0x3001)
        );
        assert_eq!(vo.offset(), 16);
    }

    #[test]
    fn test_vfuncoff_parse_too_short() {
        let data = [0u8; 6];
        assert!(LfVfuncoff::parse(&data).is_err());
    }

    #[test]
    fn test_vfuncoff_emit() {
        let vo = LfVfuncoff::from_parsed(0x3001, 16);
        let emitted = vo.emit(Bind::NONE);
        // Format: "VFTablePtr<off=16>: 0x3001"
        assert!(emitted.contains("VFTablePtr<off="));
        assert!(emitted.contains("0x3001"));
        assert!(emitted.contains("16"));
    }

    #[test]
    fn test_vfuncoff_emit_format() {
        let vo = LfVfuncoff::from_parsed(0x4001, 24);
        let emitted = vo.emit(Bind::NONE);
        // Format: "VFTablePtr<off=24>: 0x4001"
        assert!(emitted.starts_with("VFTablePtr<off=24>: "));
        assert!(emitted.contains("0x4001"));
    }

    #[test]
    fn test_vfuncoff_record_number() {
        let mut vo = LfVfuncoff::new(RecordNumber::type_record(0x3001), 16);
        assert!(vo.record_number().is_no_type());
        vo.set_record_number(RecordNumber::type_record(0x5000));
        assert_eq!(vo.record_number().index(), 0x5000);
    }

    #[test]
    fn test_vfuncoff_pointer_type_record_number() {
        let vo = LfVfuncoff::new(RecordNumber::type_record(0x6000), 0);
        assert_eq!(
            vo.pointer_type_record_number(),
            RecordNumber::type_record(0x6000)
        );
    }

    #[test]
    fn test_vfuncoff_has_valid_vftable_type() {
        let vo = LfVfuncoff::new(RecordNumber::type_record(0x3001), 16);
        assert!(vo.has_valid_vftable_type());

        let vo2 = LfVfuncoff::new(RecordNumber::NO_TYPE, 0);
        assert!(!vo2.has_valid_vftable_type());
    }

    #[test]
    fn test_vfuncoff_to_field_list_entry() {
        let vo = LfVfuncoff::from_parsed(0x3001, 16);
        let entry = vo.to_field_list_entry();
        match entry {
            super::super::abstract_field_list_ms_type::FieldListEntry::VfFuncOffset {
                type_record,
                vftable_offset,
            } => {
                assert_eq!(type_record, RecordNumber::type_record(0x3001));
                assert_eq!(vftable_offset, 16);
            }
            _ => panic!("Expected VfFuncOffset variant"),
        }
    }

    #[test]
    fn test_vfuncoff_name_is_empty() {
        let vo = LfVfuncoff::new(RecordNumber::type_record(0x3001), 16);
        assert_eq!(vo.name(), "");
    }

    #[test]
    fn test_vfuncoff_display() {
        let vo = LfVfuncoff::from_parsed(0x3001, 16);
        let display = format!("{}", vo);
        assert!(display.contains("VFTablePtr<off=16>"));
        assert!(display.contains("0x3001"));
    }

    #[test]
    fn test_vfuncoff_eq() {
        let vo1 = LfVfuncoff::new(RecordNumber::type_record(0x3001), 16);
        let vo2 = LfVfuncoff::new(RecordNumber::type_record(0x3001), 16);
        assert_eq!(vo1, vo2);

        let vo3 = LfVfuncoff::new(RecordNumber::type_record(0x3001), 24);
        assert_ne!(vo1, vo3);
    }

    // =========================================================================
    // parse_from_reader tests
    // =========================================================================

    #[test]
    fn test_vfunctab_parse_from_reader() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000u16.to_le_bytes()); // padding
        data.extend_from_slice(&0x3001u32.to_le_bytes()); // vftableType

        let mut reader = PdbByteReader::new(&data);
        let vt = LfVfunctab::parse_from_reader(&mut reader).unwrap();
        assert_eq!(vt.pdb_id(), 0x1409);
        assert_eq!(
            vt.vftable_type_record_number,
            RecordNumber::type_record(0x3001)
        );
    }

    #[test]
    fn test_vfunctab_parse_from_reader_too_short() {
        let data = [0u8; 4];
        let mut reader = PdbByteReader::new(&data);
        assert!(LfVfunctab::parse_from_reader(&mut reader).is_err());
    }

    #[test]
    fn test_vfuncoff_parse_from_reader() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x3001u32.to_le_bytes()); // vftableType
        data.extend_from_slice(&16i32.to_le_bytes());     // offsetInVFTable

        let mut reader = PdbByteReader::new(&data);
        let vo = LfVfuncoff::parse_from_reader(&mut reader).unwrap();
        assert_eq!(vo.pdb_id(), 0x140C);
        assert_eq!(
            vo.vftable_type_record_number,
            RecordNumber::type_record(0x3001)
        );
        assert_eq!(vo.offset(), 16);
    }

    #[test]
    fn test_vfuncoff_parse_from_reader_too_short() {
        let data = [0u8; 6];
        let mut reader = PdbByteReader::new(&data);
        assert!(LfVfuncoff::parse_from_reader(&mut reader).is_err());
    }

    // =========================================================================
    // Alias and clone tests
    // =========================================================================

    #[test]
    fn test_vfunctab_get_pointer_type_record_number_alias() {
        let vt = make_test_vfunctab();
        assert_eq!(
            vt.get_pointer_type_record_number(),
            vt.pointer_type_record_number()
        );
        assert_eq!(
            vt.get_pointer_type_record_number(),
            RecordNumber::type_record(0x3001)
        );
    }

    #[test]
    fn test_vfunctab_clone() {
        let vt = make_test_vfunctab();
        let vt2 = vt.clone();
        assert_eq!(vt, vt2);
    }

    #[test]
    fn test_vfuncoff_get_pointer_type_record_number_alias() {
        let vo = LfVfuncoff::new(RecordNumber::type_record(0x3001), 16);
        assert_eq!(
            vo.get_pointer_type_record_number(),
            vo.pointer_type_record_number()
        );
    }

    #[test]
    fn test_vfuncoff_clone() {
        let vo = LfVfuncoff::new(RecordNumber::type_record(0x3001), 16);
        let vo2 = vo.clone();
        assert_eq!(vo, vo2);
    }

    #[test]
    fn test_vfuncoff_default() {
        let vo = LfVfuncoff {
            record_number: RecordNumber::NO_TYPE,
            vftable_type_record_number: RecordNumber::NO_TYPE,
            offset_in_vftable: 0,
        };
        assert!(!vo.has_valid_vftable_type());
        assert_eq!(vo.offset(), 0);
        assert_eq!(vo.name(), "");
    }

    #[test]
    fn test_vfunctab_emit_with_different_ids() {
        // Test emit with various type record IDs
        for id in [0x1000u32, 0x2000, 0x7FFF, 0x8000, 0xFFFF] {
            let vt = LfVfunctab::from_parsed(id);
            let emitted = vt.emit(Bind::NONE);
            assert!(emitted.contains("VFTablePtr:"));
            assert!(emitted.contains(&format!("0x{:04X}", id)));
        }
    }

    #[test]
    fn test_vfuncoff_emit_with_various_offsets() {
        for offset in [0u32, 4, 8, 16, 100, 0xFFFF] {
            let vo = LfVfuncoff::from_parsed(0x3001, offset);
            let emitted = vo.emit(Bind::NONE);
            assert!(emitted.contains(&format!("off={}", offset)));
            assert!(emitted.contains("0x3001"));
        }
    }
}
