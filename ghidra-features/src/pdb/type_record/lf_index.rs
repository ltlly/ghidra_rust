//! LF_INDEX -- concrete Index type record.
//!
//! Ports Ghidra's `IndexMsType` (PDB_ID = 0x1404) Java class.
//!
//! Represents an indirect type reference in the PDB type stream. An index
//! record acts as a forwarding pointer to another type record, allowing the
//! type stream to reference types beyond the 16-bit type index range.
//!
//! # Binary Layout (LF_INDEX / 0x1404)
//!
//! ```text
//! +0  u16   padding              2 bytes of discarded padding
//! +2  u32   referencedRecord     Type index of the referenced record
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

/// Concrete PDB index type record (`LF_INDEX`).
///
/// This is the Rust equivalent of Ghidra's `IndexMsType`. It stores a
/// reference to another type record, acting as a forwarding pointer for
/// indirect type resolution. The Java implementation discards 2 bytes of
/// padding before reading the referenced record number; this struct
/// optionally preserves that padding for round-trip fidelity.
#[derive(Debug, Clone)]
pub struct LfIndex {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// The 2-byte padding value discarded during parsing.
    pub padding: u16,
    /// Record number of the referenced type.
    pub referenced_record_number: RecordNumber,
}

impl LfIndex {
    /// PDB ID for the 16-bit variant (`LF_INDEX_16` / `Index16MsType`).
    pub const PDB_ID_16: u32 = 0x0405;

    /// Create a new index type record.
    pub fn new(referenced_record_number: RecordNumber) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            padding: 0,
            referenced_record_number,
        }
    }

    /// Create a new index type record with explicit padding value.
    pub fn with_padding(padding: u16, referenced_record_number: RecordNumber) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            padding,
            referenced_record_number,
        }
    }

    /// Create from a raw parsed type index.
    pub fn from_parsed(referenced_type_index: u32) -> Self {
        Self::new(RecordNumber::type_record(referenced_type_index))
    }

    /// Create from raw parsed field values including padding.
    pub fn from_parsed_full(padding: u16, referenced_type_index: u32) -> Self {
        Self::with_padding(
            padding,
            RecordNumber::type_record(referenced_type_index),
        )
    }

    /// Get the record number of the referenced type.
    pub fn referenced(&self) -> RecordNumber {
        self.referenced_record_number
    }

    /// Whether this index record has a valid (non-NO_TYPE) reference.
    pub fn is_valid_reference(&self) -> bool {
        !self.referenced_record_number.is_no_type()
    }

    /// Whether this index record points to itself (circular reference).
    ///
    /// This is a degenerate case that should not occur in well-formed PDBs.
    pub fn is_self_referential(&self) -> bool {
        self.record_number != RecordNumber::NO_TYPE
            && self.record_number == self.referenced_record_number
    }

    /// The total binary size of this record in the PDB stream.
    ///
    /// Always 6 bytes: 2 bytes padding + 4 bytes record number.
    pub fn total_record_size(&self) -> usize {
        6
    }

    /// Convert this index record into a [`FieldListEntry::Index`].
    ///
    /// This is the Rust equivalent of Java's `MsTypeField` interface
    /// implementation on `AbstractIndexMsType`. It allows `LfIndex` to be
    /// used as a continuation entry within a field list.
    pub fn to_field_list_entry(&self) -> super::abstract_field_list_ms_type::FieldListEntry {
        super::abstract_field_list_ms_type::FieldListEntry::Index {
            type_record: self.referenced_record_number,
        }
    }

    /// Parse an `LF_INDEX` record (32-bit variant, PDB_ID 0x1404) from raw bytes.
    ///
    /// Mirrors the Java `IndexMsType(AbstractPdb, PdbByteReader)` constructor.
    /// The `data` slice starts after the 2-byte leaf ID.
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u16   padding              2 bytes of discarded padding
    /// +2  u32   referencedRecord     Type index of the referenced record
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 6 {
            return Err(format!(
                "LF_INDEX payload too short: need >= 6 bytes, got {}",
                data.len()
            ));
        }
        let padding = u16::from_le_bytes([data[0], data[1]]);
        let referenced = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        Ok(Self::from_parsed_full(padding, referenced))
    }

    /// Parse a 16-bit variant `LF_INDEX` record (PDB_ID 0x0405) from raw bytes.
    ///
    /// Uses a 16-bit (2-byte) referenced record number instead of 32-bit.
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u16   padding              2 bytes of discarded padding
    /// +2  u16   referencedRecord     Type index of the referenced record
    /// ```
    pub fn parse_16(data: &[u8]) -> Result<Self, String> {
        if data.len() < 4 {
            return Err(format!(
                "LF_INDEX_16 payload too short: need >= 4 bytes, got {}",
                data.len()
            ));
        }
        let padding = u16::from_le_bytes([data[0], data[1]]);
        let referenced = u16::from_le_bytes([data[2], data[3]]) as u32;
        Ok(Self::from_parsed_full(padding, referenced))
    }
}

impl AbstractMsType for LfIndex {
    fn pdb_id(&self) -> u32 {
        0x1404 // LF_INDEX
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java:
        //   builder.append(String.format("index: 0x%08x",
        //     referencedRecordNumber.getNumber()));
        format!(
            "index: 0x{:08x}",
            self.referenced_record_number.index()
        )
    }
}

impl fmt::Display for LfIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_index() -> LfIndex {
        LfIndex::new(RecordNumber::type_record(0x3000))
    }

    #[test]
    fn test_index_basic() {
        let idx = make_test_index();
        assert_eq!(idx.pdb_id(), 0x1404);
        assert_eq!(
            idx.referenced_record_number,
            RecordNumber::type_record(0x3000)
        );
    }

    #[test]
    fn test_index_from_parsed() {
        let idx = LfIndex::from_parsed(0x5000);
        assert_eq!(idx.referenced(), RecordNumber::type_record(0x5000));
    }

    #[test]
    fn test_index_from_parsed_zero() {
        let idx = LfIndex::from_parsed(0);
        assert_eq!(idx.referenced(), RecordNumber::type_record(0));
    }

    #[test]
    fn test_index_accessors() {
        let idx = make_test_index();
        assert_eq!(idx.referenced(), RecordNumber::type_record(0x3000));
    }

    #[test]
    fn test_index_emit() {
        let idx = make_test_index();
        let emitted = idx.emit(Bind::NONE);
        assert!(emitted.contains("index:"));
        assert!(emitted.contains("0x00003000"));
    }

    #[test]
    fn test_index_emit_format() {
        let idx = LfIndex::from_parsed(0xABCD);
        let emitted = idx.emit(Bind::NONE);
        assert!(emitted.contains("0x0000abcd"));
    }

    #[test]
    fn test_index_record_number() {
        let mut idx = make_test_index();
        assert!(idx.record_number().is_no_type());
        idx.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(idx.record_number().index(), 0x2000);
    }

    #[test]
    fn test_index_display() {
        let idx = make_test_index();
        let display = format!("{}", idx);
        assert!(display.contains("index"));
        assert!(display.contains("0x00003000"));
    }

    #[test]
    fn test_index_with_padding() {
        let idx = LfIndex::with_padding(0xABCD, RecordNumber::type_record(0x5000));
        assert_eq!(idx.padding, 0xABCD);
        assert_eq!(idx.referenced(), RecordNumber::type_record(0x5000));
    }

    #[test]
    fn test_index_from_parsed_full() {
        let idx = LfIndex::from_parsed_full(0x1234, 0x6000);
        assert_eq!(idx.padding, 0x1234);
        assert_eq!(idx.referenced(), RecordNumber::type_record(0x6000));
    }

    #[test]
    fn test_index_is_valid_reference_true() {
        let idx = make_test_index();
        assert!(idx.is_valid_reference());
    }

    #[test]
    fn test_index_is_valid_reference_false() {
        let idx = LfIndex::new(RecordNumber::NO_TYPE);
        assert!(!idx.is_valid_reference());
    }

    #[test]
    fn test_index_is_self_referential_false() {
        let idx = make_test_index();
        // record_number is NO_TYPE by default, referenced is 0x3000
        assert!(!idx.is_self_referential());
    }

    #[test]
    fn test_index_is_self_referential_true() {
        let mut idx = LfIndex::new(RecordNumber::type_record(0x3000));
        idx.set_record_number(RecordNumber::type_record(0x3000));
        assert!(idx.is_self_referential());
    }

    #[test]
    fn test_index_is_self_referential_different() {
        let mut idx = LfIndex::new(RecordNumber::type_record(0x4000));
        idx.set_record_number(RecordNumber::type_record(0x3000));
        assert!(!idx.is_self_referential());
    }

    #[test]
    fn test_index_total_record_size() {
        let idx = make_test_index();
        assert_eq!(idx.total_record_size(), 6);
    }

    #[test]
    fn test_index_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000u16.to_le_bytes()); // padding
        data.extend_from_slice(&0x3000u32.to_le_bytes()); // referencedRecord

        let idx = LfIndex::parse(&data).unwrap();
        assert_eq!(idx.pdb_id(), 0x1404);
        assert_eq!(idx.referenced(), RecordNumber::type_record(0x3000));
        assert_eq!(idx.padding, 0);
    }

    #[test]
    fn test_index_parse_with_padding() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xABCDu16.to_le_bytes()); // non-zero padding
        data.extend_from_slice(&0x5000u32.to_le_bytes()); // referencedRecord

        let idx = LfIndex::parse(&data).unwrap();
        assert_eq!(idx.padding, 0xABCD);
        assert_eq!(idx.referenced(), RecordNumber::type_record(0x5000));
    }

    #[test]
    fn test_index_parse_too_short() {
        let data = [0u8; 4];
        assert!(LfIndex::parse(&data).is_err());
    }

    #[test]
    fn test_index_parse_16() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000u16.to_le_bytes()); // padding
        data.extend_from_slice(&0x6000u16.to_le_bytes()); // 16-bit referenced

        let idx = LfIndex::parse_16(&data).unwrap();
        assert_eq!(idx.pdb_id(), 0x1404);
        assert_eq!(idx.referenced(), RecordNumber::type_record(0x6000));
        assert_eq!(idx.padding, 0);
    }

    #[test]
    fn test_index_parse_16_too_short() {
        let data = [0u8; 2];
        assert!(LfIndex::parse_16(&data).is_err());
    }

    #[test]
    fn test_index_parse_roundtrip() {
        let idx = LfIndex::with_padding(0x1234, RecordNumber::type_record(0x5000));
        let mut data = Vec::new();
        data.extend_from_slice(&idx.padding.to_le_bytes());
        data.extend_from_slice(&idx.referenced_record_number.index().to_le_bytes());

        let idx2 = LfIndex::parse(&data).unwrap();
        assert_eq!(idx2.padding, idx.padding);
        assert_eq!(idx2.referenced(), idx.referenced());
    }

    #[test]
    fn test_index_pdb_id_16() {
        assert_eq!(LfIndex::PDB_ID_16, 0x0405);
    }

    #[test]
    fn test_index_to_field_list_entry() {
        let idx = LfIndex::new(RecordNumber::type_record(0x3000));
        let entry = idx.to_field_list_entry();
        match entry {
            super::super::abstract_field_list_ms_type::FieldListEntry::Index { type_record } => {
                assert_eq!(type_record, RecordNumber::type_record(0x3000));
            }
            _ => panic!("Expected FieldListEntry::Index"),
        }
    }

    #[test]
    fn test_index_to_field_list_entry_no_type() {
        let idx = LfIndex::new(RecordNumber::NO_TYPE);
        let entry = idx.to_field_list_entry();
        match entry {
            super::super::abstract_field_list_ms_type::FieldListEntry::Index { type_record } => {
                assert_eq!(type_record, RecordNumber::NO_TYPE);
            }
            _ => panic!("Expected FieldListEntry::Index"),
        }
    }
}
