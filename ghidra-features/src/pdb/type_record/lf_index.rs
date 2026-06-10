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
/// indirect type resolution.
#[derive(Debug, Clone)]
pub struct LfIndex {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the referenced type.
    pub referenced_record_number: RecordNumber,
}

impl LfIndex {
    /// Create a new index type record.
    pub fn new(referenced_record_number: RecordNumber) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            referenced_record_number,
        }
    }

    /// Create from a raw parsed type index.
    pub fn from_parsed(referenced_type_index: u32) -> Self {
        Self::new(RecordNumber::type_record(referenced_type_index))
    }

    /// Get the record number of the referenced type.
    pub fn referenced(&self) -> RecordNumber {
        self.referenced_record_number
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
}
