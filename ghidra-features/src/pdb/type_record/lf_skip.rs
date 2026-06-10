//! LF_SKIP -- concrete Skip type record.
//!
//! Ports Ghidra's `SkipMsType` (PDB_ID = 0x1200) Java class.
//!
//! Represents a skip record in the PDB type stream. A skip record is used
//! to mark unused/invalid type indices in the TPI stream. It contains a
//! reference to the next valid type record, allowing parsers to skip over
//! the gap.
//!
//! # Binary Layout (LF_SKIP / 0x1200)
//!
//! ```text
//! +0  u32   nextValidRecordNumber   Type index of the next valid record
//! +4  byte[] remainingBytes         Padding/filler data for the skipped region
//!     ...  padding                  Align to 4-byte boundary
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

/// Concrete PDB skip type record (`LF_SKIP`).
///
/// This is the Rust equivalent of Ghidra's `SkipMsType`. It stores the
/// record number of the next valid type record and the length of the
/// skip region.
#[derive(Debug, Clone)]
pub struct LfSkip {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the next valid type record in the stream.
    pub next_valid_record_number: RecordNumber,
    /// Length of the skip region (remaining bytes after the next-valid pointer).
    pub skip_length: u32,
}

impl LfSkip {
    /// Create a new skip type record.
    pub fn new(next_valid_record_number: RecordNumber, skip_length: u32) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            next_valid_record_number,
            skip_length,
        }
    }

    /// Create from raw parsed field values.
    ///
    /// `next_valid_type_index` is the raw type index of the next valid record.
    /// `remaining_length` is the number of remaining bytes in the record body.
    pub fn from_parsed(next_valid_type_index: u32, remaining_length: u32) -> Self {
        Self::new(
            RecordNumber::type_record(next_valid_type_index),
            remaining_length,
        )
    }

    /// Get the record number of the next valid type.
    pub fn next_valid(&self) -> RecordNumber {
        self.next_valid_record_number
    }

    /// Get the skip region length in bytes.
    pub fn length(&self) -> u32 {
        self.skip_length
    }
}

impl AbstractMsType for LfSkip {
    fn pdb_id(&self) -> u32 {
        0x1200 // LF_SKIP
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java:
        //   builder.append(String.format(
        //     "Skip Record, nextValidTypeIndex = 0x%x, Length = 0x%x",
        //     nextValidRecordNumber.getNumber(), recordLength));
        format!(
            "Skip Record, nextValidTypeIndex = 0x{:x}, Length = 0x{:x}",
            self.next_valid_record_number.index(),
            self.skip_length
        )
    }
}

impl fmt::Display for LfSkip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_skip() -> LfSkip {
        LfSkip::new(RecordNumber::type_record(0x1234), 0x40)
    }

    #[test]
    fn test_skip_basic() {
        let skip = make_test_skip();
        assert_eq!(skip.pdb_id(), 0x1200);
        assert_eq!(
            skip.next_valid_record_number,
            RecordNumber::type_record(0x1234)
        );
        assert_eq!(skip.skip_length, 0x40);
    }

    #[test]
    fn test_skip_from_parsed() {
        let skip = LfSkip::from_parsed(0x5678, 0x100);
        assert_eq!(skip.next_valid(), RecordNumber::type_record(0x5678));
        assert_eq!(skip.length(), 0x100);
    }

    #[test]
    fn test_skip_from_parsed_zero() {
        let skip = LfSkip::from_parsed(0, 0);
        assert_eq!(skip.next_valid(), RecordNumber::type_record(0));
        assert_eq!(skip.length(), 0);
    }

    #[test]
    fn test_skip_accessors() {
        let skip = make_test_skip();
        assert_eq!(skip.next_valid(), RecordNumber::type_record(0x1234));
        assert_eq!(skip.length(), 0x40);
    }

    #[test]
    fn test_skip_emit() {
        let skip = make_test_skip();
        let emitted = skip.emit(Bind::NONE);
        assert!(emitted.contains("Skip Record"));
        assert!(emitted.contains("nextValidTypeIndex = 0x1234"));
        assert!(emitted.contains("Length = 0x40"));
    }

    #[test]
    fn test_skip_emit_format() {
        let skip = LfSkip::from_parsed(0xABCD, 0x20);
        let emitted = skip.emit(Bind::NONE);
        assert!(emitted.contains("0xabcd"));
        assert!(emitted.contains("0x20"));
    }

    #[test]
    fn test_skip_record_number() {
        let mut skip = make_test_skip();
        assert!(skip.record_number().is_no_type());
        skip.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(skip.record_number().index(), 0x2000);
    }

    #[test]
    fn test_skip_display() {
        let skip = make_test_skip();
        let display = format!("{}", skip);
        assert!(display.contains("Skip Record"));
        assert!(display.contains("0x1234"));
    }
}
