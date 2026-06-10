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
/// skip region. The optional `remaining_bytes` field captures any raw
/// filler data found in the skip region (useful for round-trip fidelity).
#[derive(Debug, Clone)]
pub struct LfSkip {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the next valid type record in the stream.
    pub next_valid_record_number: RecordNumber,
    /// Length of the skip region (remaining bytes after the next-valid pointer).
    pub skip_length: u32,
    /// Raw filler bytes from the skipped region, if captured during parsing.
    pub remaining_bytes: Vec<u8>,
}

impl LfSkip {
    /// PDB ID for the 16-bit variant (`LF_SKIP_16` / `Skip16MsType`).
    pub const PDB_ID_16: u32 = 0x0200;

    /// Create a new skip type record.
    pub fn new(next_valid_record_number: RecordNumber, skip_length: u32) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            next_valid_record_number,
            skip_length,
            remaining_bytes: Vec::new(),
        }
    }

    /// Create a new skip type record with remaining bytes data.
    pub fn with_remaining_bytes(
        next_valid_record_number: RecordNumber,
        skip_length: u32,
        remaining_bytes: Vec<u8>,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            next_valid_record_number,
            skip_length,
            remaining_bytes,
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

    /// Create from raw parsed field values with remaining bytes.
    pub fn from_parsed_with_bytes(
        next_valid_type_index: u32,
        remaining_bytes: Vec<u8>,
    ) -> Self {
        let length = remaining_bytes.len() as u32;
        Self::with_remaining_bytes(
            RecordNumber::type_record(next_valid_type_index),
            length,
            remaining_bytes,
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

    /// Whether this skip record has a valid next-record reference.
    ///
    /// A skip record is considered valid if its next-valid reference is not
    /// `NO_TYPE` (i.e., there is actually a record to skip to).
    pub fn is_valid(&self) -> bool {
        !self.next_valid_record_number.is_no_type()
    }

    /// Whether this skip record has captured remaining bytes.
    pub fn has_remaining_bytes(&self) -> bool {
        !self.remaining_bytes.is_empty()
    }

    /// The total binary size of this record in the PDB stream.
    ///
    /// Includes the 4-byte next-valid record number plus the remaining bytes,
    /// rounded up to a 4-byte alignment boundary.
    pub fn total_record_size(&self) -> usize {
        let data_size = 4 + self.remaining_bytes.len();
        (data_size + 3) & !3 // align to 4
    }

    /// Parse an `LF_SKIP` record (32-bit variant, PDB_ID 0x1200) from raw bytes.
    ///
    /// Mirrors the Java `SkipMsType(AbstractPdb, PdbByteReader)` constructor
    /// which delegates to `AbstractSkipMsType` with `recordNumberSize = 32`.
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u32   nextValidRecordNumber   Type index of the next valid record
    /// +4  byte[] remainingBytes         Padding/filler data for the skipped region
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        Self::parse_inner(data, 4) // 4-byte (32-bit) record number
    }

    /// Parse a 16-bit variant `LF_SKIP` record (PDB_ID 0x0200) from raw bytes.
    ///
    /// Same layout but with a 16-bit (2-byte) next-valid record number.
    pub fn parse_16(data: &[u8]) -> Result<Self, String> {
        Self::parse_inner(data, 2) // 2-byte (16-bit) record number
    }

    /// Internal parser that handles both 16-bit and 32-bit record number sizes.
    fn parse_inner(data: &[u8], record_num_size: usize) -> Result<Self, String> {
        if data.len() < record_num_size {
            return Err(format!(
                "LF_SKIP payload too short: need >= {} bytes, got {}",
                record_num_size, data.len()
            ));
        }
        let next_valid = if record_num_size == 4 {
            u32::from_le_bytes([data[0], data[1], data[2], data[3]])
        } else {
            u16::from_le_bytes([data[0], data[1]]) as u32
        };
        let remaining_bytes = data[record_num_size..].to_vec();
        Ok(Self::from_parsed_with_bytes(next_valid, remaining_bytes))
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

    #[test]
    fn test_skip_with_remaining_bytes() {
        let skip = LfSkip::with_remaining_bytes(
            RecordNumber::type_record(0x1234),
            5,
            vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
        );
        assert_eq!(skip.length(), 5);
        assert!(skip.has_remaining_bytes());
        assert_eq!(skip.remaining_bytes.len(), 5);
    }

    #[test]
    fn test_skip_from_parsed_with_bytes() {
        let skip = LfSkip::from_parsed_with_bytes(
            0x5678,
            vec![0x00; 16],
        );
        assert_eq!(skip.next_valid(), RecordNumber::type_record(0x5678));
        assert_eq!(skip.length(), 16);
        assert!(skip.has_remaining_bytes());
    }

    #[test]
    fn test_skip_is_valid_true() {
        let skip = make_test_skip();
        assert!(skip.is_valid());
    }

    #[test]
    fn test_skip_is_valid_false() {
        let skip = LfSkip::new(RecordNumber::NO_TYPE, 0);
        assert!(!skip.is_valid());
    }

    #[test]
    fn test_skip_has_remaining_bytes_false() {
        let skip = make_test_skip();
        assert!(!skip.has_remaining_bytes());
        assert!(skip.remaining_bytes.is_empty());
    }

    #[test]
    fn test_skip_total_record_size_no_remaining() {
        // 4 bytes for next-valid record, no remaining => 4 aligned to 4 = 4
        let skip = make_test_skip();
        assert_eq!(skip.total_record_size(), 4);
    }

    #[test]
    fn test_skip_total_record_size_with_remaining() {
        // 4 + 5 = 9, aligned to 4 => 12
        let skip = LfSkip::with_remaining_bytes(
            RecordNumber::type_record(0x1234),
            5,
            vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
        );
        assert_eq!(skip.total_record_size(), 12);
    }

    #[test]
    fn test_skip_total_record_size_aligned() {
        // 4 + 8 = 12, already aligned
        let skip = LfSkip::with_remaining_bytes(
            RecordNumber::type_record(0x1234),
            8,
            vec![0x00; 8],
        );
        assert_eq!(skip.total_record_size(), 12);
    }

    #[test]
    fn test_skip_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x5678u32.to_le_bytes()); // nextValidRecordNumber
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]); // remaining

        let skip = LfSkip::parse(&data).unwrap();
        assert_eq!(skip.pdb_id(), 0x1200);
        assert_eq!(skip.next_valid(), RecordNumber::type_record(0x5678));
        assert_eq!(skip.length(), 5);
        assert!(skip.has_remaining_bytes());
        assert_eq!(skip.remaining_bytes, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    }

    #[test]
    fn test_skip_parse_no_remaining() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1234u32.to_le_bytes());

        let skip = LfSkip::parse(&data).unwrap();
        assert_eq!(skip.next_valid(), RecordNumber::type_record(0x1234));
        assert_eq!(skip.length(), 0);
        assert!(!skip.has_remaining_bytes());
    }

    #[test]
    fn test_skip_parse_16() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xABCDu16.to_le_bytes()); // 16-bit nextValid
        data.extend_from_slice(&[0x01, 0x02, 0x03]);

        let skip = LfSkip::parse_16(&data).unwrap();
        assert_eq!(skip.pdb_id(), 0x1200);
        assert_eq!(skip.next_valid(), RecordNumber::type_record(0xABCD));
        assert_eq!(skip.length(), 3);
    }

    #[test]
    fn test_skip_parse_too_short() {
        let data = [0u8; 2];
        assert!(LfSkip::parse(&data).is_err());
    }

    #[test]
    fn test_skip_parse_16_too_short() {
        let data = [0u8; 1];
        assert!(LfSkip::parse_16(&data).is_err());
    }

    #[test]
    fn test_skip_parse_roundtrip() {
        let skip = LfSkip::with_remaining_bytes(
            RecordNumber::type_record(0x5678),
            4,
            vec![0xAA, 0xBB, 0xCC, 0xDD],
        );
        let mut data = Vec::new();
        data.extend_from_slice(&skip.next_valid_record_number.index().to_le_bytes());
        data.extend_from_slice(&skip.remaining_bytes);

        let skip2 = LfSkip::parse(&data).unwrap();
        assert_eq!(skip2.next_valid(), skip.next_valid());
        assert_eq!(skip2.remaining_bytes, skip.remaining_bytes);
    }

    #[test]
    fn test_skip_pdb_id_16() {
        assert_eq!(LfSkip::PDB_ID_16, 0x0200);
    }
}
