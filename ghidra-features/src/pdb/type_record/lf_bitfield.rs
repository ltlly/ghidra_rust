//! LF_BITFIELD -- concrete Bitfield type record.
//!
//! Ports Ghidra's `BitfieldMsType` (PDB_ID = 0x1205) Java class.
//!
//! Represents a C/C++ bitfield type in the PDB type stream. A bitfield
//! specifies a base type, the number of bits used, and the bit position
//! within the underlying storage unit.
//!
//! # Binary Layout (LF_BITFIELD / 0x1205)
//!
//! ```text
//! +0  u32   underlyingType   Type index of the base integral type
//! +4  u8    length           Number of bits in the bitfield
//! +5  u8    position         Bit position of the least-significant bit
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

/// Concrete PDB bitfield type record (`LF_BITFIELD`).
///
/// This is the Rust equivalent of Ghidra's `BitfieldMsType`. It stores
/// the underlying integral type, the bit length, and the bit position.
///
/// # Examples
///
/// ```text
/// // C: unsigned int x : 4;
/// // Underlying type: unsigned int, length=4, position=0
/// ```
#[derive(Debug, Clone)]
pub struct LfBitfield {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the underlying integral type.
    pub underlying_type_record_number: RecordNumber,
    /// Number of bits used by this bitfield.
    pub bit_length: u8,
    /// Bit position of the least-significant bit within the storage unit.
    pub bit_position: u8,
}

impl LfBitfield {
    /// Create a new bitfield type record.
    pub fn new(
        underlying_type_record_number: RecordNumber,
        bit_length: u8,
        bit_position: u8,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            underlying_type_record_number,
            bit_length,
            bit_position,
        }
    }

    /// Create from raw parsed field values.
    pub fn from_parsed(
        underlying_type_index: u32,
        bit_length: u8,
        bit_position: u8,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(underlying_type_index),
            bit_length,
            bit_position,
        )
    }
}

impl AbstractMsType for LfBitfield {
    fn pdb_id(&self) -> u32 {
        0x1205 // LF_BITFIELD
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        let mut result = String::new();
        result.push_str(&self.underlying_type_record_number.to_string());
        result.push_str(" : ");
        result.push_str(&self.bit_length.to_string());
        result.push(' ');
        result
    }
}

impl fmt::Display for LfBitfield {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_bitfield() -> LfBitfield {
        LfBitfield::new(
            RecordNumber::type_record(0x0074), // unsigned int
            4,
            0,
        )
    }

    #[test]
    fn test_bitfield_basic() {
        let bf = make_test_bitfield();
        assert_eq!(bf.pdb_id(), 0x1205);
        assert_eq!(
            bf.underlying_type_record_number,
            RecordNumber::type_record(0x0074)
        );
        assert_eq!(bf.bit_length, 4);
        assert_eq!(bf.bit_position, 0);
    }

    #[test]
    fn test_bitfield_from_parsed() {
        let bf = LfBitfield::from_parsed(0x0075, 3, 4);
        assert_eq!(
            bf.underlying_type_record_number,
            RecordNumber::type_record(0x0075)
        );
        assert_eq!(bf.bit_length, 3);
        assert_eq!(bf.bit_position, 4);
    }

    #[test]
    fn test_bitfield_emit() {
        let bf = make_test_bitfield();
        let emitted = bf.emit(Bind::NONE);
        assert!(emitted.contains("0x0074"));
        assert!(emitted.contains(": 4"));
    }

    #[test]
    fn test_bitfield_emit_1bit() {
        let bf = LfBitfield::new(
            RecordNumber::type_record(0x0030), // bool
            1,
            0,
        );
        let emitted = bf.emit(Bind::NONE);
        assert!(emitted.contains("0x0030"));
        assert!(emitted.contains(": 1"));
    }

    #[test]
    fn test_bitfield_record_number() {
        let mut bf = make_test_bitfield();
        assert!(bf.record_number().is_no_type());
        bf.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(bf.record_number().index(), 0x2000);
    }

    #[test]
    fn test_bitfield_display() {
        let bf = make_test_bitfield();
        let display = format!("{}", bf);
        assert!(display.contains("0x0074"));
        assert!(display.contains(": 4"));
    }

    #[test]
    fn test_bitfield_from_parsed_at_high_position() {
        // A 3-bit field starting at position 5 in an unsigned char
        let bf = LfBitfield::from_parsed(0x0020, 3, 5);
        assert_eq!(bf.bit_length, 3);
        assert_eq!(bf.bit_position, 5);
    }
}
