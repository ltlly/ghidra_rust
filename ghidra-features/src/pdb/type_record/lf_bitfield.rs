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

    /// Get the record number of the underlying (base) integral type.
    ///
    /// Mirrors Java `AbstractBitfieldMsType.getElementRecordNumber()`.
    pub fn element_record_number(&self) -> RecordNumber {
        self.underlying_type_record_number
    }

    /// Get the bit length of the bitfield.
    ///
    /// Mirrors Java `AbstractBitfieldMsType.getBitLength()`.
    pub fn bit_length(&self) -> u8 {
        self.bit_length
    }

    /// Get the bit position of the least-significant bit.
    ///
    /// Mirrors Java `AbstractBitfieldMsType.getBitPosition()`.
    pub fn bit_position(&self) -> u8 {
        self.bit_position
    }

    /// Compute the bit mask for this bitfield within its storage unit.
    ///
    /// For a bitfield of `bit_length` bits at `bit_position`, the mask is
    /// `((1 << bit_length) - 1) << bit_position`.
    pub fn bit_mask(&self) -> u32 {
        let width = self.bit_length.min(32);
        if width == 0 {
            0
        } else {
            ((1u32 << width) - 1) << self.bit_position
        }
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
        // Mirrors Java: pdb.getTypeRecord(elementRecordNumber).emit(builder, Bind.NONE)
        result.push_str(&self.underlying_type_record_number.to_string());
        result.push_str(" : ");
        result.push_str(&self.bit_length.to_string());
        // Mirrors Java: builder.append(" <@").append(position).append(">")
        result.push_str(&format!(" <@{}>", self.bit_position));
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
        assert!(emitted.contains("<@0>"));
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
        assert!(emitted.contains("<@0>"));
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
        assert!(display.contains("<@0>"));
    }

    #[test]
    fn test_bitfield_from_parsed_at_high_position() {
        // A 3-bit field starting at position 5 in an unsigned char
        let bf = LfBitfield::from_parsed(0x0020, 3, 5);
        assert_eq!(bf.bit_length, 3);
        assert_eq!(bf.bit_position, 5);
    }

    #[test]
    fn test_bitfield_accessors() {
        let bf = make_test_bitfield();
        assert_eq!(bf.element_record_number(), RecordNumber::type_record(0x0074));
        assert_eq!(bf.bit_length(), 4);
        assert_eq!(bf.bit_position(), 0);
    }

    #[test]
    fn test_bitfield_bit_mask() {
        // 4-bit field at position 0: mask = 0x0F
        let bf = make_test_bitfield();
        assert_eq!(bf.bit_mask(), 0x0F);

        // 1-bit field at position 0: mask = 0x01
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 1, 0);
        assert_eq!(bf.bit_mask(), 0x01);

        // 3-bit field at position 5: mask = 0xE0
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 3, 5);
        assert_eq!(bf.bit_mask(), 0xE0);

        // 8-bit field at position 0: mask = 0xFF
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 8, 0);
        assert_eq!(bf.bit_mask(), 0xFF);

        // 0-bit field: mask = 0
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 0, 0);
        assert_eq!(bf.bit_mask(), 0);
    }

    #[test]
    fn test_bitfield_emit_at_position() {
        let bf = LfBitfield::from_parsed(0x0020, 3, 5);
        let emitted = bf.emit(Bind::NONE);
        assert!(emitted.contains("<@5>"));
        assert!(emitted.contains(": 3"));
    }
}
