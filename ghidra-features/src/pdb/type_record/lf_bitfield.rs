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
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Parse an `LF_BITFIELD` record from raw bytes (payload after leaf ID).
    ///
    /// Mirrors the Java `BitfieldMsType(AbstractPdb, PdbByteReader)` constructor.
    /// The `data` slice should start at the `underlyingType` field.
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u32   underlyingType   Type index of the base integral type
    /// +4  u8    length           Number of bits in the bitfield
    /// +5  u8    position         Bit position of the least-significant bit
    /// ```
    ///
    /// Note: The Java implementation calls `reader.align4()` after parsing.
    /// Since we parse from a flat slice, alignment is handled externally.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 6 {
            return Err(format!(
                "LF_BITFIELD payload too short: need >= 6 bytes, got {}",
                data.len()
            ));
        }
        let underlying_ti = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let length = data[4];
        let position = data[5];
        Ok(Self::from_parsed(underlying_ti, length, position))
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
    ///
    /// Uses saturating shifts to avoid overflow when `bit_length == 32`.
    pub fn bit_mask(&self) -> u32 {
        let width = self.bit_length.min(32);
        if width == 0 {
            0
        } else if width >= 32 {
            u32::MAX.wrapping_shl(self.bit_position as u32)
        } else {
            ((1u32 << width) - 1).wrapping_shl(self.bit_position as u32)
        }
    }

    /// Compute the minimum number of bytes needed to store this bitfield.
    ///
    /// Returns the ceiling of `(bit_position + bit_length) / 8`.
    /// For example, a 4-bit field at position 0 needs 1 byte;
    /// a 3-bit field at position 5 needs 1 byte;
    /// a 1-bit field at position 8 needs 2 bytes.
    pub fn byte_length(&self) -> u8 {
        let total_bits = (self.bit_position as u16) + (self.bit_length as u16);
        ((total_bits + 7) / 8) as u8
    }

    /// Whether this bitfield is valid.
    ///
    /// A bitfield is valid if:
    /// - `bit_length` is greater than 0
    /// - `bit_length` does not exceed 32 (the maximum for a u32 storage unit)
    /// - the underlying type record number is not NO_TYPE
    pub fn is_valid(&self) -> bool {
        self.bit_length > 0
            && self.bit_length <= 32
            && !self.underlying_type_record_number.is_no_type()
    }

    /// Get the total number of bits spanned (position + length).
    ///
    /// This is useful for determining the minimum storage unit size.
    pub fn total_bits_spanned(&self) -> u16 {
        (self.bit_position as u16) + (self.bit_length as u16)
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

    #[test]
    fn test_bitfield_parse() {
        // LF_BITFIELD payload: underlyingType=0x0074, length=4, position=0
        let mut data = Vec::new();
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.push(4);  // length
        data.push(0);  // position

        let bf = LfBitfield::parse(&data).unwrap();
        assert_eq!(bf.underlying_type_record_number, RecordNumber::type_record(0x0074));
        assert_eq!(bf.bit_length, 4);
        assert_eq!(bf.bit_position, 0);
        assert_eq!(bf.pdb_id(), 0x1205);
    }

    #[test]
    fn test_bitfield_parse_at_position() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0030u32.to_le_bytes());
        data.push(1);  // length
        data.push(7);  // position

        let bf = LfBitfield::parse(&data).unwrap();
        assert_eq!(bf.bit_length, 1);
        assert_eq!(bf.bit_position, 7);
    }

    #[test]
    fn test_bitfield_parse_too_short() {
        let data = [0u8; 4];
        assert!(LfBitfield::parse(&data).is_err());
    }

    #[test]
    fn test_bitfield_name() {
        let bf = make_test_bitfield();
        // Bitfields don't have names; name() returns ""
        assert_eq!(bf.name(), "");
    }

    #[test]
    fn test_bitfield_byte_length() {
        // 4 bits at position 0 -> 1 byte
        let bf = make_test_bitfield();
        assert_eq!(bf.byte_length(), 1);

        // 8 bits at position 0 -> 1 byte
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 8, 0);
        assert_eq!(bf.byte_length(), 1);

        // 1 bit at position 8 -> 2 bytes
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 1, 8);
        assert_eq!(bf.byte_length(), 2);

        // 3 bits at position 5 -> 1 byte (5+3=8 bits = 1 byte)
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 3, 5);
        assert_eq!(bf.byte_length(), 1);

        // 9 bits at position 0 -> 2 bytes
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 9, 0);
        assert_eq!(bf.byte_length(), 2);
    }

    #[test]
    fn test_bitfield_is_valid() {
        let bf = make_test_bitfield();
        assert!(bf.is_valid());

        // 0-length bitfield is invalid
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 0, 0);
        assert!(!bf.is_valid());

        // No underlying type is invalid
        let bf = LfBitfield::new(RecordNumber::NO_TYPE, 4, 0);
        assert!(!bf.is_valid());

        // 32-bit field is valid
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 32, 0);
        assert!(bf.is_valid());

        // 33-bit field is invalid
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 33, 0);
        assert!(!bf.is_valid());
    }

    #[test]
    fn test_bitfield_total_bits_spanned() {
        let bf = make_test_bitfield();
        assert_eq!(bf.total_bits_spanned(), 4);

        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 3, 5);
        assert_eq!(bf.total_bits_spanned(), 8);

        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 1, 31);
        assert_eq!(bf.total_bits_spanned(), 32);
    }

    #[test]
    fn test_bitfield_eq() {
        let bf1 = make_test_bitfield();
        let bf2 = make_test_bitfield();
        assert_eq!(bf1, bf2);

        let bf3 = LfBitfield::new(
            RecordNumber::type_record(0x0074),
            8,
            0,
        );
        assert_ne!(bf1, bf3);
    }

    #[test]
    fn test_bitfield_bit_mask_edge_cases() {
        // 32-bit field at position 0: mask = 0xFFFF_FFFF
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 32, 0);
        assert_eq!(bf.bit_mask(), 0xFFFF_FFFF);

        // 16-bit field at position 16: mask = 0xFFFF_0000
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 16, 16);
        assert_eq!(bf.bit_mask(), 0xFFFF_0000);

        // 4-bit field at position 4: mask = 0xF0
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 4, 4);
        assert_eq!(bf.bit_mask(), 0xF0);
    }

    #[test]
    fn test_bitfield_byte_length_edge_cases() {
        // 32 bits at position 0 -> 4 bytes
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 32, 0);
        assert_eq!(bf.byte_length(), 4);

        // 1 bit at position 31 -> 4 bytes
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 1, 31);
        assert_eq!(bf.byte_length(), 4);

        // 16 bits at position 16 -> 4 bytes
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 16, 16);
        assert_eq!(bf.byte_length(), 4);
    }

    #[test]
    fn test_bitfield_is_valid_edge_cases() {
        // Exactly 32 bits is valid
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 32, 0);
        assert!(bf.is_valid());

        // 1 bit is valid
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 1, 0);
        assert!(bf.is_valid());

        // 0 bits is invalid
        let bf = LfBitfield::new(RecordNumber::type_record(0x0074), 0, 0);
        assert!(!bf.is_valid());
    }

    #[test]
    fn test_bitfield_parse_alignment_note() {
        // Java calls reader.align4() after parsing. The Rust parse
        // returns the parsed data; alignment is handled externally.
        let mut data = Vec::new();
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.push(4);  // length
        data.push(0);  // position
        // Remaining bytes would be padding in aligned format
        data.push(0);
        data.push(0);

        let bf = LfBitfield::parse(&data).unwrap();
        assert_eq!(bf.bit_length, 4);
        assert_eq!(bf.bit_position, 0);
    }
}
