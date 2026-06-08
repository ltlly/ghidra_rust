//! PDB BitField -- bitfield data type for PDB parsing.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb.PdbBitField`.

use std::fmt;

/// Errors that can occur with bitfield operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitFieldError {
    /// Invalid bit size (must be >= 1).
    InvalidBitSize(u32),
    /// Invalid bit offset (must be >= -1).
    InvalidBitOffset(i32),
    /// Bit size exceeds the base type size.
    BitSizeExceedsBase { bit_size: u32, base_size: u32 },
    /// The base type is not suitable for a bitfield.
    InvalidBaseType(String),
}

impl fmt::Display for BitFieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BitFieldError::InvalidBitSize(size) => {
                write!(f, "invalid PDB bit size: {}", size)
            }
            BitFieldError::InvalidBitOffset(offset) => {
                write!(f, "invalid PDB bit offset: {}", offset)
            }
            BitFieldError::BitSizeExceedsBase { bit_size, base_size } => {
                write!(
                    f,
                    "bitfield size {} exceeds base type size {}",
                    bit_size, base_size
                )
            }
            BitFieldError::InvalidBaseType(name) => {
                write!(f, "invalid base type for bitfield: {}", name)
            }
        }
    }
}

impl std::error::Error for BitFieldError {}

/// A PDB bitfield data type.
///
/// Represents a bitfield within a composite type, tracking the base type,
/// bit size, and bit offset within the base type. This is used during PDB
/// parsing to hold bitfield information before it is applied to the program's
/// data type manager.
///
/// The bitfield packing assumes little-endian (LSB first) bit ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbBitField {
    /// The base data type index (in TPI) for this bitfield.
    pub base_type_index: u32,
    /// The size of the base type in bytes.
    pub base_type_size: u32,
    /// The size of the bitfield in bits.
    pub bit_size: u32,
    /// The bit offset within the full base type.
    /// A value of -1 indicates unknown offset.
    /// Stored as i32 for compatibility with the Java implementation.
    bit_offset_within_base: i32,
    /// The minimal bit offset within the storage unit (bit_offset % 8).
    /// This is the offset used for the actual BitFieldDataType.
    minimal_bit_offset: u8,
}

impl PdbBitField {
    /// Create a new PDB bitfield.
    ///
    /// # Arguments
    /// * `base_type_index` - The type index of the base type in TPI.
    /// * `base_type_size` - The size of the base type in bytes.
    /// * `bit_size` - The size of the bitfield in bits (must be >= 1).
    /// * `bit_offset_within_base` - The bit offset within the base type (-1 if unknown).
    ///
    /// # Errors
    /// Returns an error if the bit size is 0 or the offset is invalid.
    pub fn new(
        base_type_index: u32,
        base_type_size: u32,
        bit_size: u32,
        bit_offset_within_base: i32,
    ) -> Result<Self, BitFieldError> {
        if bit_size < 1 {
            return Err(BitFieldError::InvalidBitSize(bit_size));
        }
        if bit_offset_within_base < -1 {
            return Err(BitFieldError::InvalidBitOffset(bit_offset_within_base));
        }
        if bit_size > base_type_size * 8 {
            return Err(BitFieldError::BitSizeExceedsBase {
                bit_size,
                base_size: base_type_size,
            });
        }

        let minimal_bit_offset = if bit_offset_within_base < 0 {
            0
        } else {
            // Assumes little-endian packing (LSB first)
            (bit_offset_within_base as u32 % 8) as u8
        };

        Ok(Self {
            base_type_index,
            base_type_size,
            bit_size,
            bit_offset_within_base,
            minimal_bit_offset,
        })
    }

    /// Get the bit offset within the full base type.
    ///
    /// Returns -1 if the offset is unknown.
    pub fn bit_offset_within_base(&self) -> i32 {
        self.bit_offset_within_base
    }

    /// Get the minimal bit offset within the storage byte.
    ///
    /// This is `bit_offset_within_base % 8` for little-endian bitfields.
    pub fn minimal_bit_offset(&self) -> u8 {
        self.minimal_bit_offset
    }

    /// Get the storage size in bytes for this bitfield.
    ///
    /// This is the size of the base type that contains the bitfield.
    pub fn storage_size(&self) -> u32 {
        self.base_type_size
    }

    /// Get the declared bit size of this bitfield.
    pub fn declared_bit_size(&self) -> u32 {
        self.bit_size
    }

    /// Check if the bit offset is known.
    pub fn has_known_offset(&self) -> bool {
        self.bit_offset_within_base >= 0
    }

    /// Get the byte offset of the base type within its containing structure.
    ///
    /// This is `bit_offset_within_base / 8` for the purpose of structure
    /// insertion with `insertBitFieldAt`.
    pub fn base_offset_adjustment(&self) -> i32 {
        if self.bit_offset_within_base < 0 {
            0
        } else {
            self.bit_offset_within_base / 8
        }
    }
}

impl fmt::Display for PdbBitField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bitfield(baseSize:{}, bitSize:{}, bitOffsetInBase:{})",
            self.base_type_size, self.bit_size, self.bit_offset_within_base
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_bitfield() {
        let bf = PdbBitField::new(0x0074, 4, 8, 0).unwrap();
        assert_eq!(bf.base_type_index, 0x0074);
        assert_eq!(bf.base_type_size, 4);
        assert_eq!(bf.bit_size, 8);
        assert_eq!(bf.bit_offset_within_base(), 0);
        assert_eq!(bf.minimal_bit_offset(), 0);
        assert!(bf.has_known_offset());
    }

    #[test]
    fn test_bitfield_offset_within_byte() {
        let bf = PdbBitField::new(0x0074, 4, 4, 12).unwrap();
        assert_eq!(bf.bit_offset_within_base(), 12);
        assert_eq!(bf.minimal_bit_offset(), 4); // 12 % 8 = 4
        assert_eq!(bf.base_offset_adjustment(), 1); // 12 / 8 = 1
    }

    #[test]
    fn test_bitfield_unknown_offset() {
        let bf = PdbBitField::new(0x0074, 4, 8, -1).unwrap();
        assert_eq!(bf.bit_offset_within_base(), -1);
        assert_eq!(bf.minimal_bit_offset(), 0);
        assert!(!bf.has_known_offset());
    }

    #[test]
    fn test_invalid_bit_size_zero() {
        let result = PdbBitField::new(0x0074, 4, 0, 0);
        assert!(matches!(result, Err(BitFieldError::InvalidBitSize(0))));
    }

    #[test]
    fn test_invalid_bit_offset() {
        let result = PdbBitField::new(0x0074, 4, 8, -2);
        assert!(matches!(result, Err(BitFieldError::InvalidBitOffset(-2))));
    }

    #[test]
    fn test_bit_size_exceeds_base() {
        let result = PdbBitField::new(0x0074, 1, 16, 0);
        assert!(matches!(
            result,
            Err(BitFieldError::BitSizeExceedsBase {
                bit_size: 16,
                base_size: 1
            })
        ));
    }

    #[test]
    fn test_storage_size() {
        let bf = PdbBitField::new(0x0074, 4, 1, 0).unwrap();
        assert_eq!(bf.storage_size(), 4);
    }

    #[test]
    fn test_display() {
        let bf = PdbBitField::new(0x0074, 4, 8, 0).unwrap();
        let s = format!("{}", bf);
        assert!(s.contains("baseSize:4"));
        assert!(s.contains("bitSize:8"));
        assert!(s.contains("bitOffsetInBase:0"));
    }

    #[test]
    fn test_error_display() {
        let e = BitFieldError::InvalidBitSize(0);
        assert!(e.to_string().contains("invalid PDB bit size"));

        let e = BitFieldError::BitSizeExceedsBase {
            bit_size: 32,
            base_size: 1,
        };
        assert!(e.to_string().contains("exceeds base type size"));
    }

    #[test]
    fn test_single_bit_bitfield() {
        let bf = PdbBitField::new(0x0074, 1, 1, 0).unwrap();
        assert_eq!(bf.bit_size, 1);
        assert_eq!(bf.storage_size(), 1);
    }

    #[test]
    fn test_64bit_base() {
        let bf = PdbBitField::new(0x0075, 8, 32, 16).unwrap();
        assert_eq!(bf.base_type_size, 8);
        assert_eq!(bf.bit_size, 32);
        assert_eq!(bf.minimal_bit_offset(), 0); // 16 % 8 = 0
        assert_eq!(bf.base_offset_adjustment(), 2); // 16 / 8 = 2
    }
}
