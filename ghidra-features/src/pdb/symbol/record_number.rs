//! RecordNumber -- typed wrapper for PDB record indices.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber`.

use std::fmt;

/// Category of a PDB record number.
///
/// PDB record numbers are distinguished by whether they reference a **type**
/// record (from the TPI/IPI stream) or an **item** record (from the IPI stream
/// in newer PDB versions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordCategory {
    /// A type record number (TPI stream index).
    Type,
    /// An item record number (IPI stream index).
    Item,
}

impl fmt::Display for RecordCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordCategory::Type => write!(f, "TYPE"),
            RecordCategory::Item => write!(f, "ITEM"),
        }
    }
}

/// A typed PDB record number.
///
/// `RecordNumber` wraps a raw `u32` index and tags it with a [`RecordCategory`]
/// so that type indices and item indices cannot be confused at the type level.
///
/// # Constants
///
/// - [`RecordNumber::T_NOTYPE`] — The sentinel value `0`, meaning "no type".
/// - [`RecordNumber::T_VOID`] — The sentinel value `3`, meaning `void`.
///
/// # Construction
///
/// Use the associated functions [`RecordNumber::type_record_number`] and
/// [`RecordNumber::item_record_number`] to create instances with the correct
/// category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordNumber {
    category: RecordCategory,
    number: u32,
}

impl RecordNumber {
    /// Sentinel value for "no type" (0).
    pub const T_NOTYPE: u32 = 0;

    /// Sentinel value for `void` (3).
    pub const T_VOID: u32 = 3;

    /// A record number with `Type` category and value `0` (no type).
    pub const NO_TYPE: RecordNumber = RecordNumber {
        category: RecordCategory::Type,
        number: Self::T_NOTYPE,
    };

    /// Create a type record number.
    ///
    /// Returns [`RecordNumber::NO_TYPE`] if `number` equals [`Self::T_NOTYPE`].
    pub fn type_record_number(number: u32) -> Self {
        if number == Self::T_NOTYPE {
            return Self::NO_TYPE;
        }
        RecordNumber {
            category: RecordCategory::Type,
            number,
        }
    }

    /// Create an item record number.
    ///
    /// Returns [`RecordNumber::NO_TYPE`] if `number` equals [`Self::T_NOTYPE`].
    pub fn item_record_number(number: u32) -> Self {
        if number == Self::T_NOTYPE {
            return Self::NO_TYPE;
        }
        RecordNumber {
            category: RecordCategory::Item,
            number,
        }
    }

    /// Create a record number for the given category.
    pub fn make(category: RecordCategory, number: u32) -> Self {
        match category {
            RecordCategory::Type => Self::type_record_number(number),
            RecordCategory::Item => Self::item_record_number(number),
        }
    }

    /// Parse a record number from a byte slice at the given offset.
    ///
    /// `size` selects the width: `16` for a 16-bit index, `32` for a 32-bit index.
    /// Returns the parsed `RecordNumber` and the number of bytes consumed.
    pub fn parse(data: &[u8], offset: usize, category: RecordCategory, size: u16) -> (Self, usize) {
        let (number, consumed) = match size {
            16 => {
                if offset + 2 > data.len() {
                    return (Self::make(category, 0), 0);
                }
                let val = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
                (val, 2)
            }
            32 => {
                if offset + 4 > data.len() {
                    return (Self::make(category, 0), 0);
                }
                let val = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                (val, 4)
            }
            _ => (0, 0),
        };
        (Self::make(category, number), consumed)
    }

    /// Return the category of this record number.
    pub fn category(&self) -> RecordCategory {
        self.category
    }

    /// Return the raw numeric value.
    pub fn number(&self) -> u32 {
        self.number
    }

    /// Return `true` if this is a "no type" sentinel.
    pub fn is_no_type(&self) -> bool {
        self.number == Self::T_NOTYPE
    }
}

impl fmt::Display for RecordNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}]", self.category, self.number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_record_number() {
        let rn = RecordNumber::type_record_number(42);
        assert_eq!(rn.category(), RecordCategory::Type);
        assert_eq!(rn.number(), 42);
        assert!(!rn.is_no_type());
    }

    #[test]
    fn test_item_record_number() {
        let rn = RecordNumber::item_record_number(100);
        assert_eq!(rn.category(), RecordCategory::Item);
        assert_eq!(rn.number(), 100);
    }

    #[test]
    fn test_no_type_sentinel() {
        let rn = RecordNumber::type_record_number(0);
        assert_eq!(rn, RecordNumber::NO_TYPE);
        assert!(rn.is_no_type());
    }

    #[test]
    fn test_make_dispatch() {
        let t = RecordNumber::make(RecordCategory::Type, 5);
        assert_eq!(t.category(), RecordCategory::Type);
        let i = RecordNumber::make(RecordCategory::Item, 7);
        assert_eq!(i.category(), RecordCategory::Item);
    }

    #[test]
    fn test_parse_16bit() {
        let data = [0x2A, 0x00]; // 42 little-endian
        let (rn, consumed) = RecordNumber::parse(&data, 0, RecordCategory::Type, 16);
        assert_eq!(rn.number(), 42);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_parse_32bit() {
        let data = [0x78, 0x56, 0x34, 0x12]; // 0x12345678 little-endian
        let (rn, consumed) = RecordNumber::parse(&data, 0, RecordCategory::Item, 32);
        assert_eq!(rn.number(), 0x12345678);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_display() {
        let rn = RecordNumber::type_record_number(99);
        assert_eq!(format!("{}", rn), "TYPE[99]");
    }

    #[test]
    fn test_constants() {
        assert_eq!(RecordNumber::T_NOTYPE, 0);
        assert_eq!(RecordNumber::T_VOID, 3);
        assert!(RecordNumber::NO_TYPE.is_no_type());
    }
}
