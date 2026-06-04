//! Address range information for table display.
//!
//! Ports `ghidra.app.plugin.core.codebrowser.AddressRangeInfo`, a Java record
//! that holds metadata about an address range for use in address range tables.

use std::fmt;

/// Address metadata for a single contiguous address range.
///
/// Used by [`AddressRangeTableModel`](super::address_range_table_model::AddressRangeTableModel)
/// to display selected ranges with their properties.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.codebrowser.AddressRangeInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct AddressRangeInfo {
    /// Smallest address in the range (inclusive).
    min: u64,
    /// Largest address in the range (inclusive).
    max: u64,
    /// Number of addresses in the range.
    size: u64,
    /// `true` when all bytes in the range have the same value or all are undefined.
    is_same_byte: bool,
    /// Number of references targeting this range.
    num_refs_to: usize,
    /// Number of references originating from this range.
    num_refs_from: usize,
}

impl AddressRangeInfo {
    /// Create a new address range info.
    pub fn new(
        min: u64,
        max: u64,
        size: u64,
        is_same_byte: bool,
        num_refs_to: usize,
        num_refs_from: usize,
    ) -> Self {
        Self {
            min,
            max,
            size,
            is_same_byte,
            num_refs_to,
            num_refs_from,
        }
    }

    /// Returns the minimum (lowest) address in the range.
    pub fn min(&self) -> u64 {
        self.min
    }

    /// Returns the maximum (highest) address in the range.
    pub fn max(&self) -> u64 {
        self.max
    }

    /// Returns the size (number of addresses) in the range.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns whether all bytes in the range are identical.
    pub fn is_same_byte(&self) -> bool {
        self.is_same_byte
    }

    /// Returns the number of references targeting this range.
    pub fn num_refs_to(&self) -> usize {
        self.num_refs_to
    }

    /// Returns the number of references originating from this range.
    pub fn num_refs_from(&self) -> usize {
        self.num_refs_from
    }

    /// Check whether all bytes in a data slice have the same value.
    ///
    /// Ports `AddressRangeInfo.isSameByteValue(Address, Address, Program)`.
    ///
    /// Returns `true` if every byte in `data` has the same value, or if
    /// `data` is empty.
    pub fn is_same_byte_value(data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }
        let first = data[0];
        data.iter().all(|&b| b == first)
    }
}

impl fmt::Display for AddressRangeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AddressRangeInfo(0x{:X}..0x{:X}, size={}, same_byte={}, refs_to={}, refs_from={})",
            self.min, self.max, self.size, self.is_same_byte, self.num_refs_to, self.num_refs_from
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_range_info_creation() {
        let info = AddressRangeInfo::new(0x1000, 0x10FF, 256, true, 10, 5);
        assert_eq!(info.min(), 0x1000);
        assert_eq!(info.max(), 0x10FF);
        assert_eq!(info.size(), 256);
        assert!(info.is_same_byte());
        assert_eq!(info.num_refs_to(), 10);
        assert_eq!(info.num_refs_from(), 5);
    }

    #[test]
    fn test_is_same_byte_value_uniform() {
        assert!(AddressRangeInfo::is_same_byte_value(&[0xAA, 0xAA, 0xAA]));
        assert!(AddressRangeInfo::is_same_byte_value(&[0x00, 0x00]));
        assert!(AddressRangeInfo::is_same_byte_value(&[0xFF]));
    }

    #[test]
    fn test_is_same_byte_value_mixed() {
        assert!(!AddressRangeInfo::is_same_byte_value(&[0x00, 0x01]));
        assert!(!AddressRangeInfo::is_same_byte_value(&[0xAA, 0xBB, 0xCC]));
    }

    #[test]
    fn test_is_same_byte_value_empty() {
        assert!(AddressRangeInfo::is_same_byte_value(&[]));
    }

    #[test]
    fn test_display() {
        let info = AddressRangeInfo::new(0x400000, 0x400100, 257, false, 3, 1);
        let display = format!("{}", info);
        assert!(display.contains("0x400000"));
        assert!(display.contains("0x400100"));
        assert!(display.contains("size=257"));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let info = AddressRangeInfo::new(0x1000, 0x10FF, 256, true, 10, 5);
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: AddressRangeInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, deserialized);
    }

    #[test]
    fn test_equality() {
        let a = AddressRangeInfo::new(0x1000, 0x10FF, 256, true, 10, 5);
        let b = AddressRangeInfo::new(0x1000, 0x10FF, 256, true, 10, 5);
        let c = AddressRangeInfo::new(0x1000, 0x10FF, 256, false, 10, 5);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
