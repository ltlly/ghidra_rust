//! Register value range — a contiguous address range with a specific register value.
//!
//! Ported from `RegisterValueRange` in Ghidra's `ghidra.app.plugin.core.register`.
//!
//! A `RegisterValueRange` associates a register value (as a big integer)
//! with a start and end address range. It also tracks whether the value
//! is a default value (overridable) or an explicitly set value.

use ghidra_core::addr::Address;
use std::cmp::Ordering;
use std::fmt;

/// A contiguous address range carrying a specific register value.
///
/// Ported from `RegisterValueRange` in Java. Stores a start address,
/// end address, a value (as a `u64`), and whether it's a default value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterValueRange {
    /// Start address of this range (inclusive).
    start: Address,
    /// End address of this range (inclusive).
    end: Address,
    /// The register value for this range.
    value: u64,
    /// Whether this value is a default (can be overridden).
    is_default: bool,
}

impl RegisterValueRange {
    /// Create a new register value range.
    pub fn new(start: Address, end: Address, value: u64, is_default: bool) -> Self {
        Self {
            start,
            end,
            value,
            is_default,
        }
    }

    /// Create a value range from a pair of addresses and a value.
    pub fn from_range(start: Address, end: Address, value: u64) -> Self {
        Self::new(start, end, value, false)
    }

    /// Create a default value range.
    pub fn default_range(start: Address, end: Address, value: u64) -> Self {
        Self::new(start, end, value, true)
    }

    /// Get the start address.
    pub fn start_address(&self) -> Address {
        self.start
    }

    /// Get the end address.
    pub fn end_address(&self) -> Address {
        self.end
    }

    /// Get the register value.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Whether this is a default value.
    pub fn is_default(&self) -> bool {
        self.is_default
    }

    /// Set the end address (used when merging adjacent ranges with the same value).
    pub fn set_end_address(&mut self, end: Address) {
        self.end = end;
    }

    /// Whether the given address is within this range.
    pub fn contains(&self, addr: &Address) -> bool {
        addr.offset >= self.start.offset && addr.offset <= self.end.offset
    }

    /// The size of this range in bytes.
    pub fn size(&self) -> u64 {
        self.end.offset - self.start.offset + 1
    }

    /// Whether this range is adjacent to (immediately precedes) another range.
    pub fn is_adjacent_to(&self, other: &RegisterValueRange) -> bool {
        self.end.offset + 1 == other.start.offset
    }

    /// Whether this range can be merged with another (same value, adjacent,
    /// both default or both non-default).
    pub fn can_merge_with(&self, other: &RegisterValueRange) -> bool {
        self.value == other.value
            && self.is_default == other.is_default
            && self.is_adjacent_to(other)
    }
}

impl fmt::Display for RegisterValueRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{:x}..0x{:x} = 0x{:x}{}",
            self.start.offset,
            self.end.offset,
            self.value,
            if self.is_default { "  (default)" } else { "" }
        )
    }
}

impl PartialOrd for RegisterValueRange {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RegisterValueRange {
    fn cmp(&self, other: &Self) -> Ordering {
        self.start
            .offset
            .cmp(&other.start.offset)
            .then(self.end.offset.cmp(&other.end.offset))
    }
}

// ============================================================================
// Comparator helpers for table sorting
// ============================================================================

/// Sort column indices for the register values table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RegisterValueColumn {
    /// Start address column.
    StartAddress = 0,
    /// End address column.
    EndAddress = 1,
    /// Value column.
    Value = 2,
}

impl RegisterValueColumn {
    /// Compare two register value ranges by this column.
    pub fn compare(&self, a: &RegisterValueRange, b: &RegisterValueRange) -> Ordering {
        match self {
            Self::StartAddress => a.start_address().offset.cmp(&b.start_address().offset),
            Self::EndAddress => a.end_address().offset.cmp(&b.end_address().offset),
            Self::Value => a.value().cmp(&b.value()),
        }
    }
}

/// Merge a list of sorted, adjacent ranges with identical values into
/// consolidated ranges.  This mirrors the collapsing logic in
/// `RegisterValuesPanel.setRegister()`.
pub fn merge_adjacent_ranges(ranges: &mut Vec<RegisterValueRange>) {
    if ranges.len() <= 1 {
        return;
    }
    let mut merged: Vec<RegisterValueRange> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if let Some(last) = merged.last_mut() {
            if last.can_merge_with(&range) {
                last.set_end_address(range.end_address());
                continue;
            }
        }
        merged.push(range);
    }
    *ranges = merged;
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_create_range() {
        let r = RegisterValueRange::new(addr(0x1000), addr(0x1fff), 42, false);
        assert_eq!(r.start_address(), addr(0x1000));
        assert_eq!(r.end_address(), addr(0x1fff));
        assert_eq!(r.value(), 42);
        assert!(!r.is_default());
    }

    #[test]
    fn test_contains() {
        let r = RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 0);
        assert!(r.contains(&addr(0x1000)));
        assert!(r.contains(&addr(0x1500)));
        assert!(r.contains(&addr(0x1fff)));
        assert!(!r.contains(&addr(0x2000)));
        assert!(!r.contains(&addr(0x0fff)));
    }

    #[test]
    fn test_size() {
        let r = RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 0);
        assert_eq!(r.size(), 0x1000);
    }

    #[test]
    fn test_is_adjacent_to() {
        let r1 = RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5);
        let r2 = RegisterValueRange::from_range(addr(0x2000), addr(0x2fff), 5);
        let r3 = RegisterValueRange::from_range(addr(0x2001), addr(0x2fff), 5);
        assert!(r1.is_adjacent_to(&r2));
        assert!(!r1.is_adjacent_to(&r3));
    }

    #[test]
    fn test_can_merge_same_value_adjacent() {
        let r1 = RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5);
        let r2 = RegisterValueRange::from_range(addr(0x2000), addr(0x2fff), 5);
        assert!(r1.can_merge_with(&r2));
    }

    #[test]
    fn test_cannot_merge_different_value() {
        let r1 = RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5);
        let r2 = RegisterValueRange::from_range(addr(0x2000), addr(0x2fff), 10);
        assert!(!r1.can_merge_with(&r2));
    }

    #[test]
    fn test_cannot_merge_not_adjacent() {
        let r1 = RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5);
        let r2 = RegisterValueRange::from_range(addr(0x3000), addr(0x3fff), 5);
        assert!(!r1.can_merge_with(&r2));
    }

    #[test]
    fn test_cannot_merge_default_with_nondefault() {
        let r1 = RegisterValueRange::new(addr(0x1000), addr(0x1fff), 5, true);
        let r2 = RegisterValueRange::new(addr(0x2000), addr(0x2fff), 5, false);
        assert!(!r1.can_merge_with(&r2));
    }

    #[test]
    fn test_merge_adjacent_ranges() {
        let mut ranges = vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5),
            RegisterValueRange::from_range(addr(0x2000), addr(0x2fff), 5),
            RegisterValueRange::from_range(addr(0x3000), addr(0x3fff), 10),
        ];
        merge_adjacent_ranges(&mut ranges);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start_address(), addr(0x1000));
        assert_eq!(ranges[0].end_address(), addr(0x2fff));
        assert_eq!(ranges[0].value(), 5);
        assert_eq!(ranges[1].start_address(), addr(0x3000));
        assert_eq!(ranges[1].value(), 10);
    }

    #[test]
    fn test_merge_empty() {
        let mut ranges: Vec<RegisterValueRange> = vec![];
        merge_adjacent_ranges(&mut ranges);
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_merge_single() {
        let mut ranges = vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5),
        ];
        merge_adjacent_ranges(&mut ranges);
        assert_eq!(ranges.len(), 1);
    }

    #[test]
    fn test_display() {
        let r = RegisterValueRange::new(addr(0x1000), addr(0x1fff), 42, true);
        let s = format!("{}", r);
        assert!(s.contains("0x1000"));
        assert!(s.contains("0x1fff"));
        assert!(s.contains("0x2a"));
        assert!(s.contains("(default)"));
    }

    #[test]
    fn test_ordering() {
        let r1 = RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5);
        let r2 = RegisterValueRange::from_range(addr(0x2000), addr(0x2fff), 5);
        assert!(r1 < r2);
    }

    #[test]
    fn test_sort_column_compare() {
        let r1 = RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5);
        let r2 = RegisterValueRange::from_range(addr(0x2000), addr(0x2fff), 10);

        assert_eq!(
            RegisterValueColumn::StartAddress.compare(&r1, &r2),
            Ordering::Less
        );
        assert_eq!(
            RegisterValueColumn::EndAddress.compare(&r1, &r2),
            Ordering::Less
        );
        assert_eq!(
            RegisterValueColumn::Value.compare(&r1, &r2),
            Ordering::Less
        );
    }
}
