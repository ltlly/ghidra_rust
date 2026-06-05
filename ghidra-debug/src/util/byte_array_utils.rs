//! Byte array utility functions for trace operations.
//!
//! Ported from Ghidra's `ghidra.trace.util.ByteArrayUtils`.
//! Provides functions for computing diffs between byte arrays,
//! which is essential for efficient trace memory change tracking.

/// A contiguous range of addresses where two byte arrays differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffRange {
    /// The start address (inclusive) of the differing range.
    pub start: u64,
    /// The end address (inclusive) of the differing range.
    pub end: u64,
}

impl DiffRange {
    /// Create a new diff range.
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// The length of this diff range in bytes.
    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Whether this range is empty (should not happen in practice).
    pub fn is_empty(&self) -> bool {
        self.start > self.end
    }
}

/// An ordered set of address ranges (union of non-overlapping ranges).
///
/// This is a simplified version of Ghidra's `AddressSet`, operating
/// on `u64` addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressSet {
    ranges: Vec<DiffRange>,
}

impl AddressSet {
    /// Create a new empty address set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a range to the set.
    pub fn add_range(&mut self, start: u64, end: u64) {
        if start > end {
            return;
        }
        let new_range = DiffRange::new(start, end);
        // Find where to insert
        let pos = self.ranges.iter().position(|r| r.start > start).unwrap_or(self.ranges.len());
        self.ranges.insert(pos, new_range);
        self.merge_overlapping();
    }

    /// Merge overlapping or adjacent ranges.
    fn merge_overlapping(&mut self) {
        if self.ranges.len() <= 1 {
            return;
        }
        let mut merged = Vec::new();
        let mut current = self.ranges[0].clone();
        for range in &self.ranges[1..] {
            if range.start <= current.end + 1 {
                current.end = current.end.max(range.end);
            } else {
                merged.push(current);
                current = range.clone();
            }
        }
        merged.push(current);
        self.ranges = merged;
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Get the number of ranges.
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// Get the minimum address, if any.
    pub fn min_address(&self) -> Option<u64> {
        self.ranges.first().map(|r| r.start)
    }

    /// Get the maximum address, if any.
    pub fn max_address(&self) -> Option<u64> {
        self.ranges.last().map(|r| r.end)
    }

    /// Iterate over the ranges.
    pub fn iter(&self) -> impl Iterator<Item = &DiffRange> {
        self.ranges.iter()
    }

    /// Check if a given address is in the set.
    pub fn contains(&self, addr: u64) -> bool {
        self.ranges.iter().any(|r| r.start <= addr && addr <= r.end)
    }

    /// Check if a given range intersects with any range in the set.
    pub fn intersects(&self, start: u64, end: u64) -> bool {
        self.ranges.iter().any(|r| r.start <= end && start <= r.end)
    }
}

/// Compute the address set where two byte arrays differ, given a start address.
///
/// Both arrays must have the same length. Returns an `AddressSet` containing
/// contiguous ranges of addresses where the bytes differ.
///
/// Corresponds to Ghidra's `ByteArrayUtils.computeDiffsAddressSet()`.
pub fn compute_diffs_address_set(start: u64, a: &[u8], b: &[u8]) -> AddressSet {
    assert_eq!(a.len(), b.len(), "Arrays must be the same length");

    let mut result = AddressSet::new();
    let mut diff_start: Option<u64> = None;

    for i in 0..a.len() {
        if a[i] == b[i] {
            if let Some(ds) = diff_start {
                result.add_range(ds, start + i as u64 - 1);
                diff_start = None;
            }
        } else {
            if diff_start.is_none() {
                diff_start = Some(start + i as u64);
            }
        }
    }

    // Handle trailing difference
    if let Some(ds) = diff_start {
        let end = start + a.len() as u64 - 1;
        result.add_range(ds, end);
    }

    result
}

/// Check if two byte arrays are equal.
pub fn bytes_equal(a: &[u8], b: &[u8]) -> bool {
    a == b
}

/// Find the first position where two byte arrays differ.
///
/// Returns `None` if the arrays are equal or have different lengths.
pub fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    if a.len() != b.len() {
        return Some(0);
    }
    a.iter().zip(b.iter()).position(|(x, y)| x != y)
}

/// XOR two byte arrays of equal length.
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "Arrays must be the same length");
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Compute a simple hash of a byte range.
///
/// This uses a FNV-1a style hash for fast comparison.
pub fn hash_bytes(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_diffs_no_diff() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        let result = compute_diffs_address_set(0, &a, &b);
        assert!(result.is_empty());
    }

    #[test]
    fn test_compute_diffs_single_byte() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 0, 4, 5];
        let result = compute_diffs_address_set(0, &a, &b);
        assert_eq!(result.range_count(), 1);
        assert_eq!(result.min_address(), Some(2));
        assert_eq!(result.max_address(), Some(2));
    }

    #[test]
    fn test_compute_diffs_multiple_ranges() {
        let a = [1, 2, 3, 4, 5, 6, 7, 8];
        let b = [1, 0, 0, 4, 5, 0, 0, 8];
        let result = compute_diffs_address_set(0, &a, &b);
        assert_eq!(result.range_count(), 2);
        // First diff: bytes 1-2
        let ranges: Vec<_> = result.iter().collect();
        assert_eq!(ranges[0].start, 1);
        assert_eq!(ranges[0].end, 2);
        // Second diff: bytes 5-6
        assert_eq!(ranges[1].start, 5);
        assert_eq!(ranges[1].end, 6);
    }

    #[test]
    fn test_compute_diffs_with_start_offset() {
        let a = [1, 2, 3];
        let b = [1, 0, 3];
        let result = compute_diffs_address_set(0x1000, &a, &b);
        assert_eq!(result.min_address(), Some(0x1001));
        assert_eq!(result.max_address(), Some(0x1001));
    }

    #[test]
    fn test_compute_diffs_all_different() {
        let a = [1, 2, 3];
        let b = [4, 5, 6];
        let result = compute_diffs_address_set(0, &a, &b);
        assert_eq!(result.range_count(), 1);
        assert_eq!(result.min_address(), Some(0));
        assert_eq!(result.max_address(), Some(2));
    }

    #[test]
    fn test_address_set_empty() {
        let set = AddressSet::new();
        assert!(set.is_empty());
        assert_eq!(set.range_count(), 0);
        assert_eq!(set.min_address(), None);
        assert_eq!(set.max_address(), None);
    }

    #[test]
    fn test_address_set_add_range() {
        let mut set = AddressSet::new();
        set.add_range(10, 20);
        set.add_range(30, 40);
        assert_eq!(set.range_count(), 2);
        assert!(set.contains(10));
        assert!(set.contains(15));
        assert!(set.contains(20));
        assert!(!set.contains(25));
        assert!(set.contains(30));
    }

    #[test]
    fn test_address_set_merge_adjacent() {
        let mut set = AddressSet::new();
        set.add_range(10, 20);
        set.add_range(21, 30);
        assert_eq!(set.range_count(), 1); // merged
        assert_eq!(set.min_address(), Some(10));
        assert_eq!(set.max_address(), Some(30));
    }

    #[test]
    fn test_address_set_intersects() {
        let mut set = AddressSet::new();
        set.add_range(10, 20);
        assert!(set.intersects(15, 25));
        assert!(set.intersects(5, 15));
        assert!(!set.intersects(25, 30));
    }

    #[test]
    fn test_bytes_equal() {
        assert!(bytes_equal(&[1, 2, 3], &[1, 2, 3]));
        assert!(!bytes_equal(&[1, 2, 3], &[1, 2, 4]));
        assert!(!bytes_equal(&[1, 2], &[1, 2, 3]));
    }

    #[test]
    fn test_first_diff() {
        assert_eq!(first_diff(&[1, 2, 3], &[1, 2, 3]), None);
        assert_eq!(first_diff(&[1, 2, 3], &[1, 0, 3]), Some(1));
        assert_eq!(first_diff(&[0, 2, 3], &[1, 2, 3]), Some(0));
    }

    #[test]
    fn test_xor_bytes() {
        let a = [0xFF, 0x00, 0xAA];
        let b = [0xFF, 0xFF, 0x00];
        let result = xor_bytes(&a, &b);
        assert_eq!(result, vec![0x00, 0xFF, 0xAA]);
    }

    #[test]
    fn test_hash_bytes() {
        let h1 = hash_bytes(&[1, 2, 3]);
        let h2 = hash_bytes(&[1, 2, 3]);
        let h3 = hash_bytes(&[1, 2, 4]);
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_diff_range() {
        let r = DiffRange::new(10, 20);
        assert_eq!(r.len(), 11);
        assert!(!r.is_empty());
    }
}
