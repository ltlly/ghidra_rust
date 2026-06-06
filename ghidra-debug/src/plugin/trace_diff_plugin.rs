//! Debugger Trace View Diff Plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.diff.DebuggerTraceViewDiffPlugin`.
//! Provides the ability to compare memory state between two snapshots (points in time)
//! in a trace. The comparison is limited to raw bytes.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The state of a diff comparison session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DiffSessionState {
    /// No comparison is active.
    Inactive,
    /// A comparison is being computed.
    Computing,
    /// A comparison is active and displayed.
    Active,
}

impl Default for DiffSessionState {
    fn default() -> Self {
        Self::Inactive
    }
}

/// A configuration for the trace view diff plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDiffPluginConfig {
    /// The block size in bytes for memory comparison.
    pub block_size: usize,
    /// Color for highlighting differences.
    pub diff_color: (u8, u8, u8),
    /// Whether to show marker annotations for differences.
    pub show_markers: bool,
}

impl Default for TraceDiffPluginConfig {
    fn default() -> Self {
        Self {
            block_size: 4096,
            diff_color: (255, 200, 200),
            show_markers: true,
        }
    }
}

/// Represents a contiguous range of addresses that differ between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DiffRange {
    /// Start address (offset).
    pub min: u64,
    /// End address (offset, inclusive).
    pub max: u64,
}

impl DiffRange {
    /// Create a new diff range.
    pub fn new(min: u64, max: u64) -> Self {
        assert!(min <= max, "min must be <= max");
        Self { min, max }
    }

    /// Create a single-address range.
    pub fn single(addr: u64) -> Self {
        Self { min: addr, max: addr }
    }

    /// The length of this range.
    pub fn len(&self) -> u64 {
        self.max - self.min + 1
    }

    /// Whether this range is empty (shouldn't happen with valid ranges).
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Whether this range contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.min && addr <= self.max
    }

    /// Whether this range overlaps with another.
    pub fn overlaps(&self, other: &DiffRange) -> bool {
        self.min <= other.max && other.min <= self.max
    }

    /// Merge this range with another (assumes they overlap or are adjacent).
    pub fn merge(&self, other: &DiffRange) -> DiffRange {
        DiffRange {
            min: self.min.min(other.min),
            max: self.max.max(other.max),
        }
    }
}

/// A sorted set of diff ranges.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiffAddressSet {
    ranges: Vec<DiffRange>,
}

impl DiffAddressSet {
    /// Create an empty address set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The number of contiguous ranges.
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// Get all ranges.
    pub fn ranges(&self) -> &[DiffRange] {
        &self.ranges
    }

    /// The total number of bytes covered.
    pub fn total_bytes(&self) -> u64 {
        self.ranges.iter().map(|r| r.len()).sum()
    }

    /// Add a range to the set, merging with existing overlapping ranges.
    pub fn add_range(&mut self, range: DiffRange) {
        let mut new_ranges = Vec::new();
        let mut merged = range;

        for existing in &self.ranges {
            if merged.overlaps(existing) || existing.max + 1 == merged.min || merged.max + 1 == existing.min {
                merged = merged.merge(existing);
            } else if existing.max < merged.min {
                new_ranges.push(existing.clone());
            } else {
                new_ranges.push(merged.clone());
                merged = existing.clone();
            }
        }
        new_ranges.push(merged);
        new_ranges.sort_by_key(|r| r.min);
        self.ranges = new_ranges;
    }

    /// Add a single address.
    pub fn add_address(&mut self, addr: u64) {
        self.add_range(DiffRange::single(addr));
    }

    /// Add a contiguous range from min to max (inclusive).
    pub fn add(&mut self, min: u64, max: u64) {
        self.add_range(DiffRange::new(min, max));
    }

    /// Get the minimum address in the set.
    pub fn min_address(&self) -> Option<u64> {
        self.ranges.first().map(|r| r.min)
    }

    /// Get the maximum address in the set.
    pub fn max_address(&self) -> Option<u64> {
        self.ranges.last().map(|r| r.max)
    }

    /// Get the range containing the given address.
    pub fn get_range_containing(&self, addr: u64) -> Option<&DiffRange> {
        self.ranges.iter().find(|r| r.contains(addr))
    }

    /// Check whether the set contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        self.get_range_containing(addr).is_some()
    }

    /// Intersect this set with another.
    pub fn intersect(&self, other: &DiffAddressSet) -> DiffAddressSet {
        let mut result = DiffAddressSet::new();
        for r1 in &self.ranges {
            for r2 in &other.ranges {
                if r1.overlaps(r2) {
                    let min = r1.min.max(r2.min);
                    let max = r1.max.min(r2.max);
                    result.add_range(DiffRange::new(min, max));
                }
            }
        }
        result
    }

    /// Compute the union of two sets.
    pub fn union(&self, other: &DiffAddressSet) -> DiffAddressSet {
        let mut result = self.clone();
        for range in &other.ranges {
            result.add_range(range.clone());
        }
        result
    }
}

/// The result of computing a diff between two trace snapshots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotDiffResult {
    /// The left (current) snap.
    pub snap_left: i64,
    /// The right (alternate) snap.
    pub snap_right: i64,
    /// Set of addresses where bytes differ.
    pub diff_set: DiffAddressSet,
    /// Time taken to compute in milliseconds.
    pub compute_time_ms: u64,
}

impl SnapshotDiffResult {
    /// Create a new empty diff result.
    pub fn new(snap_left: i64, snap_right: i64) -> Self {
        Self {
            snap_left,
            snap_right,
            ..Default::default()
        }
    }

    /// Whether there are any differences.
    pub fn has_differences(&self) -> bool {
        !self.diff_set.is_empty()
    }

    /// Number of differing byte ranges.
    pub fn range_count(&self) -> usize {
        self.diff_set.range_count()
    }

    /// Total number of differing bytes.
    pub fn byte_count(&self) -> u64 {
        self.diff_set.total_bytes()
    }

    /// Whether this is a degenerate comparison (same snap on both sides).
    pub fn is_degenerate(&self) -> bool {
        self.snap_left == self.snap_right
    }
}

/// Compare two byte buffers and record differing address ranges.
///
/// This function compares `buf1` and `buf2` byte-by-byte starting at `base_addr`,
/// and records the contiguous ranges of differences in the result.
pub fn compare_bytes(
    result: &mut DiffAddressSet,
    base_addr: u64,
    buf1: &[u8],
    buf2: &[u8],
) {
    let len = buf1.len().min(buf2.len());
    let mut range_start: Option<u64> = None;

    for i in 0..len {
        if buf1[i] != buf2[i] {
            if range_start.is_none() {
                range_start = Some(base_addr + i as u64);
            }
        } else if let Some(start) = range_start.take() {
            result.add(start, base_addr + i as u64 - 1);
        }
    }

    if let Some(start) = range_start {
        result.add(start, base_addr + len as u64 - 1);
    }
}

/// Compute the minimum address within a block for the given offset.
pub fn min_of_block(block_size: usize, offset: u64) -> u64 {
    offset / block_size as u64 * block_size as u64
}

/// Compute the maximum address within a block for the given offset.
pub fn max_of_block(block_size: usize, offset: u64) -> u64 {
    (offset + block_size as u64 - 1) / block_size as u64 * block_size as u64 - 1
}

/// Compute the remaining bytes in the current block.
pub fn len_remains_block(block_size: usize, offset: u64) -> usize {
    block_size - (offset % block_size as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_session_state() {
        assert_eq!(DiffSessionState::default(), DiffSessionState::Inactive);
        assert_eq!(DiffSessionState::Inactive, DiffSessionState::Inactive);
        assert_ne!(DiffSessionState::Active, DiffSessionState::Computing);
    }

    #[test]
    fn test_diff_range() {
        let r = DiffRange::new(100, 200);
        assert_eq!(r.len(), 101);
        assert!(r.contains(150));
        assert!(r.contains(100));
        assert!(r.contains(200));
        assert!(!r.contains(99));
        assert!(!r.contains(201));
    }

    #[test]
    fn test_diff_range_single() {
        let r = DiffRange::single(42);
        assert_eq!(r.min, 42);
        assert_eq!(r.max, 42);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn test_diff_range_overlaps() {
        let a = DiffRange::new(10, 20);
        let b = DiffRange::new(15, 25);
        let c = DiffRange::new(30, 40);
        assert!(a.overlaps(&b));
        assert!(b.overlaps(&a));
        assert!(!a.overlaps(&c));
        assert!(!c.overlaps(&a));
    }

    #[test]
    fn test_diff_range_merge() {
        let a = DiffRange::new(10, 20);
        let b = DiffRange::new(15, 30);
        let merged = a.merge(&b);
        assert_eq!(merged.min, 10);
        assert_eq!(merged.max, 30);
    }

    #[test]
    fn test_diff_address_set_add() {
        let mut set = DiffAddressSet::new();
        assert!(set.is_empty());

        set.add(100, 200);
        assert_eq!(set.range_count(), 1);
        assert_eq!(set.total_bytes(), 101);

        // Add non-overlapping range
        set.add(300, 400);
        assert_eq!(set.range_count(), 2);
        assert_eq!(set.total_bytes(), 202);
    }

    #[test]
    fn test_diff_address_set_merge_adjacent() {
        let mut set = DiffAddressSet::new();
        set.add(100, 200);
        set.add(201, 300);
        assert_eq!(set.range_count(), 1);
        assert_eq!(set.min_address(), Some(100));
        assert_eq!(set.max_address(), Some(300));
    }

    #[test]
    fn test_diff_address_set_merge_overlapping() {
        let mut set = DiffAddressSet::new();
        set.add(100, 200);
        set.add(150, 250);
        assert_eq!(set.range_count(), 1);
        assert_eq!(set.min_address(), Some(100));
        assert_eq!(set.max_address(), Some(250));
    }

    #[test]
    fn test_diff_address_set_contains() {
        let mut set = DiffAddressSet::new();
        set.add(100, 200);
        assert!(set.contains(150));
        assert!(set.contains(100));
        assert!(!set.contains(50));
    }

    #[test]
    fn test_diff_address_set_intersect() {
        let mut a = DiffAddressSet::new();
        a.add(100, 200);
        a.add(300, 400);

        let mut b = DiffAddressSet::new();
        b.add(150, 350);

        let c = a.intersect(&b);
        assert_eq!(c.range_count(), 2);
        assert!(c.contains(150));
        assert!(c.contains(300));
        assert!(!c.contains(100));
        assert!(!c.contains(400));
    }

    #[test]
    fn test_diff_address_set_union() {
        let mut a = DiffAddressSet::new();
        a.add(100, 200);

        let mut b = DiffAddressSet::new();
        b.add(300, 400);

        let c = a.union(&b);
        assert_eq!(c.range_count(), 2);
        assert_eq!(c.min_address(), Some(100));
        assert_eq!(c.max_address(), Some(400));
    }

    #[test]
    fn test_compare_bytes_no_diff() {
        let buf = vec![0u8; 100];
        let mut set = DiffAddressSet::new();
        compare_bytes(&mut set, 0, &buf, &buf);
        assert!(set.is_empty());
    }

    #[test]
    fn test_compare_bytes_single_diff() {
        let buf1 = vec![0u8; 10];
        let mut buf2 = vec![0u8; 10];
        buf2[5] = 0xFF;
        let mut set = DiffAddressSet::new();
        compare_bytes(&mut set, 0, &buf1, &buf2);
        assert_eq!(set.range_count(), 1);
        assert!(set.contains(5));
        assert!(!set.contains(4));
    }

    #[test]
    fn test_compare_bytes_range_diff() {
        let buf1 = vec![0u8; 20];
        let mut buf2 = vec![0u8; 20];
        for i in 5..10 {
            buf2[i] = 0xFF;
        }
        let mut set = DiffAddressSet::new();
        compare_bytes(&mut set, 0x400000, &buf1, &buf2);
        assert_eq!(set.range_count(), 1);
        assert!(set.contains(0x400005));
        assert!(set.contains(0x400009));
        assert!(!set.contains(0x400004));
    }

    #[test]
    fn test_compare_bytes_multiple_ranges() {
        let buf1 = vec![0u8; 20];
        let mut buf2 = vec![0u8; 20];
        buf2[2] = 0xFF;
        buf2[3] = 0xFF;
        buf2[10] = 0xFF;
        let mut set = DiffAddressSet::new();
        compare_bytes(&mut set, 0, &buf1, &buf2);
        assert_eq!(set.range_count(), 2);
    }

    #[test]
    fn test_block_utils() {
        assert_eq!(min_of_block(4096, 0x400100), 0x400000);
        assert_eq!(max_of_block(4096, 0x400100), 0x400FFF);
        assert_eq!(len_remains_block(4096, 0x400000), 4096);
        assert_eq!(len_remains_block(4096, 0x400100), 3840);
    }

    #[test]
    fn test_snapshot_diff_result() {
        let result = SnapshotDiffResult::new(0, 1);
        assert!(!result.has_differences());
        assert!(result.is_degenerate() == false);
        assert_eq!(result.range_count(), 0);
    }

    #[test]
    fn test_snapshot_diff_degenerate() {
        let result = SnapshotDiffResult::new(5, 5);
        assert!(result.is_degenerate());
    }

    #[test]
    fn test_snapshot_diff_with_differences() {
        let mut result = SnapshotDiffResult::new(0, 1);
        result.diff_set.add(0x400000, 0x400FFF);
        result.diff_set.add(0x500000, 0x5000FF);
        assert!(result.has_differences());
        assert_eq!(result.range_count(), 2);
        assert_eq!(result.byte_count(), 4096 + 256);
    }

    #[test]
    fn test_diff_plugin_config_default() {
        let config = TraceDiffPluginConfig::default();
        assert_eq!(config.block_size, 4096);
        assert!(config.show_markers);
    }

    #[test]
    fn test_diff_address_set_serde() {
        let mut set = DiffAddressSet::new();
        set.add(100, 200);
        set.add(300, 400);
        let json = serde_json::to_string(&set).unwrap();
        let back: DiffAddressSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back.range_count(), 2);
        assert_eq!(back.min_address(), Some(100));
    }

    #[test]
    fn test_snapshot_diff_result_serde() {
        let mut result = SnapshotDiffResult::new(0, 1);
        result.diff_set.add(0x400000, 0x4000FF);
        let json = serde_json::to_string(&result).unwrap();
        let back: SnapshotDiffResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.snap_left, 0);
        assert_eq!(back.snap_right, 1);
        assert!(back.has_differences());
    }

    #[test]
    fn test_diff_range_sorted_insertion() {
        let mut set = DiffAddressSet::new();
        set.add(500, 600);
        set.add(100, 200);
        set.add(300, 400);
        assert_eq!(set.min_address(), Some(100));
        assert_eq!(set.max_address(), Some(600));
        assert_eq!(set.range_count(), 3);
    }

    #[test]
    fn test_compare_bytes_empty_buffers() {
        let buf = vec![];
        let mut set = DiffAddressSet::new();
        compare_bytes(&mut set, 0, &buf, &buf);
        assert!(set.is_empty());
    }

    #[test]
    fn test_diff_address_set_get_range_containing() {
        let mut set = DiffAddressSet::new();
        set.add(100, 200);
        set.add(300, 400);
        let r = set.get_range_containing(150);
        assert!(r.is_some());
        assert_eq!(r.unwrap().min, 100);
        assert!(set.get_range_containing(250).is_none());
    }
}
