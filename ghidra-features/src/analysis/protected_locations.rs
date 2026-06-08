//! Protected locations tracking for analysis.
//!
//! Ported from `AutoAnalysisManager`'s protected locations mechanism.
//!
//! During an analysis run, certain addresses that are known to contain
//! valid code are marked as "protected" to prevent them from being
//! cleared or overwritten by analysis passes. This module provides the
//! data structure for tracking these protected locations.

use std::collections::BTreeSet;
use std::fmt;

// ---------------------------------------------------------------------------
// ProtectedLocations
// ---------------------------------------------------------------------------

/// Tracks addresses that should be protected from clearing during analysis.
///
/// Ported from the `protectedLocations` field in `AutoAnalysisManager.java`.
/// When analysis creates new code (e.g., via disassembly), the resulting
/// addresses are added to the protected set to prevent subsequent analysis
/// passes from inadvertently clearing them.
///
/// The protected set is reset at the end of each analysis run.
///
/// # Usage
///
/// ```ignore
/// let mut protected = ProtectedLocations::new();
/// protected.add(0x1000);
/// protected.add_range(0x2000, 0x3000);
///
/// assert!(protected.contains(0x1000));
/// assert!(protected.contains(0x2500));
/// assert!(!protected.contains(0x4000));
/// ```
#[derive(Debug, Clone)]
pub struct ProtectedLocations {
    /// Individual protected addresses.
    addresses: BTreeSet<u64>,
    /// Protected ranges (start, end) where end is exclusive.
    ranges: Vec<(u64, u64)>,
}

impl ProtectedLocations {
    /// Create a new empty protected locations set.
    pub fn new() -> Self {
        Self {
            addresses: BTreeSet::new(),
            ranges: Vec::new(),
        }
    }

    /// Add a single address to the protected set.
    pub fn add(&mut self, addr: u64) {
        self.addresses.insert(addr);
    }

    /// Add a range of addresses to the protected set.
    ///
    /// # Arguments
    /// * `start` - Start address (inclusive).
    /// * `end` - End address (exclusive).
    pub fn add_range(&mut self, start: u64, end: u64) {
        if start < end {
            self.ranges.push((start, end));
        }
    }

    /// Add all addresses from an iterator.
    pub fn add_all<I: IntoIterator<Item = u64>>(&mut self, iter: I) {
        for addr in iter {
            self.addresses.insert(addr);
        }
    }

    /// Check if an address is protected.
    pub fn contains(&self, addr: u64) -> bool {
        if self.addresses.contains(&addr) {
            return true;
        }
        self.ranges.iter().any(|&(start, end)| addr >= start && addr < end)
    }

    /// Check if any address in the range is protected.
    pub fn intersects(&self, start: u64, end: u64) -> bool {
        // Check individual addresses in the range
        if self.addresses.range(start..end).next().is_some() {
            return true;
        }
        // Check range overlaps
        self.ranges
            .iter()
            .any(|&(r_start, r_end)| r_start < end && start < r_end)
    }

    /// Get the total number of individually protected addresses.
    pub fn address_count(&self) -> usize {
        self.addresses.len()
    }

    /// Get the number of protected ranges.
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// Whether the protected set is empty.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty() && self.ranges.is_empty()
    }

    /// Clear all protected locations.
    pub fn clear(&mut self) {
        self.addresses.clear();
        self.ranges.clear();
    }

    /// Get all individually protected addresses as a sorted vector.
    pub fn addresses(&self) -> Vec<u64> {
        self.addresses.iter().copied().collect()
    }

    /// Get all protected ranges.
    pub fn ranges(&self) -> &[(u64, u64)] {
        &self.ranges
    }

    /// Merge another set of protected locations into this one.
    pub fn merge(&mut self, other: &ProtectedLocations) {
        for &addr in &other.addresses {
            self.addresses.insert(addr);
        }
        for &range in &other.ranges {
            self.ranges.push(range);
        }
    }

    /// Create a new set containing only addresses present in both sets.
    pub fn intersection(&self, other: &ProtectedLocations) -> ProtectedLocations {
        let mut result = ProtectedLocations::new();
        for &addr in &self.addresses {
            if other.contains(addr) {
                result.addresses.insert(addr);
            }
        }
        result
    }
}

impl Default for ProtectedLocations {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ProtectedLocations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProtectedLocations({} addresses, {} ranges)",
            self.addresses.len(),
            self.ranges.len()
        )
    }
}

// ---------------------------------------------------------------------------
// ProtectedLocationGuard -- RAII guard for temporary protection
// ---------------------------------------------------------------------------

/// RAII guard that removes addresses from the protected set when dropped.
///
/// Useful for temporarily protecting addresses during a specific analysis
/// phase and automatically unprotecting them afterwards.
pub struct ProtectedLocationGuard<'a> {
    locations: &'a mut ProtectedLocations,
    addresses: Vec<u64>,
}

impl<'a> ProtectedLocationGuard<'a> {
    /// Create a new guard that protects the given addresses.
    pub fn new(locations: &'a mut ProtectedLocations, addresses: Vec<u64>) -> Self {
        for &addr in &addresses {
            locations.add(addr);
        }
        Self {
            locations,
            addresses,
        }
    }

    /// Get the protected addresses managed by this guard.
    pub fn addresses(&self) -> &[u64] {
        &self.addresses
    }
}

impl<'a> Drop for ProtectedLocationGuard<'a> {
    fn drop(&mut self) {
        for &addr in &self.addresses {
            self.locations.addresses.remove(&addr);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protected_locations_basic() {
        let mut protected = ProtectedLocations::new();
        assert!(protected.is_empty());

        protected.add(0x1000);
        assert!(!protected.is_empty());
        assert!(protected.contains(0x1000));
        assert!(!protected.contains(0x2000));
    }

    #[test]
    fn test_protected_locations_range() {
        let mut protected = ProtectedLocations::new();
        protected.add_range(0x1000, 0x2000);

        assert!(protected.contains(0x1000));
        assert!(protected.contains(0x1500));
        assert!(protected.contains(0x1FFF));
        assert!(!protected.contains(0x2000)); // end is exclusive
        assert!(!protected.contains(0x0FFF));
    }

    #[test]
    fn test_protected_locations_add_all() {
        let mut protected = ProtectedLocations::new();
        protected.add_all(vec![0x1000, 0x2000, 0x3000]);

        assert_eq!(protected.address_count(), 3);
        assert!(protected.contains(0x1000));
        assert!(protected.contains(0x2000));
        assert!(protected.contains(0x3000));
    }

    #[test]
    fn test_protected_locations_intersects() {
        let mut protected = ProtectedLocations::new();
        protected.add_range(0x1000, 0x2000);

        assert!(protected.intersects(0x1500, 0x1600)); // within range
        assert!(protected.intersects(0x0F00, 0x1100)); // overlaps start
        assert!(protected.intersects(0x1F00, 0x2100)); // overlaps end
        assert!(!protected.intersects(0x3000, 0x4000)); // no overlap
    }

    #[test]
    fn test_protected_locations_clear() {
        let mut protected = ProtectedLocations::new();
        protected.add(0x1000);
        protected.add_range(0x2000, 0x3000);

        protected.clear();
        assert!(protected.is_empty());
        assert!(!protected.contains(0x1000));
    }

    #[test]
    fn test_protected_locations_merge() {
        let mut p1 = ProtectedLocations::new();
        p1.add(0x1000);

        let mut p2 = ProtectedLocations::new();
        p2.add(0x2000);
        p2.add_range(0x3000, 0x4000);

        p1.merge(&p2);
        assert!(p1.contains(0x1000));
        assert!(p1.contains(0x2000));
        assert!(p1.contains(0x3500));
    }

    #[test]
    fn test_protected_locations_intersection() {
        let mut p1 = ProtectedLocations::new();
        p1.add(0x1000);
        p1.add(0x2000);
        p1.add(0x3000);

        let mut p2 = ProtectedLocations::new();
        p2.add(0x2000);
        p2.add(0x3000);
        p2.add(0x4000);

        let intersection = p1.intersection(&p2);
        assert_eq!(intersection.address_count(), 2);
        assert!(!intersection.contains(0x1000));
        assert!(intersection.contains(0x2000));
        assert!(intersection.contains(0x3000));
        assert!(!intersection.contains(0x4000));
    }

    #[test]
    fn test_protected_locations_empty_range() {
        let mut protected = ProtectedLocations::new();
        protected.add_range(0x2000, 0x1000); // start >= end, should be ignored
        assert!(protected.is_empty());
    }

    #[test]
    fn test_protected_location_guard() {
        let mut protected = ProtectedLocations::new();

        // Create the guard which adds the addresses
        {
            let guard =
                ProtectedLocationGuard::new(&mut protected, vec![0x1000, 0x2000]);
            // Verify the guard holds the expected addresses
            assert_eq!(guard.addresses(), &[0x1000, 0x2000]);
        }
        // Guard is now dropped, removing the mutable borrow

        // Addresses were added by the guard, so they are still present
        // (guard only removes addresses on drop)
        // Wait -- the guard removes them on drop. So after the block,
        // the addresses are removed. Let's verify by checking the
        // behavior: add manually, then verify guard cleanup works.
        protected.add(0x1000);
        protected.add(0x2000);
        assert!(protected.contains(0x1000));
        assert!(protected.contains(0x2000));

        {
            let _guard =
                ProtectedLocationGuard::new(&mut protected, vec![0x3000]);
        }
        // After guard is dropped, its addresses should be removed
        assert!(!protected.contains(0x3000));
        // The manually added addresses should still be present
        assert!(protected.contains(0x1000));
        assert!(protected.contains(0x2000));
    }

    #[test]
    fn test_protected_locations_display() {
        let mut protected = ProtectedLocations::new();
        protected.add(0x1000);
        protected.add_range(0x2000, 0x3000);

        let s = protected.to_string();
        assert!(s.contains("1 addresses"));
        assert!(s.contains("1 ranges"));
    }

    #[test]
    fn test_protected_locations_sorted_output() {
        let mut protected = ProtectedLocations::new();
        protected.add(0x3000);
        protected.add(0x1000);
        protected.add(0x2000);

        let addrs = protected.addresses();
        assert_eq!(addrs, vec![0x1000, 0x2000, 0x3000]);
    }
}
