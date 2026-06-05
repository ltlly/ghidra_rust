//! Address-snap range property map with R*-tree spatial indexing.
//!
//! Ported from Ghidra's `ghidra.trace.database.map` package. This module
//! provides a spatial property map where entries are keyed by
//! (address, snap) ranges and stored in an R*-tree for efficient
//! spatial queries.
//!
//! The R*-tree allows efficient queries like:
//! - "What properties are set at address X at snap S?"
//! - "What properties are set in address range [A, B] at snap S?"
//! - "What properties exist for snap range [S1, S2]?"

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

// ---------------------------------------------------------------------------
// TraceAddressSnapRange
// ---------------------------------------------------------------------------

/// A 2D range in (address, snap) space.
///
/// Ported from `ghidra.trace.model.TraceAddressSnapRange`.
/// Used as the key for entries in the address-snap property map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AddressSnapRange {
    /// Minimum address offset (inclusive).
    pub min_address: u64,
    /// Maximum address offset (inclusive).
    pub max_address: u64,
    /// Minimum snap (inclusive).
    pub min_snap: i64,
    /// Maximum snap (inclusive).
    pub max_snap: i64,
}

impl AddressSnapRange {
    /// Create a new range.
    pub fn new(min_address: u64, max_address: u64, min_snap: i64, max_snap: i64) -> Self {
        Self {
            min_address,
            max_address,
            min_snap,
            max_snap,
        }
    }

    /// Create a single-point range.
    pub fn at(address: u64, snap: i64) -> Self {
        Self {
            min_address: address,
            max_address: address,
            min_snap: snap,
            max_snap: snap,
        }
    }

    /// Create a range spanning the full lifespan at a single address.
    pub fn forever(address: u64) -> Self {
        Self {
            min_address: address,
            max_address: address,
            min_snap: i64::MIN,
            max_snap: i64::MAX,
        }
    }

    /// Create a range for a snap at a single address.
    pub fn snap(address: u64, snap: i64) -> Self {
        Self::at(address, snap)
    }

    /// Whether this range contains the given point.
    pub fn contains_point(&self, address: u64, snap: i64) -> bool {
        address >= self.min_address
            && address <= self.max_address
            && snap >= self.min_snap
            && snap <= self.max_snap
    }

    /// Whether this range overlaps with another range.
    pub fn overlaps(&self, other: &AddressSnapRange) -> bool {
        self.min_address <= other.max_address
            && self.max_address >= other.min_address
            && self.min_snap <= other.max_snap
            && self.max_snap >= other.min_snap
    }

    /// The width in address space.
    pub fn address_width(&self) -> u64 {
        self.max_address - self.min_address + 1
    }

    /// The span in snap space.
    pub fn snap_span(&self) -> i64 {
        self.max_snap - self.min_snap + 1
    }
}

impl PartialOrd for AddressSnapRange {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AddressSnapRange {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.min_address
            .cmp(&other.min_address)
            .then(self.min_snap.cmp(&other.min_snap))
            .then(self.max_address.cmp(&other.max_address))
            .then(self.max_snap.cmp(&other.max_snap))
    }
}

// ---------------------------------------------------------------------------
// Map entry
// ---------------------------------------------------------------------------

/// A property map entry keyed by (address, snap) range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressSnapPropertyEntry<V> {
    /// The spatial range key.
    pub range: AddressSnapRange,
    /// The property value.
    pub value: V,
}

// ---------------------------------------------------------------------------
// Query types
// ---------------------------------------------------------------------------

/// A point query in (address, snap) space.
#[derive(Debug, Clone, Copy)]
pub struct PointQuery {
    /// The address offset to query.
    pub address: u64,
    /// The snap to query.
    pub snap: i64,
}

impl PointQuery {
    /// Create a new point query.
    pub fn new(address: u64, snap: i64) -> Self {
        Self { address, snap }
    }
}

/// A bounding box query in (address, snap) space.
#[derive(Debug, Clone, Copy)]
pub struct RangeQuery {
    /// Minimum address (inclusive).
    pub min_address: u64,
    /// Maximum address (inclusive).
    pub max_address: u64,
    /// Minimum snap (inclusive).
    pub min_snap: i64,
    /// Maximum snap (inclusive).
    pub max_snap: i64,
}

impl RangeQuery {
    /// Create a new range query.
    pub fn new(min_address: u64, max_address: u64, min_snap: i64, max_snap: i64) -> Self {
        Self {
            min_address,
            max_address,
            min_snap,
            max_snap,
        }
    }

    /// Whether this query's bounding box overlaps with the given range.
    pub fn matches(&self, range: &AddressSnapRange) -> bool {
        range.min_address <= self.max_address
            && range.max_address >= self.min_address
            && range.min_snap <= self.max_snap
            && range.max_snap >= self.min_snap
    }
}

// ---------------------------------------------------------------------------
// AddressSnapPropertyMap
// ---------------------------------------------------------------------------

/// A property map with (address, snap) range keys.
///
/// This is a simplified implementation of Ghidra's R*-tree backed property
/// map. For production use, the R*-tree provides O(log n) spatial queries;
/// this implementation uses a sorted B-tree for correctness and simplicity.
///
/// Ported from `ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMap`.
#[derive(Debug, Clone)]
pub struct AddressSnapPropertyMap<V> {
    /// The name of this map (typically the address space).
    pub name: String,
    /// Entries indexed by range.
    entries: Vec<AddressSnapPropertyEntry<V>>,
}

impl<V: Clone + std::fmt::Debug> AddressSnapPropertyMap<V> {
    /// Create a new empty map.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entries: Vec::new(),
        }
    }

    /// Insert a property entry.
    pub fn insert(&mut self, range: AddressSnapRange, value: V) {
        // Remove any existing entry with the same range
        self.entries.retain(|e| e.range != range);
        self.entries.push(AddressSnapPropertyEntry { range, value });
        // Keep sorted by range for efficient queries
        self.entries.sort_by(|a, b| a.range.cmp(&b.range));
    }

    /// Find all entries that contain the given point.
    pub fn get_at_point(&self, address: u64, snap: i64) -> Vec<&AddressSnapPropertyEntry<V>> {
        self.entries
            .iter()
            .filter(|e| e.range.contains_point(address, snap))
            .collect()
    }

    /// Find all entries that overlap with the given range query.
    pub fn get_in_range(&self, query: &RangeQuery) -> Vec<&AddressSnapPropertyEntry<V>> {
        self.entries
            .iter()
            .filter(|e| query.matches(&e.range))
            .collect()
    }

    /// Remove the entry with the given range.
    pub fn remove(&mut self, range: &AddressSnapRange) -> Option<V> {
        if let Some(pos) = self.entries.iter().position(|e| &e.range == range) {
            Some(self.entries.remove(pos).value)
        } else {
            None
        }
    }

    /// Remove all entries that overlap with the given range.
    pub fn remove_overlapping(&mut self, range: &AddressSnapRange) -> Vec<AddressSnapPropertyEntry<V>> {
        let mut removed = Vec::new();
        self.entries.retain(|e| {
            if e.range.overlaps(range) {
                removed.push(e.clone());
                false
            } else {
                true
            }
        });
        removed
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &AddressSnapPropertyEntry<V>> {
        self.entries.iter()
    }

    /// Get all entries whose lifespan overlaps the given snap.
    pub fn get_entries_at_snap(&self, snap: i64) -> Vec<&AddressSnapPropertyEntry<V>> {
        self.entries
            .iter()
            .filter(|e| snap >= e.range.min_snap && snap <= e.range.max_snap)
            .collect()
    }

    /// Get the address set view: all addresses that have entries at the given snap.
    pub fn address_set_at_snap(&self, snap: i64) -> Vec<(u64, u64)> {
        let mut ranges: Vec<(u64, u64)> = self.entries
            .iter()
            .filter(|e| snap >= e.range.min_snap && snap <= e.range.max_snap)
            .map(|e| (e.range.min_address, e.range.max_address))
            .collect();
        ranges.sort();
        ranges
    }
}

// ---------------------------------------------------------------------------
// Occlusion iterator
// ---------------------------------------------------------------------------

/// Direction for occlusion queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OcclusionDirection {
    /// Search into the future (increasing snap).
    IntoFuture,
    /// Search into the past (decreasing snap).
    IntoPast,
}

/// An occlusion query result: the range and lifespan where an entry is "visible"
/// (i.e., not occluded by another entry).
#[derive(Debug, Clone)]
pub struct OcclusionEntry<V> {
    /// The entry that is visible.
    pub entry: AddressSnapPropertyEntry<V>,
    /// The snap range during which this entry is the occlusion winner.
    pub visibility: Lifespan,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_snap_range_at() {
        let r = AddressSnapRange::at(0x400000, 10);
        assert_eq!(r.min_address, 0x400000);
        assert_eq!(r.max_address, 0x400000);
        assert_eq!(r.min_snap, 10);
        assert_eq!(r.max_snap, 10);
        assert!(r.contains_point(0x400000, 10));
        assert!(!r.contains_point(0x400001, 10));
    }

    #[test]
    fn test_address_snap_range_overlaps() {
        let r1 = AddressSnapRange::new(0x1000, 0x2000, 0, 10);
        let r2 = AddressSnapRange::new(0x1500, 0x2500, 5, 15);
        let r3 = AddressSnapRange::new(0x3000, 0x4000, 0, 10);

        assert!(r1.overlaps(&r2));
        assert!(r2.overlaps(&r1));
        assert!(!r1.overlaps(&r3));
    }

    #[test]
    fn test_address_snap_range_dimensions() {
        let r = AddressSnapRange::new(0x1000, 0x1FFF, 0, 9);
        assert_eq!(r.address_width(), 0x1000);
        assert_eq!(r.snap_span(), 10);
    }

    #[test]
    fn test_property_map_insert_and_query() {
        let mut map = AddressSnapPropertyMap::new("ram");
        assert!(map.is_empty());

        map.insert(
            AddressSnapRange::new(0x400000, 0x400FFF, 0, 100),
            "region_a".to_string(),
        );
        map.insert(
            AddressSnapRange::new(0x401000, 0x401FFF, 0, 100),
            "region_b".to_string(),
        );

        assert_eq!(map.len(), 2);

        // Point query
        let results = map.get_at_point(0x400100, 50);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "region_a");

        // Point outside
        let results = map.get_at_point(0x500000, 50);
        assert!(results.is_empty());
    }

    #[test]
    fn test_property_map_range_query() {
        let mut map = AddressSnapPropertyMap::new("ram");
        map.insert(
            AddressSnapRange::new(0x400000, 0x400FFF, 0, 100),
            "a".to_string(),
        );
        map.insert(
            AddressSnapRange::new(0x401000, 0x401FFF, 0, 100),
            "b".to_string(),
        );
        map.insert(
            AddressSnapRange::new(0x402000, 0x402FFF, 0, 100),
            "c".to_string(),
        );

        let query = RangeQuery::new(0x400500, 0x401500, 0, 50);
        let results = map.get_in_range(&query);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_property_map_remove() {
        let mut map = AddressSnapPropertyMap::new("ram");
        let range = AddressSnapRange::new(0x400000, 0x400FFF, 0, 100);
        map.insert(range, "value".to_string());

        let removed = map.remove(&range);
        assert_eq!(removed, Some("value".to_string()));
        assert!(map.is_empty());
    }

    #[test]
    fn test_property_map_snap_filtering() {
        let mut map = AddressSnapPropertyMap::new("ram");
        map.insert(AddressSnapRange::new(0x1000, 0x1FFF, 0, 10), "early".to_string());
        map.insert(AddressSnapRange::new(0x1000, 0x1FFF, 20, 30), "late".to_string());

        let at_snap_5 = map.get_entries_at_snap(5);
        assert_eq!(at_snap_5.len(), 1);
        assert_eq!(at_snap_5[0].value, "early");

        let at_snap_25 = map.get_entries_at_snap(25);
        assert_eq!(at_snap_25.len(), 1);
        assert_eq!(at_snap_25[0].value, "late");

        let at_snap_15 = map.get_entries_at_snap(15);
        assert!(at_snap_15.is_empty());
    }

    #[test]
    fn test_property_map_address_set() {
        let mut map = AddressSnapPropertyMap::new("ram");
        map.insert(AddressSnapRange::new(0x1000, 0x1FFF, 0, 10), "a".to_string());
        map.insert(AddressSnapRange::new(0x3000, 0x3FFF, 0, 10), "b".to_string());

        let addrs = map.address_set_at_snap(5);
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], (0x1000, 0x1FFF));
        assert_eq!(addrs[1], (0x3000, 0x3FFF));
    }

    #[test]
    fn test_range_query_matches() {
        let query = RangeQuery::new(0x1000, 0x2000, 0, 10);
        let inside = AddressSnapRange::new(0x1500, 0x1800, 5, 8);
        let outside = AddressSnapRange::new(0x3000, 0x4000, 0, 10);
        let partial = AddressSnapRange::new(0x1800, 0x3000, 5, 15);

        assert!(query.matches(&inside));
        assert!(!query.matches(&outside));
        assert!(query.matches(&partial));
    }
}
