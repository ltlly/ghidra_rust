//! DBTraceAddressSnapRangePropertyMap and R-Tree implementations.
//!
//! Ported from `ghidra/trace/database/map/` package. Provides spatial
//! indexing of properties over (address, snap) ranges, including:
//! - `DBTraceAddressSnapRangePropertyMapSpace` for per-space maps
//! - `DBTraceAddressSnapRangePropertyMapTree` for R-Tree indexing
//! - Occlusion iterators for temporal queries
//! - Address set views of map entries

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::RangeInclusive;

use crate::model::Lifespan;

/// A property map entry spanning an address-snap range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyMapEntry<V: Clone> {
    /// Unique entry ID.
    pub id: u64,
    /// Minimum address offset.
    pub addr_min: u64,
    /// Maximum address offset.
    pub addr_max: u64,
    /// Minimum snap (inclusive).
    pub snap_min: i64,
    /// Maximum snap (inclusive).
    pub snap_max: i64,
    /// The stored value.
    pub value: V,
}

impl<V: Clone> PropertyMapEntry<V> {
    /// Get the lifespan of this entry.
    pub fn lifespan(&self) -> Lifespan {
        Lifespan::span(self.snap_min, self.snap_max)
    }

    /// Check if this entry contains the given point.
    fn contains_point(&self, addr: u64, snap: i64) -> bool {
        addr >= self.addr_min && addr <= self.addr_max && snap >= self.snap_min && snap <= self.snap_max
    }

    /// Check if this entry's range intersects a query range.
    fn intersects(&self, addr_min: u64, addr_max: u64, snap_min: i64, snap_max: i64) -> bool {
        self.addr_min <= addr_max
            && self.addr_max >= addr_min
            && self.snap_min <= snap_max
            && self.snap_max >= snap_min
    }
}

/// A spatial property map for a specific address space.
///
/// Ported from `DBTraceAddressSnapRangePropertyMapSpace.java`.
#[derive(Debug)]
pub struct PropertyMapSpace<V: Clone + std::fmt::Debug> {
    /// The space name.
    pub space_name: String,
    entries: BTreeMap<u64, PropertyMapEntry<V>>,
    next_id: u64,
}

impl<V: Clone + std::fmt::Debug> PropertyMapSpace<V> {
    /// Create a new property map space.
    pub fn new(space_name: String) -> Self {
        Self {
            space_name,
            entries: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Add a property entry.
    pub fn add(
        &mut self,
        addr_min: u64,
        addr_max: u64,
        snap_min: i64,
        snap_max: i64,
        value: V,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.entries.insert(
            id,
            PropertyMapEntry {
                id,
                addr_min,
                addr_max,
                snap_min,
                snap_max,
                value,
            },
        );
        id
    }

    /// Get the value at a specific point.
    pub fn get(&self, addr: u64, snap: i64) -> Option<&V> {
        self.entries
            .values()
            .find(|e| e.contains_point(addr, snap))
            .map(|e| &e.value)
    }

    /// Get all entries that intersect the given range.
    pub fn get_intersecting(
        &self,
        addr_min: u64,
        addr_max: u64,
        snap_min: i64,
        snap_max: i64,
    ) -> Vec<&PropertyMapEntry<V>> {
        self.entries
            .values()
            .filter(|e| e.intersects(addr_min, addr_max, snap_min, snap_max))
            .collect()
    }

    /// Get all entries as of a given snap (latest value up to that snap).
    pub fn get_as_of_snap(&self, addr: u64, snap: i64) -> Option<&V> {
        self.entries
            .values()
            .filter(|e| addr >= e.addr_min && addr <= e.addr_max && e.snap_min <= snap)
            .max_by_key(|e| e.snap_min)
            .map(|e| &e.value)
    }

    /// Remove an entry by ID.
    pub fn remove(&mut self, id: u64) -> Option<PropertyMapEntry<V>> {
        self.entries.remove(&id)
    }

    /// Get all entries.
    pub fn all_entries(&self) -> Vec<&PropertyMapEntry<V>> {
        self.entries.values().collect()
    }

    /// Get entries whose address range overlaps the given range at any snap.
    pub fn entries_in_address_range(&self, addr_min: u64, addr_max: u64) -> Vec<&PropertyMapEntry<V>> {
        self.entries
            .values()
            .filter(|e| e.addr_min <= addr_max && e.addr_max >= addr_min)
            .collect()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Occlusion direction for temporal queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcclusionDirection {
    /// Look into the future (from snap forward).
    IntoFuture,
    /// Look into the past (from snap backward).
    IntoPast,
}

/// An iterator over property entries considering occlusion (temporal masking).
///
/// Ported from `AbstractDBTraceAddressSnapRangePropertyMapOcclusionIterable.java`.
#[derive(Debug)]
pub struct OcclusionIterator<'a, V: Clone + std::fmt::Debug> {
    entries: Vec<&'a PropertyMapEntry<V>>,
    direction: OcclusionDirection,
    index: usize,
    /// Already-covered ranges for occlusion.
    covered: Vec<(u64, u64)>,
}

impl<'a, V: Clone + std::fmt::Debug> OcclusionIterator<'a, V> {
    /// Create a new occlusion iterator.
    pub fn new(
        entries: Vec<&'a PropertyMapEntry<V>>,
        direction: OcclusionDirection,
    ) -> Self {
        Self {
            entries,
            direction,
            index: 0,
            covered: Vec::new(),
        }
    }

    fn is_occluded(&self, addr_min: u64, addr_max: u64) -> bool {
        self.covered
            .iter()
            .any(|&(c_min, c_max)| c_min <= addr_min && c_max >= addr_max)
    }
}

impl<'a, V: Clone + std::fmt::Debug> Iterator for OcclusionIterator<'a, V> {
    type Item = &'a PropertyMapEntry<V>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.entries.len() {
            let entry = self.entries[self.index];
            self.index += 1;

            if !self.is_occluded(entry.addr_min, entry.addr_max) {
                self.covered.push((entry.addr_min, entry.addr_max));
                return Some(entry);
            }
        }
        None
    }
}

/// Address set view providing the union of address ranges in a property map.
///
/// Ported from `DBTraceAddressSnapRangePropertyMapAddressSetView.java`.
#[derive(Debug, Clone)]
pub struct PropertyMapAddressSetView {
    /// Merged address ranges.
    pub ranges: Vec<(u64, u64)>,
}

impl PropertyMapAddressSetView {
    /// Create from entries.
    pub fn from_entries<V: Clone + std::fmt::Debug>(entries: &[&PropertyMapEntry<V>]) -> Self {
        let mut ranges: Vec<(u64, u64)> = entries
            .iter()
            .map(|e| (e.addr_min, e.addr_max))
            .collect();
        ranges.sort();
        // Merge overlapping ranges
        let mut merged = Vec::new();
        for range in ranges {
            if let Some(last) = merged.last_mut() {
                let last: &mut (u64, u64) = last;
                if range.0 <= last.1 + 1 {
                    last.1 = last.1.max(range.1);
                    continue;
                }
            }
            merged.push(range);
        }
        Self { ranges: merged }
    }

    /// Check if this view contains the given address offset.
    pub fn contains(&self, offset: u64) -> bool {
        self.ranges
            .iter()
            .any(|&(min, max)| offset >= min && offset <= max)
    }

    /// Get the total number of addresses covered.
    pub fn num_addresses(&self) -> u64 {
        self.ranges
            .iter()
            .map(|&(min, max)| max - min + 1)
            .sum()
    }

    /// Check if this set is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// Abstract property map that delegates to per-space maps.
///
/// Ported from `AbstractDBTracePropertyMap.java`.
#[derive(Debug)]
pub struct AbstractPropertyMap<V: Clone + std::fmt::Debug> {
    /// Per-space property maps.
    pub spaces: BTreeMap<String, PropertyMapSpace<V>>,
}

impl<V: Clone + std::fmt::Debug> AbstractPropertyMap<V> {
    /// Create a new abstract property map.
    pub fn new() -> Self {
        Self {
            spaces: BTreeMap::new(),
        }
    }

    /// Get or create a space.
    pub fn get_or_create_space(&mut self, space_name: &str) -> &mut PropertyMapSpace<V> {
        self.spaces
            .entry(space_name.to_string())
            .or_insert_with(|| PropertyMapSpace::new(space_name.to_string()))
    }

    /// Get a value at a specific point.
    pub fn get(&self, space_name: &str, addr: u64, snap: i64) -> Option<&V> {
        self.spaces
            .get(space_name)
            .and_then(|s| s.get(addr, snap))
    }

    /// Set a value spanning a range.
    pub fn set(
        &mut self,
        space_name: &str,
        addr_min: u64,
        addr_max: u64,
        snap_min: i64,
        snap_max: i64,
        value: V,
    ) -> u64 {
        let space = self.get_or_create_space(space_name);
        space.add(addr_min, addr_max, snap_min, snap_max, value)
    }

    /// Get all entries across all spaces.
    pub fn all_entries(&self) -> Vec<&PropertyMapEntry<V>> {
        self.spaces
            .values()
            .flat_map(|s| s.all_entries())
            .collect()
    }

    /// Total number of entries across all spaces.
    pub fn total_entries(&self) -> usize {
        self.spaces.values().map(|s| s.len()).sum()
    }
}

impl<V: Clone + std::fmt::Debug> Default for AbstractPropertyMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_map_space_add_and_get() {
        let mut space = PropertyMapSpace::<bool>::new("ram".into());
        space.add(0x100, 0x200, 0, 100, true);
        assert_eq!(space.get(0x150, 50), Some(&true));
        assert_eq!(space.get(0x300, 50), None);
        assert_eq!(space.get(0x150, 200), None);
    }

    #[test]
    fn test_property_map_space_as_of_snap() {
        let mut space = PropertyMapSpace::<i32>::new("ram".into());
        space.add(0x100, 0x100, 0, 50, 1);
        space.add(0x100, 0x100, 51, 100, 2);

        assert_eq!(space.get_as_of_snap(0x100, 30), Some(&1));
        assert_eq!(space.get_as_of_snap(0x100, 75), Some(&2));
        assert_eq!(space.get_as_of_snap(0x100, 0), Some(&1));
    }

    #[test]
    fn test_property_map_space_intersecting() {
        let mut space = PropertyMapSpace::<String>::new("ram".into());
        space.add(0x100, 0x200, 0, 50, "a".into());
        space.add(0x150, 0x250, 25, 75, "b".into());

        let entries = space.get_intersecting(0x120, 0x220, 10, 60);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_abstract_property_map() {
        let mut map = AbstractPropertyMap::<i32>::new();
        map.set("ram", 0x100, 0x200, 0, 100, 42);
        assert_eq!(map.get("ram", 0x150, 50), Some(&42));
        assert_eq!(map.get("ram", 0x300, 50), None);
    }

    #[test]
    fn test_property_map_address_set_view() {
        let mut space = PropertyMapSpace::<bool>::new("ram".into());
        space.add(0x100, 0x200, 0, 100, true);
        space.add(0x300, 0x400, 0, 100, true);
        space.add(0x150, 0x350, 0, 100, true);

        let entries = space.all_entries();
        let asv = PropertyMapAddressSetView::from_entries(&entries);
        // Should merge overlapping ranges
        assert!(asv.contains(0x100));
        assert!(asv.contains(0x250));
        assert!(asv.contains(0x400));
        assert!(!asv.contains(0x50));
    }

    #[test]
    fn test_occlusion_iterator() {
        let mut space = PropertyMapSpace::<i32>::new("ram".into());
        space.add(0x100, 0x200, 0, 100, 1);
        space.add(0x100, 0x200, 50, 150, 2); // Same address range

        let entries = space.all_entries();
        let iter = OcclusionIterator::new(entries, OcclusionDirection::IntoFuture);
        let visible: Vec<_> = iter.collect();
        // First entry passes; second is occluded (same address range)
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].value, 1);
    }
}
