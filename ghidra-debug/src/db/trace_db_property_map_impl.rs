//! Property map implementation for trace database.
//!
//! Ported from Ghidra's Framework-TraceModeling `AbstractDBTracePropertyRangeMap`
//! and concrete property map types. Provides address-snap-keyed property
//! storage with range queries and occlusion handling.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A property map entry covering a range of addresses and snaps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyMapRangeEntry<V: Clone> {
    /// Minimum address offset (inclusive).
    pub min_offset: u64,
    /// Maximum address offset (inclusive).
    pub max_offset: u64,
    /// The lifespan (snap range) this property is valid for.
    pub lifespan: Lifespan,
    /// The stored value.
    pub value: V,
}

impl<V: Clone> PropertyMapRangeEntry<V> {
    /// Create a new property map entry.
    pub fn new(min_offset: u64, max_offset: u64, lifespan: Lifespan, value: V) -> Self {
        Self {
            min_offset,
            max_offset,
            lifespan,
            value,
        }
    }

    /// Create a point entry (single address, single snap).
    pub fn point(offset: u64, snap: i64, value: V) -> Self {
        Self {
            min_offset: offset,
            max_offset: offset,
            lifespan: Lifespan::at(snap),
            value,
        }
    }

    /// Check if this entry covers the given offset at the given snap.
    pub fn contains(&self, offset: u64, snap: i64) -> bool {
        offset >= self.min_offset
            && offset <= self.max_offset
            && self.lifespan.contains(snap)
    }

    /// The number of addresses covered.
    pub fn address_length(&self) -> u64 {
        self.max_offset - self.min_offset + 1
    }
}

/// An address-space-scoped property map for trace data.
///
/// Stores properties keyed by (address, snap) pairs. Supports range queries
/// and manages property lifecycle including occlusion (overlapping entries).
#[derive(Debug, Clone)]
pub struct TracePropertyRangeMap<V: Clone> {
    /// The address space name this map belongs to.
    space_name: String,
    /// The property entries sorted by (min_offset, min_snap).
    entries: Vec<PropertyMapRangeEntry<V>>,
}

impl<V: Clone> TracePropertyRangeMap<V> {
    /// Create a new empty property map for the given address space.
    pub fn new(space_name: impl Into<String>) -> Self {
        Self {
            space_name: space_name.into(),
            entries: Vec::new(),
        }
    }

    /// Get the address space name.
    pub fn space_name(&self) -> &str {
        &self.space_name
    }

    /// Add a property entry.
    pub fn add(&mut self, entry: PropertyMapRangeEntry<V>) {
        self.entries.push(entry);
    }

    /// Set a property value at a specific address and snap.
    pub fn set(&mut self, offset: u64, snap: i64, value: V) {
        self.entries.push(PropertyMapRangeEntry::point(offset, snap, value));
    }

    /// Set a property over a range of addresses and a lifespan.
    pub fn set_range(
        &mut self,
        min_offset: u64,
        max_offset: u64,
        lifespan: Lifespan,
        value: V,
    ) {
        self.entries
            .push(PropertyMapRangeEntry::new(min_offset, max_offset, lifespan, value));
    }

    /// Get the property value at the given offset and snap.
    ///
    /// Returns the most recently added entry that covers the given position.
    pub fn get(&self, offset: u64, snap: i64) -> Option<&V> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.contains(offset, snap))
            .map(|e| &e.value)
    }

    /// Get all entries that cover the given offset at the given snap.
    pub fn get_all(&self, offset: u64, snap: i64) -> Vec<&PropertyMapRangeEntry<V>> {
        self.entries
            .iter()
            .filter(|e| e.contains(offset, snap))
            .collect()
    }

    /// Get all entries within a range of addresses and snaps.
    pub fn get_range(
        &self,
        min_offset: u64,
        max_offset: u64,
        lifespan: &Lifespan,
    ) -> Vec<&PropertyMapRangeEntry<V>> {
        self.entries
            .iter()
            .filter(|e| {
                e.min_offset <= max_offset
                    && e.max_offset >= min_offset
                    && e.lifespan.intersects(lifespan)
            })
            .collect()
    }

    /// Remove all entries that are fully contained within the given span
    /// and address range. Returns the number of entries removed.
    pub fn clear_range(
        &mut self,
        min_offset: u64,
        max_offset: u64,
        lifespan: &Lifespan,
    ) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| {
            !(e.min_offset >= min_offset
                && e.max_offset <= max_offset
                && lifespan.encloses(&e.lifespan))
        });
        before - self.entries.len()
    }

    /// Truncate entries that overlap with the given span, making room for new data.
    ///
    /// If an entry's start snap is contained in the given span, the entry is removed.
    /// Otherwise, its end snap is truncated.
    pub fn make_way(&mut self, min_offset: u64, max_offset: u64, lifespan: &Lifespan) {
        self.entries.retain_mut(|e| {
            if e.min_offset > max_offset || e.max_offset < min_offset {
                return true; // No address overlap
            }
            if lifespan.contains(e.lifespan.lmin()) {
                return false; // Remove: start is within the span to clear
            }
            if e.lifespan.intersects(lifespan) {
                // Truncate: set end snap to one less than the clearing span's start
                let new_max = lifespan.lmin() - 1;
                if new_max >= e.lifespan.lmin() {
                    e.lifespan = Lifespan::span(e.lifespan.lmin(), new_max);
                }
            }
            true
        });
    }

    /// Get the number of entries in the map.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &PropertyMapRangeEntry<V>> {
        self.entries.iter()
    }

    /// Remove all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Remove entries by predicate.
    pub fn remove_where<F: Fn(&PropertyMapRangeEntry<V>) -> bool>(&mut self, pred: F) {
        self.entries.retain(|e| !pred(e));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_entry_contains() {
        let entry = PropertyMapRangeEntry::new(0x1000, 0x1FFF, Lifespan::span(0, 100), 42u32);
        assert!(entry.contains(0x1000, 50));
        assert!(entry.contains(0x1FFF, 0));
        assert!(entry.contains(0x1500, 100));
        assert!(!entry.contains(0x2000, 50)); // out of address range
        assert!(!entry.contains(0x1000, 101)); // out of lifespan
    }

    #[test]
    fn test_property_map_set_get() {
        let mut map = TracePropertyRangeMap::<String>::new("ram");
        // set() creates a point entry at the exact snap
        map.set(0x400000, 0, "hello".to_string());
        map.set(0x400000, 5, "world".to_string());

        assert_eq!(map.get(0x400000, 0), Some(&"hello".to_string()));
        assert_eq!(map.get(0x400000, 5), Some(&"world".to_string()));
        // snap 3 is not covered by either point entry
        assert_eq!(map.get(0x400000, 3), None);
        assert_eq!(map.get(0x400001, 0), None);

        // Use set_range for a wider lifespan
        map.set_range(0x400000, 0x400000, Lifespan::span(10, 20), "range_val".to_string());
        assert_eq!(map.get(0x400000, 15), Some(&"range_val".to_string()));
        assert_eq!(map.get(0x400000, 25), None);
    }

    #[test]
    fn test_property_map_range_query() {
        let mut map = TracePropertyRangeMap::<i32>::new("ram");
        map.set_range(0x1000, 0x1FFF, Lifespan::span(0, 50), 1);
        map.set_range(0x2000, 0x2FFF, Lifespan::span(0, 50), 2);

        let results = map.get_range(0x1500, 0x2500, &Lifespan::span(25, 75));
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_property_map_clear() {
        let mut map = TracePropertyRangeMap::<i32>::new("ram");
        map.set_range(0x1000, 0x1FFF, Lifespan::span(0, 100), 1);
        map.set_range(0x1000, 0x1FFF, Lifespan::span(50, 200), 2);

        let removed = map.clear_range(0x1000, 0x1FFF, &Lifespan::span(0, 100));
        assert_eq!(removed, 1);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_property_map_make_way() {
        let mut map = TracePropertyRangeMap::<i32>::new("ram");
        map.set_range(0x1000, 0x1FFF, Lifespan::span(0, 200), 1);

        map.make_way(0x1000, 0x1FFF, &Lifespan::span(50, 100));

        // Entry starts at 0, so should be truncated to end at 49
        assert_eq!(map.len(), 1);
        let entry = &map.entries[0];
        assert_eq!(entry.lifespan.lmin(), 0);
        assert_eq!(entry.lifespan.lmax(), 49);
    }

    #[test]
    fn test_point_entry() {
        let entry = PropertyMapRangeEntry::<bool>::point(0x400000, 10, true);
        assert!(entry.contains(0x400000, 10));
        assert!(!entry.contains(0x400000, 11));
        assert_eq!(entry.address_length(), 1);
    }
}
