//! TraceAddressSnapRangePropertyMap - maps from address+snap ranges to values.
//!
//! Ported from Ghidra's `ghidra.trace.model.map` package.
//! Provides a 3D property map keyed by (address_range, snap_range, value).

use serde::{Deserialize, Serialize};

use super::{Lifespan, TraceAddressSnapRange};

/// An entry in the address-snap range property map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressSnapRangeEntry<V: Clone> {
    /// The address-snap range.
    pub range: TraceAddressSnapRange,
    /// The value.
    pub value: V,
}

impl<V: Clone> AddressSnapRangeEntry<V> {
    /// Create a new entry.
    pub fn new(range: TraceAddressSnapRange, value: V) -> Self {
        Self { range, value }
    }

    /// Whether this entry contains the given address at the given snap.
    pub fn contains(&self, address: u64, snap: i64) -> bool {
        self.range.contains(address, snap)
    }
}

/// A property map keyed by address-snap ranges.
///
/// Maps (min_addr, max_addr, min_snap, max_snap) -> V. Supports querying
/// the value at a specific (address, snap) point.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceAddressSnapRangePropertyMap<V: Clone> {
    entries: Vec<AddressSnapRangeEntry<V>>,
}

impl<V: Clone> TraceAddressSnapRangePropertyMap<V> {
    /// Create a new empty map.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Set a value for an address-snap range.
    pub fn set(
        &mut self,
        min_address: u64,
        max_address: u64,
        min_snap: i64,
        max_snap: i64,
        value: V,
    ) {
        let range = TraceAddressSnapRange::new(
            min_address,
            max_address,
            Lifespan::span(min_snap, max_snap),
        );
        self.entries.push(AddressSnapRangeEntry::new(range, value));
    }

    /// Get the most recent value at the given address and snap.
    pub fn get(&self, address: u64, snap: i64) -> Option<&V> {
        self.entries
            .iter()
            .filter(|e| e.contains(address, snap))
            .max_by_key(|e| e.range.lifespan.lmin())
            .map(|e| &e.value)
    }

    /// Get all entries that contain the given address and snap.
    pub fn get_all(&self, address: u64, snap: i64) -> Vec<&AddressSnapRangeEntry<V>> {
        self.entries
            .iter()
            .filter(|e| e.contains(address, snap))
            .collect()
    }

    /// Remove entries that overlap with the given range.
    pub fn remove(
        &mut self,
        min_address: u64,
        max_address: u64,
        min_snap: i64,
        max_snap: i64,
    ) {
        let remove_range = Lifespan::span(min_snap, max_snap);
        self.entries.retain(|e| {
            !e.range.lifespan.intersects(&remove_range)
                || (e.range.min_offset > max_address || e.range.max_offset < min_address)
        });
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries.
    pub fn entries(&self) -> &[AddressSnapRangeEntry<V>] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get() {
        let mut map: TraceAddressSnapRangePropertyMap<String> = TraceAddressSnapRangePropertyMap::new();
        map.set(0x100, 0x1ff, 0, 10, "region1".into());
        map.set(0x200, 0x2ff, 5, 20, "region2".into());

        assert_eq!(map.get(0x150, 5), Some(&"region1".to_string()));
        assert_eq!(map.get(0x250, 10), Some(&"region2".to_string()));
        assert!(map.get(0x300, 5).is_none());
        assert!(map.get(0x150, 15).is_none()); // snap 15 outside range [0,10]
    }

    #[test]
    fn test_get_all() {
        let mut map: TraceAddressSnapRangePropertyMap<i32> = TraceAddressSnapRangePropertyMap::new();
        map.set(0x100, 0x1ff, 0, 10, 1);
        map.set(0x100, 0x1ff, 5, 20, 2);

        let all = map.get_all(0x150, 7);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_remove() {
        let mut map: TraceAddressSnapRangePropertyMap<i32> = TraceAddressSnapRangePropertyMap::new();
        map.set(0x100, 0x1ff, 0, 10, 1);
        map.set(0x200, 0x2ff, 0, 10, 2);

        map.remove(0x100, 0x1ff, 0, 10);
        assert!(map.get(0x150, 5).is_none());
        assert!(map.get(0x250, 5).is_some());
    }

    #[test]
    fn test_empty_map() {
        let map: TraceAddressSnapRangePropertyMap<bool> = TraceAddressSnapRangePropertyMap::new();
        assert!(map.is_empty());
        assert!(map.get(0, 0).is_none());
    }
}
