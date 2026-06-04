//! TracePropertyMap - address-property maps in a trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.property` package.
//! Provides maps from address ranges to arbitrary property values.

use serde::{Deserialize, Serialize};

use super::Lifespan;

/// An entry in a trace property map: an address range mapped to a value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracePropertyEntry<V: Clone> {
    /// Start offset.
    pub min_address: u64,
    /// End offset.
    pub max_address: u64,
    /// The property value.
    pub value: V,
    /// The lifespan of this entry.
    pub lifespan: Lifespan,
}

impl<V: Clone> TracePropertyEntry<V> {
    /// Create a new property entry.
    pub fn new(min_address: u64, max_address: u64, value: V, lifespan: Lifespan) -> Self {
        Self {
            min_address,
            max_address,
            value,
            lifespan,
        }
    }

    /// Whether this entry covers the given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.min_address && address <= self.max_address
    }

    /// The size of the range.
    pub fn size(&self) -> u64 {
        self.max_address - self.min_address + 1
    }
}

/// A property map that maps address ranges to values of type V.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracePropertyMap<V: Clone> {
    entries: Vec<TracePropertyEntry<V>>,
}

impl<V: Clone> TracePropertyMap<V> {
    /// Create a new empty property map.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a property entry.
    pub fn set(&mut self, min_address: u64, max_address: u64, value: V, lifespan: Lifespan) {
        self.entries.push(TracePropertyEntry::new(
            min_address,
            max_address,
            value,
            lifespan,
        ));
    }

    /// Get the property value at the given address and snap.
    pub fn get(&self, address: u64, snap: i64) -> Option<&V> {
        self.entries
            .iter()
            .filter(|e| e.contains(address) && e.lifespan.contains(snap))
            .max_by_key(|e| e.lifespan.lmin())
            .map(|e| &e.value)
    }

    /// Get all entries at a given snap.
    pub fn entries_at(&self, snap: i64) -> Vec<&TracePropertyEntry<V>> {
        self.entries
            .iter()
            .filter(|e| e.lifespan.contains(snap))
            .collect()
    }

    /// Remove entries at the given address range.
    pub fn remove(&mut self, min_address: u64, max_address: u64) {
        self.entries
            .retain(|e| e.min_address > max_address || e.max_address < min_address);
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// An address-based boolean property map (e.g., for tracking initialized bytes).
pub type TraceBoolPropertyMap = TracePropertyMap<bool>;

/// An address-based integer property map.
pub type TraceIntPropertyMap = TracePropertyMap<i64>;

/// An address-based string property map.
pub type TraceStringPropertyMap = TracePropertyMap<String>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_entry_contains() {
        let entry = TracePropertyEntry::new(0x100, 0x1ff, true, Lifespan::at(0));
        assert!(entry.contains(0x100));
        assert!(entry.contains(0x150));
        assert!(entry.contains(0x1ff));
        assert!(!entry.contains(0x200));
        assert!(!entry.contains(0x099));
        assert_eq!(entry.size(), 256);
    }

    #[test]
    fn test_property_map_set_and_get() {
        let mut map: TracePropertyMap<bool> = TracePropertyMap::new();
        map.set(0x100, 0x1ff, true, Lifespan::now_on(0));
        map.set(0x200, 0x2ff, false, Lifespan::now_on(0));

        assert_eq!(map.get(0x150, 5), Some(&true));
        assert_eq!(map.get(0x250, 5), Some(&false));
        assert!(map.get(0x300, 5).is_none());
    }

    #[test]
    fn test_property_map_lifespan() {
        let mut map: TracePropertyMap<i64> = TracePropertyMap::new();
        map.set(0x100, 0x100, 42, Lifespan::span(0, 5));
        map.set(0x100, 0x100, 99, Lifespan::now_on(6));

        assert_eq!(map.get(0x100, 3), Some(&42));
        assert_eq!(map.get(0x100, 10), Some(&99));
    }

    #[test]
    fn test_property_map_remove() {
        let mut map: TracePropertyMap<String> = TracePropertyMap::new();
        map.set(0x100, 0x1ff, "hello".into(), Lifespan::ALL);
        map.set(0x300, 0x3ff, "world".into(), Lifespan::ALL);

        map.remove(0x100, 0x1ff);
        assert!(map.get(0x150, 0).is_none());
        assert_eq!(map.get(0x350, 0), Some(&"world".to_string()));
    }

    #[test]
    fn test_property_map_serde() {
        let mut map: TracePropertyMap<bool> = TracePropertyMap::new();
        map.set(0x100, 0x1ff, true, Lifespan::ALL);
        let json = serde_json::to_string(&map).unwrap();
        let back: TracePropertyMap<bool> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.get(0x150, 0), Some(&true));
    }
}
