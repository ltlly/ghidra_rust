//! Property map model for the Debug framework.
//!
//! Ported from `ghidra.trace.model.property` — includes
//! [`TracePropertyMap`] and [`TraceAddressPropertyManager`].

use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// TracePropertyMap
// ---------------------------------------------------------------------------

/// A property map for a specific address space.
///
/// Ported from `ghidra.trace.model.property.TracePropertyMap`. Stores
/// key-value pairs associated with addresses, varying over time.
#[derive(Debug, Clone)]
pub struct TracePropertyMap {
    /// The address space name.
    pub space_name: String,
    /// Properties: (address, snap) -> value.
    entries: BTreeMap<(u64, i64), String>,
}

impl TracePropertyMap {
    /// Create a new property map for a space.
    pub fn new(space_name: impl Into<String>) -> Self {
        Self {
            space_name: space_name.into(),
            entries: BTreeMap::new(),
        }
    }

    /// Set a property value at an address, effective from a given snap.
    pub fn set(&mut self, address: u64, snap: i64, value: impl Into<String>) {
        self.entries.insert((address, snap), value.into());
    }

    /// Get the property value at an address for the given snap.
    ///
    /// Returns the most recent value set at or before the given snap.
    pub fn get(&self, address: u64, snap: i64) -> Option<&str> {
        self.entries
            .range(..=(address, snap))
            .next_back()
            .filter(|((addr, _), _)| *addr == address)
            .map(|(_, v)| v.as_str())
    }

    /// Remove the property at the given address.
    pub fn remove(&mut self, address: u64) {
        self.entries.retain(|(addr, _), _| *addr != address);
    }

    /// Remove the property at the given address effective from the given snap.
    pub fn remove_from(&mut self, address: u64, snap: i64) {
        self.entries.remove(&(address, snap));
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries at the given snap.
    pub fn entries_at_snap(&self, snap: i64) -> Vec<(u64, &str)> {
        let mut result: BTreeMap<u64, &str> = BTreeMap::new();
        for ((addr, s), val) in &self.entries {
            if *s <= snap {
                result.insert(*addr, val.as_str());
            }
        }
        result.into_iter().collect()
    }
}

impl fmt::Display for TracePropertyMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PropertyMap({}, {} entries)", self.space_name, self.len())
    }
}

// ---------------------------------------------------------------------------
// TraceAddressPropertyManager
// ---------------------------------------------------------------------------

/// Manages property maps across address spaces.
///
/// Ported from `ghidra.trace.model.property.TraceAddressPropertyManager`.
#[derive(Debug)]
pub struct TraceAddressPropertyManager {
    maps: BTreeMap<String, TracePropertyMap>,
}

impl TraceAddressPropertyManager {
    /// Create a new empty property manager.
    pub fn new() -> Self {
        Self {
            maps: BTreeMap::new(),
        }
    }

    /// Get or create a property map for the given space.
    pub fn get_or_create_map(&mut self, space_name: &str) -> &mut TracePropertyMap {
        self.maps
            .entry(space_name.to_string())
            .or_insert_with(|| TracePropertyMap::new(space_name))
    }

    /// Get a property map for the given space.
    pub fn get_map(&self, space_name: &str) -> Option<&TracePropertyMap> {
        self.maps.get(space_name)
    }

    /// Set a property value.
    pub fn set(&mut self, space_name: &str, address: u64, snap: i64, value: impl Into<String>) {
        self.get_or_create_map(space_name).set(address, snap, value);
    }

    /// Get a property value.
    pub fn get(&self, space_name: &str, address: u64, snap: i64) -> Option<&str> {
        self.maps.get(space_name).and_then(|m| m.get(address, snap))
    }

    /// Iterate over all property maps.
    pub fn maps(&self) -> impl Iterator<Item = &TracePropertyMap> {
        self.maps.values()
    }
}

impl Default for TraceAddressPropertyManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_map_basic() {
        let mut map = TracePropertyMap::new("ram");
        map.set(0x400000, 0, "value1");
        map.set(0x400000, 10, "value2");
        map.set(0x600000, 0, "other");

        assert_eq!(map.get(0x400000, 0), Some("value1"));
        assert_eq!(map.get(0x400000, 5), Some("value1"));
        assert_eq!(map.get(0x400000, 10), Some("value2"));
        assert_eq!(map.get(0x400000, 100), Some("value2"));
        assert_eq!(map.get(0x600000, 0), Some("other"));
        assert_eq!(map.get(0x500000, 0), None);
    }

    #[test]
    fn test_property_map_remove() {
        let mut map = TracePropertyMap::new("ram");
        map.set(0x400000, 0, "value");
        assert_eq!(map.get(0x400000, 0), Some("value"));

        map.remove(0x400000);
        assert_eq!(map.get(0x400000, 0), None);
    }

    #[test]
    fn test_property_map_entries_at_snap() {
        let mut map = TracePropertyMap::new("ram");
        map.set(0x400000, 0, "a");
        map.set(0x600000, 5, "b");
        map.set(0x400000, 10, "c");

        let entries = map.entries_at_snap(0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], (0x400000, "a"));

        let entries = map.entries_at_snap(5);
        assert_eq!(entries.len(), 2);

        let entries = map.entries_at_snap(10);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (0x400000, "c"));
        assert_eq!(entries[1], (0x600000, "b"));
    }

    #[test]
    fn test_property_map_len() {
        let mut map = TracePropertyMap::new("ram");
        assert!(map.is_empty());
        map.set(0x400000, 0, "a");
        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());
    }

    #[test]
    fn test_property_manager() {
        let mut mgr = TraceAddressPropertyManager::new();
        mgr.set("ram", 0x400000, 0, "function_start");
        mgr.set("ram", 0x400100, 0, "function_end");
        mgr.set("register", 0x0, 0, "pc_value");

        assert_eq!(mgr.get("ram", 0x400000, 0), Some("function_start"));
        assert_eq!(mgr.get("register", 0x0, 0), Some("pc_value"));
        assert_eq!(mgr.get("ram", 0x500000, 0), None);
        assert_eq!(mgr.maps().count(), 2);
    }

    #[test]
    fn test_property_map_display() {
        let map = TracePropertyMap::new("ram");
        assert_eq!(format!("{map}"), "PropertyMap(ram, 0 entries)");
    }
}
