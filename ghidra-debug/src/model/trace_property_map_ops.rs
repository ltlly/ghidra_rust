//! Property map operations for traces.
//!
//! Ported from Ghidra's `TracePropertyMapOperations` and
//! `TracePropertyMapSpace` interfaces in `ghidra.trace.model.property`.
//! Defines the operations available on property maps that store
//! typed values keyed by address-snap ranges.

use serde::{Deserialize, Serialize};

use super::lifespan::Lifespan;

/// Operations on a trace property map.
///
/// Ported from Ghidra's `TracePropertyMapOperations<T>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracePropertyMapOperations {
    /// The property name.
    pub name: String,
    /// The value type.
    pub value_type: PropertyValueType,
}

/// The type of values in a trace property map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropertyValueType {
    /// Boolean property.
    Bool,
    /// Integer property.
    Int,
    /// Long property.
    Long,
    /// String property.
    String,
    /// Void (presence-only) property.
    Void,
}

impl TracePropertyMapOperations {
    /// Create new property map operations descriptor.
    pub fn new(name: impl Into<String>, value_type: PropertyValueType) -> Self {
        Self {
            name: name.into(),
            value_type,
        }
    }
}

/// A property map space managing values across an address space.
///
/// Ported from Ghidra's `TracePropertyMapSpace`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracePropertyMapSpace {
    /// The address space name.
    pub space_name: String,
    /// Entries keyed by (address, snap).
    entries: Vec<PropertySpaceEntry>,
}

/// An entry in a property map space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertySpaceEntry {
    /// The address offset.
    pub address: u64,
    /// The lifespan of this entry.
    pub lifespan: Lifespan,
    /// The property value (serialized as string).
    pub value: String,
}

impl TracePropertyMapSpace {
    /// Create a new property map space.
    pub fn new(space_name: impl Into<String>) -> Self {
        Self {
            space_name: space_name.into(),
            entries: Vec::new(),
        }
    }

    /// Add an entry.
    pub fn add_entry(&mut self, address: u64, lifespan: Lifespan, value: impl Into<String>) {
        self.entries.push(PropertySpaceEntry {
            address,
            lifespan,
            value: value.into(),
        });
    }

    /// Get the value at a specific address and snap.
    pub fn get(&self, address: u64, snap: i64) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.address == address && e.lifespan.contains(snap))
            .map(|e| e.value.as_str())
    }

    /// Check if an entry exists at the given address and snap.
    pub fn has(&self, address: u64, snap: i64) -> bool {
        self.get(address, snap).is_some()
    }

    /// Clear entries within a lifespan and address.
    pub fn clear(&mut self, address: u64, lifespan: &Lifespan) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|e| !(e.address == address && e.lifespan.intersects(lifespan)));
        before - self.entries.len()
    }

    /// Get all entries at a given address.
    pub fn entries_at(&self, address: u64) -> Vec<&PropertySpaceEntry> {
        self.entries.iter().filter(|e| e.address == address).collect()
    }

    /// Get all entries within a lifespan.
    pub fn entries_in_lifespan(&self, lifespan: &Lifespan) -> Vec<&PropertySpaceEntry> {
        self.entries
            .iter()
            .filter(|e| e.lifespan.intersects(lifespan))
            .collect()
    }

    /// Total entry count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_map_operations_new() {
        let ops = TracePropertyMapOperations::new("Test", PropertyValueType::Bool);
        assert_eq!(ops.name, "Test");
        assert_eq!(ops.value_type, PropertyValueType::Bool);
    }

    #[test]
    fn test_property_map_space_add_and_get() {
        let mut space = TracePropertyMapSpace::new("ram");
        space.add_entry(0x1000, Lifespan::span(0, 10), "hello");
        assert_eq!(space.get(0x1000, 5), Some("hello"));
        assert_eq!(space.get(0x1000, 15), None);
        assert_eq!(space.get(0x2000, 5), None);
    }

    #[test]
    fn test_property_map_space_has() {
        let mut space = TracePropertyMapSpace::new("ram");
        space.add_entry(0x100, Lifespan::span(0, 5), "v");
        assert!(space.has(0x100, 3));
        assert!(!space.has(0x100, 10));
    }

    #[test]
    fn test_property_map_space_clear() {
        let mut space = TracePropertyMapSpace::new("ram");
        space.add_entry(0x100, Lifespan::span(0, 10), "old");
        let cleared = space.clear(0x100, &Lifespan::span(0, 10));
        assert_eq!(cleared, 1);
        assert!(space.is_empty());
    }

    #[test]
    fn test_property_map_space_entries_at() {
        let mut space = TracePropertyMapSpace::new("ram");
        space.add_entry(0x100, Lifespan::span(0, 5), "a");
        space.add_entry(0x100, Lifespan::span(6, 10), "b");
        space.add_entry(0x200, Lifespan::span(0, 5), "c");
        assert_eq!(space.entries_at(0x100).len(), 2);
        assert_eq!(space.entries_at(0x200).len(), 1);
    }

    #[test]
    fn test_property_map_space_entries_in_lifespan() {
        let mut space = TracePropertyMapSpace::new("ram");
        space.add_entry(0x100, Lifespan::span(0, 10), "a");
        space.add_entry(0x200, Lifespan::span(20, 30), "b");
        let entries = space.entries_in_lifespan(&Lifespan::span(5, 15));
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_property_map_space_len() {
        let mut space = TracePropertyMapSpace::new("ram");
        assert_eq!(space.len(), 0);
        assert!(space.is_empty());
        space.add_entry(0, Lifespan::span(0, 0), "v");
        assert_eq!(space.len(), 1);
        assert!(!space.is_empty());
    }
}
