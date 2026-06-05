//! Property map manager for trace program views.
//!
//! Ported from Ghidra's `DBTraceProgramViewPropertyMapManager` and
//! `DBTraceProgramViewPropertyMap` in `ghidra.trace.database.program`.
//! Provides the Ghidra PropertyMapManager interface for a single
//! snapshot of a trace program view.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A named property map for a trace program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewPropertyMap {
    /// The property name.
    pub name: String,
    /// The property value type.
    pub value_type: ProgramPropertyValueType,
    /// Entries keyed by address offset.
    entries: BTreeMap<u64, ProgramPropertyValue>,
}

/// Property value types for program views.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgramPropertyValueType {
    /// Boolean property.
    Bool,
    /// Integer property.
    Int,
    /// String property.
    String,
    /// Void (presence-only) property.
    Void,
    /// Long property.
    Long,
}

/// A property value in a program view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProgramPropertyValue {
    /// Boolean value.
    Bool(bool),
    /// Integer value.
    Int(i32),
    /// Long value.
    Long(i64),
    /// String value.
    String(String),
    /// Void (presence only).
    Void,
}

impl ProgramViewPropertyMap {
    /// Create a new property map.
    pub fn new(name: impl Into<String>, value_type: ProgramPropertyValueType) -> Self {
        Self {
            name: name.into(),
            value_type,
            entries: BTreeMap::new(),
        }
    }

    /// Set a value at an address.
    pub fn set(&mut self, address: u64, value: ProgramPropertyValue) {
        self.entries.insert(address, value);
    }

    /// Get a value at an address.
    pub fn get(&self, address: u64) -> Option<&ProgramPropertyValue> {
        self.entries.get(&address)
    }

    /// Remove a value at an address.
    pub fn remove(&mut self, address: u64) -> Option<ProgramPropertyValue> {
        self.entries.remove(&address)
    }

    /// Check if a value exists at an address.
    pub fn has(&self, address: u64) -> bool {
        self.entries.contains_key(&address)
    }

    /// Get the entry count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get all addresses with entries.
    pub fn addresses(&self) -> Vec<u64> {
        self.entries.keys().copied().collect()
    }

    /// Get entries as a slice of (address, value) pairs.
    pub fn entries(&self) -> Vec<(u64, &ProgramPropertyValue)> {
        self.entries.iter().map(|(&k, v)| (k, v)).collect()
    }
}

/// Property map manager for a trace program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewPropertyMapManager {
    /// Named property maps.
    maps: BTreeMap<String, ProgramViewPropertyMap>,
}

impl ProgramViewPropertyMapManager {
    /// Create a new property map manager.
    pub fn new() -> Self {
        Self {
            maps: BTreeMap::new(),
        }
    }

    /// Create a property map.
    pub fn create_map(
        &mut self,
        name: impl Into<String>,
        value_type: ProgramPropertyValueType,
    ) -> &mut ProgramViewPropertyMap {
        let name = name.into();
        self.maps
            .entry(name.clone())
            .or_insert_with(|| ProgramViewPropertyMap::new(&name, value_type))
    }

    /// Get a property map by name.
    pub fn get_map(&self, name: &str) -> Option<&ProgramViewPropertyMap> {
        self.maps.get(name)
    }

    /// Get a mutable property map by name.
    pub fn get_map_mut(&mut self, name: &str) -> Option<&mut ProgramViewPropertyMap> {
        self.maps.get_mut(name)
    }

    /// Delete a property map.
    pub fn delete_map(&mut self, name: &str) -> bool {
        self.maps.remove(name).is_some()
    }

    /// Get all map names.
    pub fn map_names(&self) -> Vec<String> {
        self.maps.keys().cloned().collect()
    }

    /// Get the number of maps.
    pub fn map_count(&self) -> usize {
        self.maps.len()
    }
}

impl Default for ProgramViewPropertyMapManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_map_create_and_set() {
        let mut map = ProgramViewPropertyMap::new("Test", ProgramPropertyValueType::Bool);
        map.set(0x100, ProgramPropertyValue::Bool(true));
        assert_eq!(map.get(0x100), Some(&ProgramPropertyValue::Bool(true)));
    }

    #[test]
    fn test_property_map_remove() {
        let mut map = ProgramViewPropertyMap::new("Test", ProgramPropertyValueType::Int);
        map.set(0x100, ProgramPropertyValue::Int(42));
        assert!(map.remove(0x100).is_some());
        assert!(!map.has(0x100));
    }

    #[test]
    fn test_property_map_len() {
        let mut map = ProgramViewPropertyMap::new("Test", ProgramPropertyValueType::String);
        assert!(map.is_empty());
        map.set(0, ProgramPropertyValue::String("a".into()));
        map.set(1, ProgramPropertyValue::String("b".into()));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_property_map_manager_create_and_get() {
        let mut mgr = ProgramViewPropertyMapManager::new();
        mgr.create_map("Comment", ProgramPropertyValueType::String);
        assert!(mgr.get_map("Comment").is_some());
        assert_eq!(mgr.map_count(), 1);
    }

    #[test]
    fn test_property_map_manager_delete() {
        let mut mgr = ProgramViewPropertyMapManager::new();
        mgr.create_map("X", ProgramPropertyValueType::Void);
        assert!(mgr.delete_map("X"));
        assert_eq!(mgr.map_count(), 0);
    }

    #[test]
    fn test_property_map_manager_names() {
        let mut mgr = ProgramViewPropertyMapManager::new();
        mgr.create_map("A", ProgramPropertyValueType::Bool);
        mgr.create_map("B", ProgramPropertyValueType::Int);
        let names = mgr.map_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"A".to_string()));
    }

    #[test]
    fn test_property_map_addresses() {
        let mut map = ProgramViewPropertyMap::new("Test", ProgramPropertyValueType::Void);
        map.set(0x300, ProgramPropertyValue::Void);
        map.set(0x100, ProgramPropertyValue::Void);
        assert_eq!(map.addresses(), vec![0x100, 0x300]);
    }
}
