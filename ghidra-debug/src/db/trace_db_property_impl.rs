//! Database-backed property map implementation.
//!
//! Ported from Ghidra's `ghidra.trace.database.property.DBTraceAddressPropertyManager`.
//! Provides per-address-space property maps that store boolean, int, string,
//! and other typed properties keyed by address ranges.
//!
//! In Ghidra, property maps are part of the Program interface and are
//! accessed via `TracePropertyMap` in trace contexts. This module provides
//! the database-level storage backing those property maps.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

// ---------------------------------------------------------------------------
// Property value types
// ---------------------------------------------------------------------------

/// A property value stored in a trace property map.
///
/// Ported from the various property map types in Ghidra (bool, int, string,
/// address, etc.).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PropertyMapValue {
    /// A boolean property (e.g., instruction start, has fallthrough).
    Bool(bool),
    /// An integer property (e.g., plate/comment type).
    Int(i64),
    /// A string property (e.g., label, comment text).
    String(String),
    /// A void property (presence/absence only, like bookmarks).
    Void,
    /// An address property (e.g., external reference target).
    Address(u64),
}

impl PropertyMapValue {
    /// Get the value as a bool, if applicable.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Get the value as an int, if applicable.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Get the value as a string, if applicable.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(v) => Some(v.as_str()),
            _ => None,
        }
    }

    /// Whether this is a void (presence-only) property.
    pub fn is_void(&self) -> bool {
        matches!(self, Self::Void)
    }
}

// ---------------------------------------------------------------------------
// PropertyMapEntry
// ---------------------------------------------------------------------------

/// A single entry in a property map, associating an address range with a value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyMapEntry {
    /// Unique key for this entry.
    pub key: i64,
    /// Start address (offset).
    pub address: u64,
    /// The property value.
    pub value: PropertyMapValue,
}

// ---------------------------------------------------------------------------
// TracePropertyMap
// ---------------------------------------------------------------------------

/// A per-address-space property map.
///
/// Ported from Ghidra's address property map. Stores key-value pairs
/// where keys are addresses and values are typed property values.
#[derive(Debug, Clone, Default)]
pub struct TracePropertyMap {
    /// Name of this property map.
    pub name: String,
    /// Entries indexed by address offset.
    entries: BTreeMap<u64, PropertyMapValue>,
}

impl TracePropertyMap {
    /// Create a new empty property map.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entries: BTreeMap::new(),
        }
    }

    /// Set a property value at the given address.
    pub fn set(&mut self, address: u64, value: PropertyMapValue) {
        self.entries.insert(address, value);
    }

    /// Get the property value at the given address.
    pub fn get(&self, address: u64) -> Option<&PropertyMapValue> {
        self.entries.get(&address)
    }

    /// Remove the property at the given address.
    pub fn remove(&mut self, address: u64) -> Option<PropertyMapValue> {
        self.entries.remove(&address)
    }

    /// Check whether a property exists at the given address.
    pub fn contains(&self, address: u64) -> bool {
        self.entries.contains_key(&address)
    }

    /// Get the number of entries in this property map.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check whether this property map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &PropertyMapValue)> {
        self.entries.iter()
    }

    /// Get all addresses that have a property set.
    pub fn addresses(&self) -> impl Iterator<Item = &u64> {
        self.entries.keys()
    }

    /// Get the next address with a property set after the given address.
    pub fn next_address(&self, address: u64) -> Option<u64> {
        self.entries
            .range(address + 1..)
            .next()
            .map(|(&k, _)| k)
    }

    /// Get the previous address with a property set before the given address.
    pub fn prev_address(&self, address: u64) -> Option<u64> {
        self.entries
            .range(..address)
            .next_back()
            .map(|(&k, _)| k)
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get entries within an address range.
    pub fn range(&self, min: u64, max: u64) -> impl Iterator<Item = (&u64, &PropertyMapValue)> {
        self.entries.range(min..=max)
    }
}

// ---------------------------------------------------------------------------
// DBTraceAddressPropertyManager
// ---------------------------------------------------------------------------

/// The database-backed property map manager.
///
/// Ported from `ghidra.trace.database.property.DBTraceAddressPropertyManager`.
/// Manages multiple named property maps per address space.
#[derive(Debug, Default)]
pub struct DbTraceAddressPropertyManager {
    /// Property maps organized by (space_name, property_name).
    maps: BTreeMap<(String, String), TracePropertyMap>,
}

impl DbTraceAddressPropertyManager {
    /// Create a new property manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a property map for the given space and property name.
    pub fn get_or_create_map(&mut self, space_name: &str, property_name: &str) -> &mut TracePropertyMap {
        let key = (space_name.to_string(), property_name.to_string());
        self.maps.entry(key).or_insert_with(|| {
            TracePropertyMap::new(property_name)
        })
    }

    /// Get a property map if it exists.
    pub fn get_map(&self, space_name: &str, property_name: &str) -> Option<&TracePropertyMap> {
        self.maps.get(&(space_name.to_string(), property_name.to_string()))
    }

    /// Remove a property map.
    pub fn remove_map(&mut self, space_name: &str, property_name: &str) -> Option<TracePropertyMap> {
        self.maps.remove(&(space_name.to_string(), property_name.to_string()))
    }

    /// Get all property map names for a given space.
    pub fn map_names(&self, space_name: &str) -> Vec<&str> {
        self.maps
            .iter()
            .filter(|((s, _), _)| s == space_name)
            .map(|((_, n), _)| n.as_str())
            .collect()
    }

    /// Get all space names that have property maps.
    pub fn space_names(&self) -> Vec<&str> {
        let mut names: Vec<_> = self.maps.keys().map(|(s, _)| s.as_str()).collect();
        names.sort();
        names.dedup();
        names
    }

    /// Set a boolean property.
    pub fn set_bool(&mut self, space_name: &str, property_name: &str, address: u64, value: bool) {
        self.get_or_create_map(space_name, property_name)
            .set(address, PropertyMapValue::Bool(value));
    }

    /// Set an integer property.
    pub fn set_int(&mut self, space_name: &str, property_name: &str, address: u64, value: i64) {
        self.get_or_create_map(space_name, property_name)
            .set(address, PropertyMapValue::Int(value));
    }

    /// Set a string property.
    pub fn set_string(&mut self, space_name: &str, property_name: &str, address: u64, value: impl Into<String>) {
        self.get_or_create_map(space_name, property_name)
            .set(address, PropertyMapValue::String(value.into()));
    }

    /// Set a void (presence-only) property.
    pub fn set_void(&mut self, space_name: &str, property_name: &str, address: u64) {
        self.get_or_create_map(space_name, property_name)
            .set(address, PropertyMapValue::Void);
    }

    /// Remove a property at the given address.
    pub fn remove_property(&mut self, space_name: &str, property_name: &str, address: u64) -> Option<PropertyMapValue> {
        self.get_map_mut(space_name, property_name)?.remove(address)
    }

    /// Get a mutable reference to a map.
    fn get_map_mut(&mut self, space_name: &str, property_name: &str) -> Option<&mut TracePropertyMap> {
        self.maps.get_mut(&(space_name.to_string(), property_name.to_string()))
    }

    /// Get the total number of property maps.
    pub fn map_count(&self) -> usize {
        self.maps.len()
    }
}

// ---------------------------------------------------------------------------
// Known Ghidra property map names
// ---------------------------------------------------------------------------

/// Well-known Ghidra property map names.
pub mod known_properties {
    /// Whether an address is the start of an instruction.
    pub const INSTRUCTION_START: &str = "Instruction Start";
    /// Whether an address has an associated instruction.
    pub const INSTRUCTION: &str = "Instruction";
    /// Whether an address is the start of defined data.
    pub const DEFINED_DATA: &str = "Defined Data";
    /// Pre-comment property.
    pub const PRE_COMMENT: &str = "Pre Comment";
    /// Post-comment property.
    pub const POST_COMMENT: &str = "Post Comment";
    /// EOL comment property.
    pub const EOL_COMMENT: &str = "EOL Comment";
    /// Repeatable comment property.
    pub const REPEATABLE_COMMENT: &str = "Repeatable Comment";
    /// Plate comment property.
    pub const PLATE_COMMENT: &str = "Plate Comment";
    /// Whether an address has a reference.
    pub const REFERENCE: &str = "Reference";
    /// Whether an address has an external reference.
    pub const EXTERNAL_REF: &str = "External Reference";
    /// Entry point property.
    pub const ENTRY_POINT: &str = "Entry Point";
    /// Thunk property.
    pub const THUNK: &str = "Thunk";
    /// Fallthrough property (for non-default fallthrough).
    pub const FALLTHROUGH: &str = "Fallthrough";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_map_value_types() {
        let b = PropertyMapValue::Bool(true);
        assert_eq!(b.as_bool(), Some(true));
        assert!(b.as_int().is_none());

        let i = PropertyMapValue::Int(42);
        assert_eq!(i.as_int(), Some(42));

        let s = PropertyMapValue::String("hello".to_string());
        assert_eq!(s.as_str(), Some("hello"));

        let v = PropertyMapValue::Void;
        assert!(v.is_void());
    }

    #[test]
    fn test_property_map_basic_ops() {
        let mut map = TracePropertyMap::new("test");
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);

        map.set(0x1000, PropertyMapValue::Bool(true));
        map.set(0x2000, PropertyMapValue::Int(42));

        assert_eq!(map.len(), 2);
        assert!(map.contains(0x1000));
        assert!(!map.contains(0x1500));
        assert_eq!(map.get(0x1000), Some(&PropertyMapValue::Bool(true)));
        assert_eq!(map.get(0x2000), Some(&PropertyMapValue::Int(42)));
    }

    #[test]
    fn test_property_map_remove() {
        let mut map = TracePropertyMap::new("test");
        map.set(0x1000, PropertyMapValue::Bool(true));

        let removed = map.remove(0x1000);
        assert_eq!(removed, Some(PropertyMapValue::Bool(true)));
        assert!(!map.contains(0x1000));
        assert!(map.is_empty());
    }

    #[test]
    fn test_property_map_range() {
        let mut map = TracePropertyMap::new("test");
        for i in 0..10 {
            map.set(i * 0x1000, PropertyMapValue::Int(i as i64));
        }

        let range: Vec<_> = map.range(0x2000, 0x5000).collect();
        assert_eq!(range.len(), 4); // 0x2000, 0x3000, 0x4000, 0x5000
    }

    #[test]
    fn test_property_map_navigation() {
        let mut map = TracePropertyMap::new("test");
        map.set(0x1000, PropertyMapValue::Void);
        map.set(0x3000, PropertyMapValue::Void);
        map.set(0x5000, PropertyMapValue::Void);

        assert_eq!(map.next_address(0x1000), Some(0x3000));
        assert_eq!(map.next_address(0x3000), Some(0x5000));
        assert_eq!(map.next_address(0x5000), None);

        assert_eq!(map.prev_address(0x5000), Some(0x3000));
        assert_eq!(map.prev_address(0x3000), Some(0x1000));
        assert_eq!(map.prev_address(0x1000), None);
    }

    #[test]
    fn test_property_manager_basic_ops() {
        let mut mgr = DbTraceAddressPropertyManager::new();

        mgr.set_bool("ram", "my_prop", 0x400000, true);
        mgr.set_int("ram", "my_prop2", 0x400000, 42);
        mgr.set_string("ram", "comment", 0x400000, "hello");

        let map = mgr.get_map("ram", "my_prop").unwrap();
        assert_eq!(map.get(0x400000), Some(&PropertyMapValue::Bool(true)));

        let map2 = mgr.get_map("ram", "my_prop2").unwrap();
        assert_eq!(map2.get(0x400000), Some(&PropertyMapValue::Int(42)));
    }

    #[test]
    fn test_property_manager_map_names() {
        let mut mgr = DbTraceAddressPropertyManager::new();
        mgr.set_bool("ram", "prop_a", 0, true);
        mgr.set_bool("ram", "prop_b", 0, true);
        mgr.set_bool("register", "reg_prop", 0, true);

        let ram_names = mgr.map_names("ram");
        assert_eq!(ram_names.len(), 2);
        assert!(ram_names.contains(&"prop_a"));
        assert!(ram_names.contains(&"prop_b"));

        let reg_names = mgr.map_names("register");
        assert_eq!(reg_names.len(), 1);
    }

    #[test]
    fn test_property_manager_remove() {
        let mut mgr = DbTraceAddressPropertyManager::new();
        mgr.set_bool("ram", "test", 0x1000, true);

        let removed = mgr.remove_property("ram", "test", 0x1000);
        assert_eq!(removed, Some(PropertyMapValue::Bool(true)));

        let map = mgr.get_map("ram", "test").unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn test_property_manager_space_names() {
        let mut mgr = DbTraceAddressPropertyManager::new();
        mgr.set_bool("ram", "a", 0, true);
        mgr.set_bool("register", "b", 0, true);
        mgr.set_bool("ram", "c", 0, true);

        let spaces = mgr.space_names();
        assert_eq!(spaces.len(), 2);
        assert!(spaces.contains(&"ram"));
        assert!(spaces.contains(&"register"));
    }

    #[test]
    fn test_known_properties() {
        // Ensure known property constants are non-empty
        assert!(!known_properties::INSTRUCTION_START.is_empty());
        assert!(!known_properties::EOL_COMMENT.is_empty());
        assert!(!known_properties::ENTRY_POINT.is_empty());
    }
}
