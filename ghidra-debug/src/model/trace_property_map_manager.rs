//! TracePropertyMapManager - manages a collection of property maps.
//!
//! Ported from Ghidra's `TraceAddressPropertyManager` and
//! `DBTraceProgramViewPropertyMapManager`.
//!
//! Provides a registry of typed property maps (int, long, string, void)
//! keyed by name, with CRUD operations and per-snap address queries.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::property::TracePropertyMap;

/// Type-erased property map entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PropertyMapValue {
    /// Integer-valued property map.
    Int(TracePropertyMap<i64>),
    /// Long-valued property map (same as int in Rust, kept for API parity).
    Long(TracePropertyMap<i64>),
    /// String-valued property map.
    String(TracePropertyMap<String>),
    /// Boolean (void) property map.
    Void(TracePropertyMap<bool>),
}

impl PropertyMapValue {
    /// Get the type name of this property map.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Int(_) => "int",
            Self::Long(_) => "long",
            Self::String(_) => "string",
            Self::Void(_) => "void",
        }
    }
}

/// Manages a collection of named property maps.
///
/// Ported from Ghidra's `TraceAddressPropertyManager`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracePropertyMapManager {
    maps: BTreeMap<String, PropertyMapValue>,
}

impl TracePropertyMapManager {
    /// Create a new empty property map manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an integer property map.
    pub fn create_int_property_map(&mut self, name: &str) -> Result<(), String> {
        if self.maps.contains_key(name) {
            return Err(format!("Property map already exists: {}", name));
        }
        self.maps.insert(
            name.to_string(),
            PropertyMapValue::Int(TracePropertyMap::new()),
        );
        Ok(())
    }

    /// Create a long property map.
    pub fn create_long_property_map(&mut self, name: &str) -> Result<(), String> {
        if self.maps.contains_key(name) {
            return Err(format!("Property map already exists: {}", name));
        }
        self.maps.insert(
            name.to_string(),
            PropertyMapValue::Long(TracePropertyMap::new()),
        );
        Ok(())
    }

    /// Create a string property map.
    pub fn create_string_property_map(&mut self, name: &str) -> Result<(), String> {
        if self.maps.contains_key(name) {
            return Err(format!("Property map already exists: {}", name));
        }
        self.maps.insert(
            name.to_string(),
            PropertyMapValue::String(TracePropertyMap::new()),
        );
        Ok(())
    }

    /// Create a void (boolean) property map.
    pub fn create_void_property_map(&mut self, name: &str) -> Result<(), String> {
        if self.maps.contains_key(name) {
            return Err(format!("Property map already exists: {}", name));
        }
        self.maps.insert(
            name.to_string(),
            PropertyMapValue::Void(TracePropertyMap::new()),
        );
        Ok(())
    }

    /// Get a property map by name.
    pub fn get_property_map(&self, name: &str) -> Option<&PropertyMapValue> {
        self.maps.get(name)
    }

    /// Get a mutable property map by name.
    pub fn get_property_map_mut(&mut self, name: &str) -> Option<&mut PropertyMapValue> {
        self.maps.get_mut(name)
    }

    /// Get an int property map by name.
    pub fn get_int_property_map(&self, name: &str) -> Option<&TracePropertyMap<i64>> {
        match self.maps.get(name) {
            Some(PropertyMapValue::Int(m)) => Some(m),
            _ => None,
        }
    }

    /// Get a mutable int property map by name.
    pub fn get_int_property_map_mut(&mut self, name: &str) -> Option<&mut TracePropertyMap<i64>> {
        match self.maps.get_mut(name) {
            Some(PropertyMapValue::Int(m)) => Some(m),
            _ => None,
        }
    }

    /// Get a long property map by name.
    pub fn get_long_property_map(&self, name: &str) -> Option<&TracePropertyMap<i64>> {
        match self.maps.get(name) {
            Some(PropertyMapValue::Long(m)) => Some(m),
            _ => None,
        }
    }

    /// Get a string property map by name.
    pub fn get_string_property_map(&self, name: &str) -> Option<&TracePropertyMap<String>> {
        match self.maps.get(name) {
            Some(PropertyMapValue::String(m)) => Some(m),
            _ => None,
        }
    }

    /// Get a void property map by name.
    pub fn get_void_property_map(&self, name: &str) -> Option<&TracePropertyMap<bool>> {
        match self.maps.get(name) {
            Some(PropertyMapValue::Void(m)) => Some(m),
            _ => None,
        }
    }

    /// Remove a property map by name.
    pub fn remove_property_map(&mut self, name: &str) -> bool {
        self.maps.remove(name).is_some()
    }

    /// Get all property map names.
    pub fn property_map_names(&self) -> Vec<&str> {
        self.maps.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of property maps.
    pub fn property_map_count(&self) -> usize {
        self.maps.len()
    }

    /// Get all property maps.
    pub fn all_maps(&self) -> &BTreeMap<String, PropertyMapValue> {
        &self.maps
    }
}

#[cfg(test)]
mod tests {
    use super::super::Lifespan;
    use super::*;

    #[test]
    fn test_create_int_map() {
        let mut mgr = TracePropertyMapManager::new();
        mgr.create_int_property_map("BookmarkType").unwrap();
        assert_eq!(mgr.property_map_count(), 1);
        assert!(mgr.get_int_property_map("BookmarkType").is_some());
    }

    #[test]
    fn test_create_string_map() {
        let mut mgr = TracePropertyMapManager::new();
        mgr.create_string_property_map("Comments").unwrap();
        assert!(mgr.get_string_property_map("Comments").is_some());
    }

    #[test]
    fn test_create_void_map() {
        let mut mgr = TracePropertyMapManager::new();
        mgr.create_void_property_map("Hit").unwrap();
        assert!(mgr.get_void_property_map("Hit").is_some());
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut mgr = TracePropertyMapManager::new();
        mgr.create_int_property_map("X").unwrap();
        assert!(mgr.create_int_property_map("X").is_err());
    }

    #[test]
    fn test_set_and_get_value() {
        let mut mgr = TracePropertyMapManager::new();
        mgr.create_int_property_map("BP").unwrap();
        let map = mgr.get_int_property_map_mut("BP").unwrap();
        map.set(0x1000, 0x1000, 1, Lifespan::at(0));
        let val = map.get(0x1000, 0);
        assert_eq!(val, Some(&1));
    }

    #[test]
    fn test_remove_map() {
        let mut mgr = TracePropertyMapManager::new();
        mgr.create_int_property_map("TEMP").unwrap();
        assert!(mgr.remove_property_map("TEMP"));
        assert_eq!(mgr.property_map_count(), 0);
        assert!(!mgr.remove_property_map("TEMP"));
    }

    #[test]
    fn test_property_map_names() {
        let mut mgr = TracePropertyMapManager::new();
        mgr.create_int_property_map("A").unwrap();
        mgr.create_string_property_map("B").unwrap();
        let names = mgr.property_map_names();
        assert_eq!(names, vec!["A", "B"]);
    }

    #[test]
    fn test_type_name() {
        let map = PropertyMapValue::Int(TracePropertyMap::new());
        assert_eq!(map.type_name(), "int");
    }

    #[test]
    fn test_get_nonexistent() {
        let mgr = TracePropertyMapManager::new();
        assert!(mgr.get_property_map("nope").is_none());
    }
}
