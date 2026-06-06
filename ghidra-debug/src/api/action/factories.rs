//! AutoReadMemorySpecFactory and LocationTrackingSpecFactory.
//!
//! Ported from Ghidra's `AutoReadMemorySpecFactory` and
//! `LocationTrackingSpecFactory` in `ghidra.debug.api.action`.
//!
//! These factories manage registries of extension-point-based
//! specifications for automatic memory reading and location tracking.

use std::collections::BTreeMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use super::{AutoReadMemorySpec, LocationTrackingSpec};

/// Factory for managing AutoReadMemorySpec extension points.
///
/// Ported from Ghidra's `AutoReadMemorySpecFactory`. Maintains a
/// registry of all registered AutoReadMemorySpec implementations
/// and provides lookup by configuration name.
#[derive(Debug)]
pub struct AutoReadMemorySpecFactory {
    specs: RwLock<BTreeMap<String, AutoReadMemorySpec>>,
}

impl AutoReadMemorySpecFactory {
    /// Create a new empty factory.
    pub fn new() -> Self {
        Self {
            specs: RwLock::new(BTreeMap::new()),
        }
    }

    /// Register a spec implementation.
    pub fn register(&self, spec: AutoReadMemorySpec) {
        let name = spec.config_name.clone();
        self.specs.write().unwrap().insert(name, spec);
    }

    /// Look up a spec by its configuration name.
    pub fn from_config_name(&self, name: &str) -> Option<AutoReadMemorySpec> {
        self.specs.read().unwrap().get(name).cloned()
    }

    /// Get all registered specs.
    pub fn all_specs(&self) -> BTreeMap<String, AutoReadMemorySpec> {
        self.specs.read().unwrap().clone()
    }

    /// Get the names of all registered specs.
    pub fn spec_names(&self) -> Vec<String> {
        self.specs.read().unwrap().keys().cloned().collect()
    }

    /// Check if a spec with the given name is registered.
    pub fn has_spec(&self, name: &str) -> bool {
        self.specs.read().unwrap().contains_key(name)
    }

    /// Remove a spec by name.
    pub fn unregister(&self, name: &str) -> Option<AutoReadMemorySpec> {
        self.specs.write().unwrap().remove(name)
    }

    /// Get the number of registered specs.
    pub fn len(&self) -> usize {
        self.specs.read().unwrap().len()
    }

    /// Check if the factory is empty.
    pub fn is_empty(&self) -> bool {
        self.specs.read().unwrap().is_empty()
    }
}

impl Default for AutoReadMemorySpecFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// Factory for managing LocationTrackingSpec extension points.
///
/// Ported from Ghidra's `LocationTrackingSpecFactory`. Maintains a
/// registry of all registered LocationTrackingSpec implementations.
#[derive(Debug)]
pub struct LocationTrackingSpecFactory {
    specs: RwLock<BTreeMap<String, LocationTrackingSpec>>,
}

impl LocationTrackingSpecFactory {
    /// Create a new empty factory.
    pub fn new() -> Self {
        Self {
            specs: RwLock::new(BTreeMap::new()),
        }
    }

    /// Register a tracking spec implementation.
    pub fn register(&self, spec: LocationTrackingSpec) {
        let name = spec.name.clone();
        self.specs.write().unwrap().insert(name, spec);
    }

    /// Look up a tracking spec by its configuration name.
    pub fn from_config_name(&self, name: &str) -> Option<LocationTrackingSpec> {
        self.specs.read().unwrap().get(name).cloned()
    }

    /// Get all registered tracking specs.
    pub fn all_specs(&self) -> BTreeMap<String, LocationTrackingSpec> {
        self.specs.read().unwrap().clone()
    }

    /// Get the names of all registered tracking specs.
    pub fn spec_names(&self) -> Vec<String> {
        self.specs.read().unwrap().keys().cloned().collect()
    }

    /// Check if a tracking spec with the given name is registered.
    pub fn has_spec(&self, name: &str) -> bool {
        self.specs.read().unwrap().contains_key(name)
    }

    /// Remove a tracking spec by name.
    pub fn unregister(&self, name: &str) -> Option<LocationTrackingSpec> {
        self.specs.write().unwrap().remove(name)
    }

    /// Get the number of registered tracking specs.
    pub fn len(&self) -> usize {
        self.specs.read().unwrap().len()
    }

    /// Check if the factory is empty.
    pub fn is_empty(&self) -> bool {
        self.specs.read().unwrap().is_empty()
    }
}

impl Default for LocationTrackingSpecFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// Codec for saving/restoring AutoReadMemorySpec configurations.
///
/// Ported from Ghidra's `AutoReadMemorySpecConfigFieldCodec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoReadMemorySpecConfig {
    /// The configuration name of the spec.
    pub spec_name: String,
}

impl AutoReadMemorySpecConfig {
    /// Create a new config for the given spec name.
    pub fn new(spec_name: impl Into<String>) -> Self {
        Self {
            spec_name: spec_name.into(),
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

/// Codec for saving/restoring LocationTrackingSpec configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationTrackingSpecConfig {
    /// The configuration name of the spec.
    pub spec_name: String,
}

impl LocationTrackingSpecConfig {
    /// Create a new config for the given spec name.
    pub fn new(spec_name: impl Into<String>) -> Self {
        Self {
            spec_name: spec_name.into(),
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_read_memory_spec_factory_empty() {
        let factory = AutoReadMemorySpecFactory::new();
        assert!(factory.is_empty());
        assert_eq!(factory.len(), 0);
        assert!(!factory.has_spec("nonexistent"));
        assert!(factory.from_config_name("nonexistent").is_none());
    }

    #[test]
    fn test_auto_read_memory_spec_factory_register() {
        let factory = AutoReadMemorySpecFactory::new();
        let spec = AutoReadMemorySpec::new("test", "Test", "Test spec");
        factory.register(spec);
        assert_eq!(factory.len(), 1);
        assert!(factory.has_spec("test"));
        assert!(!factory.has_spec("other"));
    }

    #[test]
    fn test_auto_read_memory_spec_factory_lookup() {
        let factory = AutoReadMemorySpecFactory::new();
        let spec = AutoReadMemorySpec::new("mem_read", "Read Memory", "Reads memory regions");
        factory.register(spec);
        let found = factory.from_config_name("mem_read").unwrap();
        assert_eq!(found.config_name, "mem_read");
    }

    #[test]
    fn test_auto_read_memory_spec_factory_unregister() {
        let factory = AutoReadMemorySpecFactory::new();
        factory.register(AutoReadMemorySpec::new("test", "Test", "Desc"));
        assert_eq!(factory.len(), 1);
        factory.unregister("test");
        assert!(factory.is_empty());
    }

    #[test]
    fn test_auto_read_memory_spec_factory_spec_names() {
        let factory = AutoReadMemorySpecFactory::new();
        factory.register(AutoReadMemorySpec::new("a", "A", ""));
        factory.register(AutoReadMemorySpec::new("b", "B", ""));
        let names = factory.spec_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"a".to_string()));
        assert!(names.contains(&"b".to_string()));
    }

    #[test]
    fn test_location_tracking_spec_factory_empty() {
        let factory = LocationTrackingSpecFactory::new();
        assert!(factory.is_empty());
        assert_eq!(factory.len(), 0);
    }

    #[test]
    fn test_location_tracking_spec_factory_register() {
        let factory = LocationTrackingSpecFactory::new();
        let spec = LocationTrackingSpec::new("track_pc", "register", true);
        factory.register(spec);
        assert_eq!(factory.len(), 1);
        assert!(factory.has_spec("track_pc"));
    }

    #[test]
    fn test_location_tracking_spec_factory_all_specs() {
        let factory = LocationTrackingSpecFactory::new();
        factory.register(LocationTrackingSpec::new("a", "register", true));
        factory.register(LocationTrackingSpec::new("b", "register", false));
        let all = factory.all_specs();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_auto_read_memory_spec_config() {
        let config = AutoReadMemorySpecConfig::new("test_spec");
        let json = config.to_json();
        let restored = AutoReadMemorySpecConfig::from_json(&json).unwrap();
        assert_eq!(restored.spec_name, "test_spec");
    }

    #[test]
    fn test_location_tracking_spec_config() {
        let config = LocationTrackingSpecConfig::new("track_reg");
        let json = config.to_json();
        let restored = LocationTrackingSpecConfig::from_json(&json).unwrap();
        assert_eq!(restored.spec_name, "track_reg");
    }

    #[test]
    fn test_auto_read_config_bad_json() {
        assert!(AutoReadMemorySpecConfig::from_json("invalid").is_none());
    }

    #[test]
    fn test_location_tracking_config_bad_json() {
        assert!(LocationTrackingSpecConfig::from_json("invalid").is_none());
    }
}
