//! Extended action types for the debugger API.
//!
//! Ported from `ghidra/debug/api/action/` package:
//! - `AutoReadMemorySpecFactory.java`
//! - Various additional action types

use serde::{Deserialize, Serialize};

/// Factory for creating auto-read memory specifications.
///
/// Ported from `AutoReadMemorySpecFactory.java`.
pub trait AutoReadMemorySpecFactory: std::fmt::Debug + Send + Sync {
    /// Get the name of this factory.
    fn name(&self) -> &str;

    /// Create a spec for the given language ID.
    fn create_spec(&self, language_id: &str) -> Option<AutoReadMemorySpec>;
}

/// A specification for automatically reading memory from a trace.
///
/// Ported from `AutoReadMemorySpec.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoReadMemorySpec {
    /// The name of this spec.
    pub name: String,
    /// Address ranges to read (space_name, offset_min, offset_max).
    pub ranges: Vec<(String, u64, u64)>,
    /// Whether to read the entire region.
    pub read_all: bool,
    /// Language ID this spec applies to.
    pub language_id: String,
}

impl AutoReadMemorySpec {
    /// Create a new spec.
    pub fn new(name: String, language_id: String) -> Self {
        Self {
            name,
            ranges: Vec::new(),
            read_all: false,
            language_id,
        }
    }

    /// Add a range to read.
    pub fn with_range(mut self, space: String, min: u64, max: u64) -> Self {
        self.ranges.push((space, min, max));
        self
    }

    /// Set read-all flag.
    pub fn with_read_all(mut self, read_all: bool) -> Self {
        self.read_all = read_all;
        self
    }
}

/// A registry of auto-read memory spec factories.
#[derive(Debug)]
pub struct AutoReadMemorySpecRegistry {
    factories: Vec<Box<dyn AutoReadMemorySpecFactory>>,
}

impl AutoReadMemorySpecRegistry {
    /// Create a new registry.
    pub fn new() -> Self {
        Self {
            factories: Vec::new(),
        }
    }

    /// Register a factory.
    pub fn register(&mut self, factory: Box<dyn AutoReadMemorySpecFactory>) {
        self.factories.push(factory);
    }

    /// Create specs for a language.
    pub fn create_specs(&self, language_id: &str) -> Vec<AutoReadMemorySpec> {
        self.factories
            .iter()
            .filter_map(|f| f.create_spec(language_id))
            .collect()
    }

    /// Get factory names.
    pub fn factory_names(&self) -> Vec<&str> {
        self.factories.iter().map(|f| f.name()).collect()
    }
}

impl Default for AutoReadMemorySpecRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Factory for creating location tracking specifications.
///
/// Ported from `LocationTrackingSpecFactory.java`.
pub trait LocationTrackingSpecFactory: std::fmt::Debug + Send + Sync {
    /// Get the name.
    fn name(&self) -> &str;

    /// Create a spec for a language.
    fn create_spec(&self, language_id: &str) -> Option<LocationTrackingSpec>;
}

/// A specification for location tracking (following PC, SP, etc.).
///
/// Ported from `LocationTrackingSpec.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationTrackingSpec {
    /// Name.
    pub name: String,
    /// The register to track.
    pub register: String,
    /// Language ID.
    pub language_id: String,
    /// Whether tracking is enabled.
    pub enabled: bool,
}

impl LocationTrackingSpec {
    /// Create a new spec.
    pub fn new(name: String, register: String, language_id: String) -> Self {
        Self {
            name,
            register,
            language_id,
            enabled: true,
        }
    }
}

/// A registry of location tracking spec factories.
#[derive(Debug)]
pub struct LocationTrackingSpecRegistry {
    factories: Vec<Box<dyn LocationTrackingSpecFactory>>,
}

impl LocationTrackingSpecRegistry {
    /// Create a new registry.
    pub fn new() -> Self {
        Self {
            factories: Vec::new(),
        }
    }

    /// Register a factory.
    pub fn register(&mut self, factory: Box<dyn LocationTrackingSpecFactory>) {
        self.factories.push(factory);
    }

    /// Create specs for a language.
    pub fn create_specs(&self, language_id: &str) -> Vec<LocationTrackingSpec> {
        self.factories
            .iter()
            .filter_map(|f| f.create_spec(language_id))
            .collect()
    }
}

impl Default for LocationTrackingSpecRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// An auto-map specification for automatically mapping traces to programs.
///
/// Ported from `AutoMapSpec.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoMapSpec {
    /// Name.
    pub name: String,
    /// Whether to match by module name.
    pub match_by_name: bool,
    /// Whether to match by section name.
    pub match_by_section: bool,
    /// Whether to match by address range.
    pub match_by_address: bool,
}

impl AutoMapSpec {
    /// Create a default auto-map spec.
    pub fn default_spec() -> Self {
        Self {
            name: "Default".into(),
            match_by_name: true,
            match_by_section: true,
            match_by_address: false,
        }
    }

    /// Create a spec that does nothing.
    pub fn none() -> Self {
        Self {
            name: "None".into(),
            match_by_name: false,
            match_by_section: false,
            match_by_address: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_read_memory_spec() {
        let spec = AutoReadMemorySpec::new("test".into(), "x86:LE:64:default".into())
            .with_range("ram".into(), 0x400000, 0x401000);
        assert_eq!(spec.ranges.len(), 1);
        assert!(!spec.read_all);
    }

    #[test]
    fn test_auto_read_memory_registry() {
        let registry = AutoReadMemorySpecRegistry::new();
        assert!(registry.factory_names().is_empty());
    }

    #[test]
    fn test_location_tracking_spec() {
        let spec = LocationTrackingSpec::new(
            "PC".into(),
            "RIP".into(),
            "x86:LE:64:default".into(),
        );
        assert_eq!(spec.register, "RIP");
        assert!(spec.enabled);
    }

    #[test]
    fn test_auto_map_spec() {
        let spec = AutoMapSpec::default_spec();
        assert!(spec.match_by_name);
        assert!(!spec.match_by_address);

        let none = AutoMapSpec::none();
        assert!(!none.match_by_name);
    }
}
