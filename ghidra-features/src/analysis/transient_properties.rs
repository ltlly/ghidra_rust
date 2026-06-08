//! Transient program properties for analysis.
//!
//! Ported from `ghidra.app.plugin.core.analysis.TransientProgramProperties`.
//!
//! Provides a mechanism for storing temporary analysis-related properties
//! on a program that are not persisted when the program is saved. These
//! properties are used to track analysis state, such as whether certain
//! analysis passes have been run, without modifying the program's
//! permanent properties.

pub use crate::base::analyzer::TransientProgramProperties;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

// ---------------------------------------------------------------------------
// PropertyValue
// ---------------------------------------------------------------------------

/// A value stored in transient program properties.
#[derive(Debug, Clone)]
pub enum PropertyValue {
    /// Boolean property.
    Bool(bool),
    /// Integer property.
    Int(i64),
    /// String property.
    String(String),
    /// Timestamp property.
    Timestamp(Instant),
    /// Set of string values.
    StringSet(Vec<String>),
    /// Set of u64 addresses.
    AddressSet(Vec<u64>),
}

impl PropertyValue {
    /// Try to get the value as a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get the value as an integer.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get the value as a string.
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get the value as a timestamp.
    pub fn as_timestamp(&self) -> Option<Instant> {
        match self {
            Self::Timestamp(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get the value as a string set.
    pub fn as_string_set(&self) -> Option<&[String]> {
        match self {
            Self::StringSet(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get the value as an address set.
    pub fn as_address_set(&self) -> Option<&[u64]> {
        match self {
            Self::AddressSet(v) => Some(v),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// TransientPropertyMap -- detailed property storage
// ---------------------------------------------------------------------------

/// Manages transient (non-persisted) properties keyed by string.
///
/// This is the detailed implementation providing richer property types
/// beyond what the base `TransientProgramProperties` offers.
///
/// # Usage
///
/// ```ignore
/// let props = TransientPropertyMap::new();
/// props.set_bool("has_run_data_flow", true);
/// props.set_int("function_count", 42);
/// props.set_string("last_analyzer", "DataFlow");
///
/// assert_eq!(props.get_bool("has_run_data_flow"), Some(true));
/// ```
#[derive(Clone)]
pub struct TransientPropertyMap {
    properties: Arc<RwLock<HashMap<String, PropertyValue>>>,
}

impl std::fmt::Debug for TransientPropertyMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.properties.read().unwrap().len();
        write!(f, "TransientPropertyMap({} entries)", count)
    }
}

impl TransientPropertyMap {
    /// Create a new empty properties set.
    pub fn new() -> Self {
        Self {
            properties: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set a boolean property.
    pub fn set_bool(&self, key: impl Into<String>, value: bool) {
        self.properties
            .write()
            .unwrap()
            .insert(key.into(), PropertyValue::Bool(value));
    }

    /// Set an integer property.
    pub fn set_int(&self, key: impl Into<String>, value: i64) {
        self.properties
            .write()
            .unwrap()
            .insert(key.into(), PropertyValue::Int(value));
    }

    /// Set a string property.
    pub fn set_string(&self, key: impl Into<String>, value: impl Into<String>) {
        self.properties
            .write()
            .unwrap()
            .insert(key.into(), PropertyValue::String(value.into()));
    }

    /// Set a timestamp property to the current time.
    pub fn set_timestamp_now(&self, key: impl Into<String>) {
        self.properties
            .write()
            .unwrap()
            .insert(key.into(), PropertyValue::Timestamp(Instant::now()));
    }

    /// Set a string set property.
    pub fn set_string_set(&self, key: impl Into<String>, values: Vec<String>) {
        self.properties
            .write()
            .unwrap()
            .insert(key.into(), PropertyValue::StringSet(values));
    }

    /// Set an address set property.
    pub fn set_address_set(&self, key: impl Into<String>, addresses: Vec<u64>) {
        self.properties
            .write()
            .unwrap()
            .insert(key.into(), PropertyValue::AddressSet(addresses));
    }

    /// Get a property value by key.
    pub fn get(&self, key: &str) -> Option<PropertyValue> {
        self.properties.read().unwrap().get(key).cloned()
    }

    /// Get a boolean property.
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.properties.read().unwrap().get(key).and_then(|v| v.as_bool())
    }

    /// Get an integer property.
    pub fn get_int(&self, key: &str) -> Option<i64> {
        self.properties.read().unwrap().get(key).and_then(|v| v.as_int())
    }

    /// Get a string property.
    pub fn get_string(&self, key: &str) -> Option<String> {
        self.properties
            .read()
            .unwrap()
            .get(key)
            .and_then(|v| v.as_string().map(|s| s.to_string()))
    }

    /// Check if a property exists.
    pub fn contains(&self, key: &str) -> bool {
        self.properties.read().unwrap().contains_key(key)
    }

    /// Remove a property by key.
    pub fn remove(&self, key: &str) -> Option<PropertyValue> {
        self.properties.write().unwrap().remove(key)
    }

    /// Clear all properties.
    pub fn clear(&self) {
        self.properties.write().unwrap().clear();
    }

    /// Get the number of properties.
    pub fn len(&self) -> usize {
        self.properties.read().unwrap().len()
    }

    /// Whether there are no properties.
    pub fn is_empty(&self) -> bool {
        self.properties.read().unwrap().is_empty()
    }

    /// Get all property keys.
    pub fn keys(&self) -> Vec<String> {
        self.properties.read().unwrap().keys().cloned().collect()
    }

    /// Get or set a boolean property with a default value.
    pub fn get_or_set_bool(&self, key: impl Into<String>, default: bool) -> bool {
        let key = key.into();
        let mut props = self.properties.write().unwrap();
        if let Some(val) = props.get(&key).and_then(|v| v.as_bool()) {
            val
        } else {
            props.insert(key, PropertyValue::Bool(default));
            default
        }
    }

    /// Get or set an integer property with a default value.
    pub fn get_or_set_int(&self, key: impl Into<String>, default: i64) -> i64 {
        let key = key.into();
        let mut props = self.properties.write().unwrap();
        if let Some(val) = props.get(&key).and_then(|v| v.as_int()) {
            val
        } else {
            props.insert(key, PropertyValue::Int(default));
            default
        }
    }
}

impl Default for TransientPropertyMap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Well-known property names
// ---------------------------------------------------------------------------

/// Well-known transient property keys used by the analysis framework.
pub mod keys {
    /// Whether the program has been analyzed at least once.
    pub const HAS_BEEN_ANALYZED: &str = "ghidra.analysis.has_been_analyzed";

    /// Whether auto-analysis is currently running.
    pub const ANALYSIS_RUNNING: &str = "ghidra.analysis.running";

    /// The name of the last analyzer that ran.
    pub const LAST_ANALYZER: &str = "ghidra.analysis.last_analyzer";

    /// The number of functions found during the last analysis pass.
    pub const FUNCTION_COUNT: &str = "ghidra.analysis.function_count";

    /// The number of instructions disassembled during the last pass.
    pub const INSTRUCTION_COUNT: &str = "ghidra.analysis.instruction_count";

    /// Timestamp of when the last analysis started.
    pub const LAST_ANALYSIS_START: &str = "ghidra.analysis.last_start";

    /// Timestamp of when the last analysis ended.
    pub const LAST_ANALYSIS_END: &str = "ghidra.analysis.last_end";

    /// The set of analyzers that have run during this session.
    pub const COMPLETED_ANALYZERS: &str = "ghidra.analysis.completed_analyzers";

    /// Whether the current analysis run was cancelled.
    pub const ANALYSIS_CANCELLED: &str = "ghidra.analysis.cancelled";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_map_basic() {
        let props = TransientPropertyMap::new();
        assert!(props.is_empty());

        props.set_bool("test", true);
        assert!(!props.is_empty());
        assert_eq!(props.len(), 1);
    }

    #[test]
    fn test_property_map_bool() {
        let props = TransientPropertyMap::new();
        props.set_bool("flag", true);
        assert_eq!(props.get_bool("flag"), Some(true));
        assert_eq!(props.get_bool("nonexistent"), None);
    }

    #[test]
    fn test_property_map_int() {
        let props = TransientPropertyMap::new();
        props.set_int("count", 42);
        assert_eq!(props.get_int("count"), Some(42));
    }

    #[test]
    fn test_property_map_string() {
        let props = TransientPropertyMap::new();
        props.set_string("name", "value");
        assert_eq!(props.get_string("name"), Some("value".to_string()));
    }

    #[test]
    fn test_property_map_contains() {
        let props = TransientPropertyMap::new();
        assert!(!props.contains("key"));

        props.set_bool("key", false);
        assert!(props.contains("key"));
    }

    #[test]
    fn test_property_map_remove() {
        let props = TransientPropertyMap::new();
        props.set_int("key", 1);
        assert!(props.contains("key"));

        let removed = props.remove("key");
        assert!(removed.is_some());
        assert!(!props.contains("key"));
    }

    #[test]
    fn test_property_map_clear() {
        let props = TransientPropertyMap::new();
        props.set_bool("a", true);
        props.set_int("b", 1);
        props.set_string("c", "three");

        props.clear();
        assert!(props.is_empty());
    }

    #[test]
    fn test_property_map_keys() {
        let props = TransientPropertyMap::new();
        props.set_bool("a", true);
        props.set_int("b", 1);

        let mut keys = props.keys();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[test]
    fn test_property_map_get_or_set_bool() {
        let props = TransientPropertyMap::new();
        let val = props.get_or_set_bool("flag", true);
        assert!(val);

        // Second call should return existing value
        let val = props.get_or_set_bool("flag", false);
        assert!(val);
    }

    #[test]
    fn test_property_map_get_or_set_int() {
        let props = TransientPropertyMap::new();
        let val = props.get_or_set_int("count", 10);
        assert_eq!(val, 10);

        let val = props.get_or_set_int("count", 20);
        assert_eq!(val, 10); // existing value
    }

    #[test]
    fn test_property_map_string_set() {
        let props = TransientPropertyMap::new();
        props.set_string_set("set", vec!["a".into(), "b".into()]);

        let val = props.get("set").unwrap();
        let set = val.as_string_set().unwrap();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_property_map_address_set() {
        let props = TransientPropertyMap::new();
        props.set_address_set("addrs", vec![0x1000, 0x2000, 0x3000]);

        let val = props.get("addrs").unwrap();
        let addrs = val.as_address_set().unwrap();
        assert_eq!(addrs, &[0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn test_property_map_clone_shares_state() {
        let props1 = TransientPropertyMap::new();
        props1.set_bool("shared", true);

        let props2 = props1.clone();
        assert_eq!(props2.get_bool("shared"), Some(true));

        props2.set_bool("new_key", true);
        assert!(props1.contains("new_key")); // shared state
    }

    #[test]
    fn test_property_value_types() {
        let props = TransientPropertyMap::new();

        props.set_bool("b", true);
        props.set_int("i", 42);
        props.set_string("s", "hello");

        assert_eq!(props.get_bool("b"), Some(true));
        assert_eq!(props.get_int("i"), Some(42));
        assert_eq!(props.get_string("s"), Some("hello".to_string()));

        // Wrong type returns None
        assert_eq!(props.get_bool("i"), None);
        assert_eq!(props.get_int("s"), None);
    }

    #[test]
    fn test_well_known_keys() {
        assert!(!keys::HAS_BEEN_ANALYZED.is_empty());
        assert!(!keys::ANALYSIS_RUNNING.is_empty());
        assert!(!keys::LAST_ANALYZER.is_empty());
        assert!(!keys::FUNCTION_COUNT.is_empty());
    }
}
