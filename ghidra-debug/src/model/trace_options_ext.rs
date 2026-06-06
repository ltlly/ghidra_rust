//! Extended trace options and configuration.
//!
//! Ported from Ghidra's `ghidra.trace.model.TraceOptionsManager` and
//! `ghidra.trace.model.TraceUserData` in Framework-TraceModeling.
//!
//! Provides:
//! - `TraceOptionValue`: Typed option values for trace configuration.
//! - `TraceOptionsStore`: Key-value store for trace options.
//! - `TraceUserPreference`: User-specific trace preferences.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A typed option value for trace configuration.
///
/// Ported from Ghidra's trace option value handling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TraceOptionValue {
    /// A boolean option.
    Bool(bool),
    /// An integer option.
    Int(i64),
    /// A string option.
    String(String),
    /// A floating-point option.
    Float(f64),
}

impl TraceOptionValue {
    /// Get the value as a boolean, if possible.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            TraceOptionValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Get the value as an integer, if possible.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            TraceOptionValue::Int(v) => Some(*v),
            TraceOptionValue::Float(v) => Some(*v as i64),
            _ => None,
        }
    }

    /// Get the value as a string.
    pub fn as_string(&self) -> Option<&str> {
        match self {
            TraceOptionValue::String(v) => Some(v),
            _ => None,
        }
    }

    /// Get the value as a float, if possible.
    pub fn as_float(&self) -> Option<f64> {
        match self {
            TraceOptionValue::Float(v) => Some(*v),
            TraceOptionValue::Int(v) => Some(*v as f64),
            _ => None,
        }
    }

    /// Get the type name of this option value.
    pub fn type_name(&self) -> &'static str {
        match self {
            TraceOptionValue::Bool(_) => "bool",
            TraceOptionValue::Int(_) => "int",
            TraceOptionValue::String(_) => "string",
            TraceOptionValue::Float(_) => "float",
        }
    }
}

impl From<bool> for TraceOptionValue {
    fn from(v: bool) -> Self {
        TraceOptionValue::Bool(v)
    }
}

impl From<i64> for TraceOptionValue {
    fn from(v: i64) -> Self {
        TraceOptionValue::Int(v)
    }
}

impl From<String> for TraceOptionValue {
    fn from(v: String) -> Self {
        TraceOptionValue::String(v)
    }
}

impl From<&str> for TraceOptionValue {
    fn from(v: &str) -> Self {
        TraceOptionValue::String(v.to_string())
    }
}

impl From<f64> for TraceOptionValue {
    fn from(v: f64) -> Self {
        TraceOptionValue::Float(v)
    }
}

/// A key-value store for trace options.
///
/// Ported from Ghidra's `TraceOptionsManager`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceOptionsStore {
    /// The stored options.
    options: BTreeMap<String, TraceOptionValue>,
    /// The set of option names that have been modified since last save.
    dirty: BTreeMap<String, bool>,
}

impl TraceOptionsStore {
    /// Create a new empty options store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get an option value by name.
    pub fn get(&self, name: &str) -> Option<&TraceOptionValue> {
        self.options.get(name)
    }

    /// Set an option value.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<TraceOptionValue>) {
        let name = name.into();
        self.options.insert(name.clone(), value.into());
        self.dirty.insert(name, true);
    }

    /// Remove an option.
    pub fn remove(&mut self, name: &str) -> Option<TraceOptionValue> {
        self.dirty.insert(name.to_string(), true);
        self.options.remove(name)
    }

    /// Check if an option exists.
    pub fn contains(&self, name: &str) -> bool {
        self.options.contains_key(name)
    }

    /// Get all option names.
    pub fn keys(&self) -> Vec<&String> {
        self.options.keys().collect()
    }

    /// Get all dirty (modified) option names.
    pub fn dirty_keys(&self) -> Vec<&String> {
        self.dirty.keys().collect()
    }

    /// Clear dirty flags.
    pub fn clear_dirty(&mut self) {
        self.dirty.clear();
    }

    /// Check if any options are dirty.
    pub fn is_dirty(&self) -> bool {
        self.dirty.values().any(|&v| v)
    }

    /// Get the number of options.
    pub fn len(&self) -> usize {
        self.options.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.options.is_empty()
    }

    /// Get a boolean option value, or a default.
    pub fn get_bool(&self, name: &str, default: bool) -> bool {
        self.options
            .get(name)
            .and_then(|v| v.as_bool())
            .unwrap_or(default)
    }

    /// Get an integer option value, or a default.
    pub fn get_int(&self, name: &str, default: i64) -> i64 {
        self.options
            .get(name)
            .and_then(|v| v.as_int())
            .unwrap_or(default)
    }

    /// Get a string option value, or a default.
    pub fn get_string<'a>(&'a self, name: &str, default: &'a str) -> &str {
        self.options
            .get(name)
            .and_then(|v| v.as_string())
            .unwrap_or(default)
    }
}

/// User-specific trace preferences.
///
/// Ported from Ghidra's `TraceUserData`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceUserPreferences {
    /// Per-trace user data, keyed by trace name.
    data: BTreeMap<String, BTreeMap<String, TraceOptionValue>>,
}

impl TraceUserPreferences {
    /// Create new empty user preferences.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a preference for a specific trace.
    pub fn get(&self, trace_name: &str, key: &str) -> Option<&TraceOptionValue> {
        self.data.get(trace_name)?.get(key)
    }

    /// Set a preference for a specific trace.
    pub fn set(
        &mut self,
        trace_name: impl Into<String>,
        key: impl Into<String>,
        value: impl Into<TraceOptionValue>,
    ) {
        self.data
            .entry(trace_name.into())
            .or_insert_with(BTreeMap::new)
            .insert(key.into(), value.into());
    }

    /// Remove a preference for a specific trace.
    pub fn remove(&mut self, trace_name: &str, key: &str) -> Option<TraceOptionValue> {
        self.data.get_mut(trace_name)?.remove(key)
    }

    /// Get all preference keys for a trace.
    pub fn keys_for_trace(&self, trace_name: &str) -> Vec<&String> {
        self.data
            .get(trace_name)
            .map(|m| m.keys().collect())
            .unwrap_or_default()
    }

    /// Get all trace names that have preferences.
    pub fn trace_names(&self) -> Vec<&String> {
        self.data.keys().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_option_value_conversions() {
        let v: TraceOptionValue = true.into();
        assert_eq!(v.as_bool(), Some(true));
        assert_eq!(v.type_name(), "bool");

        let v: TraceOptionValue = 42i64.into();
        assert_eq!(v.as_int(), Some(42));
        assert_eq!(v.as_float(), Some(42.0));

        let v: TraceOptionValue = "hello".into();
        assert_eq!(v.as_string(), Some("hello"));

        let v: TraceOptionValue = 3.14f64.into();
        assert_eq!(v.as_float(), Some(3.14));
        assert_eq!(v.as_int(), Some(3));
    }

    #[test]
    fn test_option_value_no_conversion() {
        let v: TraceOptionValue = true.into();
        assert!(v.as_int().is_none());
        assert!(v.as_string().is_none());
        assert!(v.as_float().is_none());
    }

    #[test]
    fn test_options_store_basic_ops() {
        let mut store = TraceOptionsStore::new();
        assert!(store.is_empty());

        store.set("auto_map", true);
        store.set("max_snap", 1000i64);
        store.set("name", "test");

        assert_eq!(store.len(), 3);
        assert!(store.contains("auto_map"));
        assert!(!store.contains("missing"));

        assert_eq!(store.get_bool("auto_map", false), true);
        assert_eq!(store.get_int("max_snap", 0), 1000);
        assert_eq!(store.get_string("name", ""), "test");

        // Default for missing keys
        assert_eq!(store.get_bool("missing", false), false);
        assert_eq!(store.get_int("missing", -1), -1);
        assert_eq!(store.get_string("missing", "default"), "default");
    }

    #[test]
    fn test_options_store_dirty_tracking() {
        let mut store = TraceOptionsStore::new();
        store.set("key", "value");
        assert!(store.is_dirty());

        store.clear_dirty();
        assert!(!store.is_dirty());
    }

    #[test]
    fn test_options_store_remove() {
        let mut store = TraceOptionsStore::new();
        store.set("key", 42i64);
        assert!(store.contains("key"));

        let removed = store.remove("key");
        assert_eq!(removed.unwrap().as_int(), Some(42));
        assert!(!store.contains("key"));
    }

    #[test]
    fn test_user_preferences() {
        let mut prefs = TraceUserPreferences::new();
        prefs.set("trace1", "layout", "default");
        prefs.set("trace1", "font_size", 12i64);
        prefs.set("trace2", "layout", "compact");

        assert_eq!(prefs.get("trace1", "layout").unwrap().as_string(), Some("default"));
        assert_eq!(prefs.get("trace1", "font_size").unwrap().as_int(), Some(12));
        assert!(prefs.get("trace1", "missing").is_none());

        let names = prefs.trace_names();
        assert_eq!(names.len(), 2);

        let keys = prefs.keys_for_trace("trace1");
        assert_eq!(keys.len(), 2);
    }
}
