//! SaveSettings - save/load settings for debugger state persistence.
//!
//! Ported from Ghidra's `SavedSettings` in `ghidra.app.plugin.core.debug.utils`.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A stored setting value (primitive or nested).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SettingValue {
    /// A boolean value.
    Bool(bool),
    /// An integer value.
    Int(i64),
    /// A floating-point value.
    Float(f64),
    /// A string value.
    String(String),
    /// A list of values.
    List(Vec<SettingValue>),
    /// A map of values.
    Map(BTreeMap<String, SettingValue>),
}

impl From<bool> for SettingValue {
    fn from(v: bool) -> Self {
        SettingValue::Bool(v)
    }
}

impl From<i64> for SettingValue {
    fn from(v: i64) -> Self {
        SettingValue::Int(v)
    }
}

impl From<i32> for SettingValue {
    fn from(v: i32) -> Self {
        SettingValue::Int(v as i64)
    }
}

impl From<f64> for SettingValue {
    fn from(v: f64) -> Self {
        SettingValue::Float(v)
    }
}

impl From<String> for SettingValue {
    fn from(v: String) -> Self {
        SettingValue::String(v)
    }
}

impl From<&str> for SettingValue {
    fn from(v: &str) -> Self {
        SettingValue::String(v.to_string())
    }
}

impl SettingValue {
    /// Try to extract a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            SettingValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to extract an integer.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            SettingValue::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to extract a float.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            SettingValue::Float(v) => Some(*v),
            SettingValue::Int(v) => Some(*v as f64),
            _ => None,
        }
    }

    /// Try to extract a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            SettingValue::String(v) => Some(v),
            _ => None,
        }
    }

    /// Try to extract a list.
    pub fn as_list(&self) -> Option<&[SettingValue]> {
        match self {
            SettingValue::List(v) => Some(v),
            _ => None,
        }
    }

    /// Try to extract a map.
    pub fn as_map(&self) -> Option<&BTreeMap<String, SettingValue>> {
        match self {
            SettingValue::Map(v) => Some(v),
            _ => None,
        }
    }
}

/// A collection of saved debugger settings.
///
/// Ported from Ghidra's `SavedSettings`. Persists configuration
/// such as column widths, selected registers, breakpoints, etc.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SavedSettings {
    /// Named settings stored by key.
    settings: IndexMap<String, SettingValue>,
}

impl SavedSettings {
    /// Create a new empty settings store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a setting by key.
    pub fn get(&self, key: &str) -> Option<&SettingValue> {
        self.settings.get(key)
    }

    /// Set a value.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<SettingValue>) {
        self.settings.insert(key.into(), value.into());
    }

    /// Remove a setting.
    pub fn remove(&mut self, key: &str) -> Option<SettingValue> {
        self.settings.shift_remove(key)
    }

    /// Check whether a key exists.
    pub fn contains_key(&self, key: &str) -> bool {
        self.settings.contains_key(key)
    }

    /// Get the number of settings.
    pub fn len(&self) -> usize {
        self.settings.len()
    }

    /// Whether the settings are empty.
    pub fn is_empty(&self) -> bool {
        self.settings.is_empty()
    }

    /// Get all setting keys.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.settings.keys().map(|s| s.as_str())
    }

    /// Get all settings as key-value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &SettingValue)> {
        self.settings.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Clear all settings.
    pub fn clear(&mut self) {
        self.settings.clear();
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Deserialize from JSON string.
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setting_value_conversions() {
        let v: SettingValue = true.into();
        assert_eq!(v.as_bool(), Some(true));

        let v: SettingValue = 42i64.into();
        assert_eq!(v.as_i64(), Some(42));

        let v: SettingValue = 3.14f64.into();
        assert_eq!(v.as_f64(), Some(3.14));

        let v: SettingValue = "hello".into();
        assert_eq!(v.as_str(), Some("hello"));

        let v: SettingValue = "owned".to_string().into();
        assert_eq!(v.as_str(), Some("owned"));
    }

    #[test]
    fn test_setting_value_wrong_type() {
        let v: SettingValue = 42i64.into();
        assert!(v.as_bool().is_none());
        assert!(v.as_str().is_none());
    }

    #[test]
    fn test_saved_settings_basic() {
        let mut s = SavedSettings::new();
        assert!(s.is_empty());

        s.set("key1", "value1");
        s.set("key2", 42i64);
        assert_eq!(s.len(), 2);
        assert!(s.contains_key("key1"));
        assert_eq!(s.get("key1").unwrap().as_str(), Some("value1"));
        assert_eq!(s.get("key2").unwrap().as_i64(), Some(42));
    }

    #[test]
    fn test_saved_settings_remove() {
        let mut s = SavedSettings::new();
        s.set("key", "value");
        assert_eq!(s.len(), 1);

        let removed = s.remove("key");
        assert!(removed.is_some());
        assert!(s.is_empty());
    }

    #[test]
    fn test_saved_settings_keys() {
        let mut s = SavedSettings::new();
        s.set("a", 1i64);
        s.set("b", 2i64);
        s.set("c", 3i64);

        let keys: Vec<&str> = s.keys().collect();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_saved_settings_serde() {
        let mut s = SavedSettings::new();
        s.set("bool_key", true);
        s.set("int_key", 100i64);
        s.set("str_key", "test");

        let json = s.to_json();
        assert!(!json.is_empty());

        let restored = SavedSettings::from_json(&json).unwrap();
        assert_eq!(restored.len(), 3);
        assert_eq!(restored.get("bool_key").unwrap().as_bool(), Some(true));
        assert_eq!(restored.get("int_key").unwrap().as_i64(), Some(100));
    }

    #[test]
    fn test_setting_value_list() {
        let v = SettingValue::List(vec![
            SettingValue::Int(1),
            SettingValue::Int(2),
            SettingValue::Int(3),
        ]);
        let list = v.as_list().unwrap();
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_setting_value_map() {
        let mut map = BTreeMap::new();
        map.insert("x".into(), SettingValue::Int(10));
        let v = SettingValue::Map(map);
        let m = v.as_map().unwrap();
        assert_eq!(m.get("x").unwrap().as_i64(), Some(10));
    }

    #[test]
    fn test_settings_int_from_i32() {
        let v: SettingValue = 42i32.into();
        assert_eq!(v.as_i64(), Some(42));
    }

    #[test]
    fn test_settings_clear() {
        let mut s = SavedSettings::new();
        s.set("a", 1i64);
        s.set("b", 2i64);
        s.clear();
        assert!(s.is_empty());
    }

    #[test]
    fn test_settings_iter() {
        let mut s = SavedSettings::new();
        s.set("x", 10i64);
        s.set("y", 20i64);
        let pairs: Vec<_> = s.iter().collect();
        assert_eq!(pairs.len(), 2);
    }
}
