//! Preference state for non-plugin preferences.
//!
//! Ports `ghidra.framework.options.PreferenceState`.

use std::collections::HashMap;

use super::option_value::OptionValue;

/// A generic state container for saving non-plugin preferences.
///
/// Ported from Ghidra's `ghidra.framework.options.PreferenceState`.
#[derive(Debug, Clone, Default)]
pub struct PreferenceState {
    name: String,
    values: HashMap<String, OptionValue>,
}

impl PreferenceState {
    /// The default name for preference state.
    pub const PREFERENCE_STATE_NAME: &'static str = "PREFERENCE_STATE";

    /// Create a new preference state.
    pub fn new() -> Self {
        Self { name: Self::PREFERENCE_STATE_NAME.to_string(), values: HashMap::new() }
    }

    /// Create a named preference state.
    pub fn with_name(name: impl Into<String>) -> Self {
        Self { name: name.into(), values: HashMap::new() }
    }

    /// Get the name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Put a value.
    pub fn put(&mut self, key: &str, value: OptionValue) {
        self.values.insert(key.to_string(), value);
    }

    /// Get a value.
    pub fn get(&self, key: &str) -> Option<&OptionValue> {
        self.values.get(key)
    }

    /// Remove a value.
    pub fn remove(&mut self, key: &str) -> Option<OptionValue> {
        self.values.remove(key)
    }

    /// Check if a key exists.
    pub fn contains(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    /// Get all keys.
    pub fn keys(&self) -> Vec<&str> {
        self.values.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the state is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl std::fmt::Display for PreferenceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PreferenceState('{}', {} entries)", self.name, self.values.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preference_state_new() {
        let ps = PreferenceState::new();
        assert_eq!(ps.name(), PreferenceState::PREFERENCE_STATE_NAME);
        assert!(ps.is_empty());
    }

    #[test]
    fn test_preference_state_put_get() {
        let mut ps = PreferenceState::new();
        ps.put("key", OptionValue::Int(42));
        assert_eq!(ps.get("key"), Some(&OptionValue::Int(42)));
        assert_eq!(ps.len(), 1);
    }

    #[test]
    fn test_preference_state_remove() {
        let mut ps = PreferenceState::new();
        ps.put("key", OptionValue::Boolean(true));
        let removed = ps.remove("key");
        assert_eq!(removed, Some(OptionValue::Boolean(true)));
        assert!(ps.is_empty());
    }

    #[test]
    fn test_preference_state_contains() {
        let mut ps = PreferenceState::new();
        assert!(!ps.contains("missing"));
        ps.put("exists", OptionValue::String("hello".into()));
        assert!(ps.contains("exists"));
    }

    #[test]
    fn test_preference_state_with_name() {
        let ps = PreferenceState::with_name("Custom");
        assert_eq!(ps.name(), "Custom");
    }

    #[test]
    fn test_preference_state_display() {
        let mut ps = PreferenceState::new();
        ps.put("a", OptionValue::Int(1));
        ps.put("b", OptionValue::Int(2));
        assert_eq!(ps.to_string(), "PreferenceState('PREFERENCE_STATE', 2 entries)");
    }
}
