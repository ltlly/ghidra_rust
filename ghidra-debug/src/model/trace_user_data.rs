//! TraceUserData - user-specific data storage for traces.
//!
//! Ported from Ghidra's `ghidra.trace.model.TraceUserData`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// User-specific data attached to a trace.
///
/// This allows storing arbitrary key-value data per user (or globally)
/// that persists with the trace but is not part of the core model.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceUserData {
    /// Global data (not user-specific).
    pub global: HashMap<String, serde_json::Value>,
    /// Per-user data, keyed by username.
    pub per_user: HashMap<String, HashMap<String, serde_json::Value>>,
}

impl TraceUserData {
    /// Create a new empty user data store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a global value.
    pub fn set_global(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.global.insert(key.into(), value);
    }

    /// Get a global value.
    pub fn get_global(&self, key: &str) -> Option<&serde_json::Value> {
        self.global.get(key)
    }

    /// Remove a global value.
    pub fn remove_global(&mut self, key: &str) -> Option<serde_json::Value> {
        self.global.remove(key)
    }

    /// Set a per-user value.
    pub fn set_user_value(
        &mut self,
        user: &str,
        key: impl Into<String>,
        value: serde_json::Value,
    ) {
        self.per_user
            .entry(user.to_string())
            .or_default()
            .insert(key.into(), value);
    }

    /// Get a per-user value.
    pub fn get_user_value(&self, user: &str, key: &str) -> Option<&serde_json::Value> {
        self.per_user.get(user)?.get(key)
    }

    /// Remove a per-user value.
    pub fn remove_user_value(&mut self, user: &str, key: &str) -> Option<serde_json::Value> {
        self.per_user.get_mut(user)?.remove(key)
    }

    /// Get all keys for a user.
    pub fn user_keys(&self, user: &str) -> Vec<&String> {
        self.per_user
            .get(user)
            .map(|m| m.keys().collect())
            .unwrap_or_default()
    }

    /// Get all global keys.
    pub fn global_keys(&self) -> Vec<&String> {
        self.global.keys().collect()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.global.is_empty() && self.per_user.is_empty()
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.global.clear();
        self.per_user.clear();
    }
}

/// Entry in the user data store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDataEntry {
    /// The key.
    pub key: String,
    /// The value.
    pub value: serde_json::Value,
    /// The user (None for global).
    pub user: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_data() {
        let mut data = TraceUserData::new();
        data.set_global("foo", serde_json::json!(42));
        assert_eq!(data.get_global("foo"), Some(&serde_json::json!(42)));
    }

    #[test]
    fn test_user_data() {
        let mut data = TraceUserData::new();
        data.set_user_value("alice", "theme", serde_json::json!("dark"));
        assert_eq!(
            data.get_user_value("alice", "theme"),
            Some(&serde_json::json!("dark"))
        );
        assert!(data.get_user_value("bob", "theme").is_none());
    }

    #[test]
    fn test_remove() {
        let mut data = TraceUserData::new();
        data.set_global("key", serde_json::json!("value"));
        assert!(!data.is_empty());

        data.remove_global("key");
        assert!(data.is_empty());
    }

    #[test]
    fn test_user_keys() {
        let mut data = TraceUserData::new();
        data.set_user_value("alice", "a", serde_json::json!(1));
        data.set_user_value("alice", "b", serde_json::json!(2));

        let keys = data.user_keys("alice");
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_clear() {
        let mut data = TraceUserData::new();
        data.set_global("x", serde_json::json!(1));
        data.set_user_value("u", "y", serde_json::json!(2));

        data.clear();
        assert!(data.is_empty());
    }
}
