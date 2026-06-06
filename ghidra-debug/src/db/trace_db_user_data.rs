//! User data storage for trace databases.
//!
//! Ported from Ghidra's `DBTraceUserData`. Provides per-trace key-value
//! storage for user-specific data such as view preferences, window
//! configurations, bookmarks, and other session state.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A stored user data entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDataEntry {
    /// The key.
    pub key: String,
    /// The value as a string.
    pub value: String,
    /// Whether this entry should persist across sessions.
    pub persistent: bool,
    /// Optional namespace to separate different consumers.
    pub namespace: Option<String>,
}

impl UserDataEntry {
    /// Create a new entry.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            persistent: true,
            namespace: None,
        }
    }

    /// Set the namespace.
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// Set persistent flag.
    pub fn with_persistent(mut self, persistent: bool) -> Self {
        self.persistent = persistent;
        self
    }

    /// The fully qualified key including namespace.
    pub fn qualified_key(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}::{}", ns, self.key),
            None => self.key.clone(),
        }
    }
}

/// Per-trace user data store.
///
/// Ported from Ghidra's `DBTraceUserData`. Stores arbitrary key-value
/// pairs associated with a trace, organized by namespace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DbTraceUserData {
    /// The data entries, keyed by qualified key.
    entries: BTreeMap<String, UserDataEntry>,
}

impl DbTraceUserData {
    /// Create a new empty user data store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Put a value.
    pub fn put(&mut self, entry: UserDataEntry) {
        let key = entry.qualified_key();
        self.entries.insert(key, entry);
    }

    /// Get a value by key and optional namespace.
    pub fn get(&self, key: &str, namespace: Option<&str>) -> Option<&UserDataEntry> {
        let qualified = match namespace {
            Some(ns) => format!("{}::{}", ns, key),
            None => key.to_string(),
        };
        self.entries.get(&qualified)
    }

    /// Get a value's string content.
    pub fn get_string(&self, key: &str, namespace: Option<&str>) -> Option<&str> {
        self.get(key, namespace).map(|e| e.value.as_str())
    }

    /// Get a value or return a default.
    pub fn get_or<'a>(&'a self, key: &str, namespace: Option<&str>, default: &'a str) -> &'a str {
        self.get_string(key, namespace).unwrap_or(default)
    }

    /// Remove a value.
    pub fn remove(&mut self, key: &str, namespace: Option<&str>) -> Option<UserDataEntry> {
        let qualified = match namespace {
            Some(ns) => format!("{}::{}", ns, key),
            None => key.to_string(),
        };
        self.entries.remove(&qualified)
    }

    /// Check if a key exists.
    pub fn contains(&self, key: &str, namespace: Option<&str>) -> bool {
        let qualified = match namespace {
            Some(ns) => format!("{}::{}", ns, key),
            None => key.to_string(),
        };
        self.entries.contains_key(&qualified)
    }

    /// Get all entries.
    pub fn all_entries(&self) -> &BTreeMap<String, UserDataEntry> {
        &self.entries
    }

    /// Get all entries in a namespace.
    pub fn entries_in_namespace(&self, namespace: &str) -> Vec<&UserDataEntry> {
        let _prefix = format!("{}::", namespace);
        self.entries
            .values()
            .filter(|e| e.namespace.as_deref() == Some(namespace))
            .collect()
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get only persistent entries.
    pub fn persistent_entries(&self) -> Vec<&UserDataEntry> {
        self.entries.values().filter(|e| e.persistent).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_data_entry() {
        let entry = UserDataEntry::new("view_mode", "flat")
            .with_namespace("listing")
            .with_persistent(true);
        assert_eq!(entry.qualified_key(), "listing::view_mode");
        assert!(entry.persistent);
    }

    #[test]
    fn test_user_data_no_namespace() {
        let entry = UserDataEntry::new("theme", "dark");
        assert_eq!(entry.qualified_key(), "theme");
    }

    #[test]
    fn test_db_user_data_put_get() {
        let mut data = DbTraceUserData::new();
        data.put(UserDataEntry::new("key1", "value1"));
        data.put(UserDataEntry::new("key2", "value2").with_namespace("ns"));

        assert_eq!(data.get_string("key1", None), Some("value1"));
        assert_eq!(data.get_string("key2", Some("ns")), Some("value2"));
        assert!(data.get("key2", None).is_none());
    }

    #[test]
    fn test_get_or_default() {
        let data = DbTraceUserData::new();
        assert_eq!(data.get_or("missing", None, "default"), "default");
    }

    #[test]
    fn test_remove() {
        let mut data = DbTraceUserData::new();
        data.put(UserDataEntry::new("k", "v"));
        assert!(data.contains("k", None));

        let removed = data.remove("k", None);
        assert!(removed.is_some());
        assert!(!data.contains("k", None));
    }

    #[test]
    fn test_namespace_entries() {
        let mut data = DbTraceUserData::new();
        data.put(UserDataEntry::new("a", "1").with_namespace("ns1"));
        data.put(UserDataEntry::new("b", "2").with_namespace("ns1"));
        data.put(UserDataEntry::new("c", "3").with_namespace("ns2"));

        let ns1_entries = data.entries_in_namespace("ns1");
        assert_eq!(ns1_entries.len(), 2);
    }

    #[test]
    fn test_persistent_filter() {
        let mut data = DbTraceUserData::new();
        data.put(UserDataEntry::new("a", "1").with_persistent(true));
        data.put(UserDataEntry::new("b", "2").with_persistent(false));
        data.put(UserDataEntry::new("c", "3").with_persistent(true));

        assert_eq!(data.persistent_entries().len(), 2);
    }

    #[test]
    fn test_clear() {
        let mut data = DbTraceUserData::new();
        data.put(UserDataEntry::new("a", "1"));
        data.put(UserDataEntry::new("b", "2"));
        assert_eq!(data.len(), 2);

        data.clear();
        assert!(data.is_empty());
    }

    #[test]
    fn test_user_data_serde() {
        let mut data = DbTraceUserData::new();
        data.put(UserDataEntry::new("k", "v").with_namespace("test"));

        let json = serde_json::to_string(&data).unwrap();
        let back: DbTraceUserData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.get_string("k", Some("test")), Some("v"));
    }

    #[test]
    fn test_entry_serde() {
        let entry = UserDataEntry::new("key", "value")
            .with_namespace("ns")
            .with_persistent(false);
        let json = serde_json::to_string(&entry).unwrap();
        let back: UserDataEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, "key");
        assert!(!back.persistent);
    }
}
