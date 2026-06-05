//! ExtKeyValue - key-value pairs for taint analysis extensions.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.taint.ExtKeyValue`.

use serde::{Deserialize, Serialize};

/// A key-value pair used in taint analysis extensions.
///
/// Ported from Ghidra's `ExtKeyValue`. Stores metadata about
/// taint sources, sinks, and propagation paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtKeyValue {
    /// The key identifying this property.
    pub key: String,
    /// The value of the property.
    pub value: String,
    /// Optional namespace for the key.
    pub namespace: Option<String>,
    /// Whether this is a user-defined property.
    pub user_defined: bool,
}

impl ExtKeyValue {
    /// Create a new key-value pair.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            namespace: None,
            user_defined: false,
        }
    }

    /// Create a user-defined key-value pair.
    pub fn user(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            namespace: None,
            user_defined: true,
        }
    }

    /// Set the namespace.
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// Get the fully qualified key (namespace::key or just key).
    pub fn qualified_key(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}::{}", ns, self.key),
            None => self.key.clone(),
        }
    }
}

/// A collection of key-value pairs with lookup by key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtKeyValueSet {
    entries: Vec<ExtKeyValue>,
}

impl ExtKeyValueSet {
    /// Create an empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key-value pair.
    pub fn push(&mut self, kv: ExtKeyValue) {
        self.entries.push(kv);
    }

    /// Find a value by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.key == key)
            .map(|e| e.value.as_str())
    }

    /// Find a value by qualified key (namespace::key).
    pub fn get_qualified(&self, qualified_key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.qualified_key() == qualified_key)
            .map(|e| e.value.as_str())
    }

    /// Get all entries.
    pub fn entries(&self) -> &[ExtKeyValue] {
        &self.entries
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Filter entries by namespace.
    pub fn filter_by_namespace(&self, namespace: &str) -> Vec<&ExtKeyValue> {
        self.entries
            .iter()
            .filter(|e| e.namespace.as_deref() == Some(namespace))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ext_key_value() {
        let kv = ExtKeyValue::new("source", "stdin");
        assert_eq!(kv.key, "source");
        assert_eq!(kv.value, "stdin");
        assert!(!kv.user_defined);
    }

    #[test]
    fn test_qualified_key() {
        let kv = ExtKeyValue::new("tainted", "true").with_namespace("angr");
        assert_eq!(kv.qualified_key(), "angr::tainted");
    }

    #[test]
    fn test_user_kv() {
        let kv = ExtKeyValue::user("note", "manually marked");
        assert!(kv.user_defined);
    }

    #[test]
    fn test_kv_set() {
        let mut set = ExtKeyValueSet::new();
        set.push(ExtKeyValue::new("a", "1"));
        set.push(ExtKeyValue::new("b", "2").with_namespace("ns"));
        assert_eq!(set.len(), 2);
        assert_eq!(set.get("a"), Some("1"));
        assert_eq!(set.get("missing"), None);
    }

    #[test]
    fn test_qualified_lookup() {
        let mut set = ExtKeyValueSet::new();
        set.push(ExtKeyValue::new("x", "val").with_namespace("test"));
        assert_eq!(set.get_qualified("test::x"), Some("val"));
        assert_eq!(set.get_qualified("other::x"), None);
    }

    #[test]
    fn test_filter_by_namespace() {
        let mut set = ExtKeyValueSet::new();
        set.push(ExtKeyValue::new("a", "1").with_namespace("ns1"));
        set.push(ExtKeyValue::new("b", "2").with_namespace("ns2"));
        set.push(ExtKeyValue::new("c", "3").with_namespace("ns1"));
        assert_eq!(set.filter_by_namespace("ns1").len(), 2);
        assert_eq!(set.filter_by_namespace("ns2").len(), 1);
    }

    #[test]
    fn test_serde() {
        let kv = ExtKeyValue::new("test", "val").with_namespace("ns");
        let json = serde_json::to_string(&kv).unwrap();
        let back: ExtKeyValue = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, "test");
    }
}
