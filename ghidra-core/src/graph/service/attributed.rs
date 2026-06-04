//! Port of `ghidra.service.graph.Attributed`.
//!
//! Trait for objects that carry named string attributes.

use std::collections::HashMap;

/// An object that has named string attributes.
///
/// Mirrors `ghidra.service.graph.Attributed`.
pub trait Attributed {
    /// Get the value of an attribute by name.
    fn get(&self, name: &str) -> Option<&str>;

    /// Set an attribute value.
    fn put(&mut self, name: &str, value: &str);

    /// Get all attribute names.
    fn keys(&self) -> Vec<&str>;

    /// Get all attributes as a map reference.
    fn attributes(&self) -> &HashMap<String, String>;

    /// Get all attributes as a mutable map reference.
    fn attributes_mut(&mut self) -> &mut HashMap<String, String>;

    /// Check if an attribute exists.
    fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Remove an attribute, returning its previous value if present.
    fn remove(&mut self, name: &str) -> Option<String> {
        self.attributes_mut().remove(name)
    }

    /// The number of attributes.
    fn attribute_count(&self) -> usize {
        self.attributes().len()
    }
}

/// A basic implementation of [`Attributed`] backed by a `HashMap`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttributeMap {
    attrs: HashMap<String, String>,
}

impl AttributeMap {
    /// Create an empty attribute map.
    pub fn new() -> Self {
        Self { attrs: HashMap::new() }
    }

    /// Create an attribute map with initial capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self { attrs: HashMap::with_capacity(cap) }
    }

    /// Set an attribute and return self for chaining.
    pub fn with(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs.insert(name.into(), value.into());
        self
    }
}

impl Attributed for AttributeMap {
    fn get(&self, name: &str) -> Option<&str> {
        self.attrs.get(name).map(|s| s.as_str())
    }

    fn put(&mut self, name: &str, value: &str) {
        self.attrs.insert(name.to_string(), value.to_string());
    }

    fn keys(&self) -> Vec<&str> {
        self.attrs.keys().map(|s| s.as_str()).collect()
    }

    fn attributes(&self) -> &HashMap<String, String> {
        &self.attrs
    }

    fn attributes_mut(&mut self) -> &mut HashMap<String, String> {
        &mut self.attrs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_map_basic() {
        let mut map = AttributeMap::new();
        map.put("color", "red");
        map.put("shape", "box");

        assert_eq!(map.get("color"), Some("red"));
        assert_eq!(map.get("shape"), Some("box"));
        assert_eq!(map.get("missing"), None);
        assert_eq!(map.attribute_count(), 2);
    }

    #[test]
    fn test_attribute_map_with_builder() {
        let map = AttributeMap::new()
            .with("label", "Node A")
            .with("color", "blue");

        assert_eq!(map.get("label"), Some("Node A"));
        assert_eq!(map.get("color"), Some("blue"));
    }

    #[test]
    fn test_attribute_map_has() {
        let mut map = AttributeMap::new();
        map.put("key", "val");
        assert!(map.has("key"));
        assert!(!map.has("nope"));
    }

    #[test]
    fn test_attribute_map_remove() {
        let mut map = AttributeMap::new();
        map.put("a", "1");
        let removed = map.remove("a");
        assert_eq!(removed.as_deref(), Some("1"));
        assert!(!map.has("a"));
        assert_eq!(map.attribute_count(), 0);
    }

    #[test]
    fn test_attribute_map_keys() {
        let mut map = AttributeMap::new();
        map.put("x", "1");
        map.put("y", "2");
        let mut keys: Vec<&str> = map.keys();
        keys.sort();
        assert_eq!(keys, vec!["x", "y"]);
    }

    #[test]
    fn test_attribute_map_overwrite() {
        let mut map = AttributeMap::new();
        map.put("key", "old");
        map.put("key", "new");
        assert_eq!(map.get("key"), Some("new"));
        assert_eq!(map.attribute_count(), 1);
    }
}
