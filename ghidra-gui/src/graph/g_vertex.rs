//! GVertex: base vertex type for Ghidra's graph framework.
//!
//! Ported from `ghidra.graph.GVertex`.

use std::collections::HashMap;
use std::fmt;

/// A vertex in a directed graph.
///
/// Each vertex has an id and an arbitrary payload.  Ported from
/// Ghidra's `GVertex`.
#[derive(Debug, Clone)]
pub struct GVertex<V: Clone + Eq + std::hash::Hash> {
    /// Unique vertex identifier.
    pub id: V,
    /// Optional display label.
    pub label: Option<String>,
    /// Arbitrary user data.
    pub data: HashMap<String, String>,
}

impl<V: Clone + Eq + std::hash::Hash> GVertex<V> {
    /// Create a new vertex with the given id.
    pub fn new(id: V) -> Self {
        Self { id, label: None, data: HashMap::new() }
    }

    /// Create a new vertex with a label.
    pub fn with_label(id: V, label: impl Into<String>) -> Self {
        Self { id, label: Some(label.into()), data: HashMap::new() }
    }

    /// Set a data attribute.
    pub fn set_data(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.data.insert(key.into(), value.into());
    }

    /// Get a data attribute.
    pub fn get_data(&self, key: &str) -> Option<&str> {
        self.data.get(key).map(|s| s.as_str())
    }
}

impl<V: Clone + Eq + std::hash::Hash + fmt::Display> fmt::Display for GVertex<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.label {
            Some(l) => write!(f, "{}({})", l, self.id),
            None => write!(f, "{}", self.id),
        }
    }
}

impl<V: Clone + Eq + std::hash::Hash> PartialEq for GVertex<V> {
    fn eq(&self, other: &Self) -> bool { self.id == other.id }
}
impl<V: Clone + Eq + std::hash::Hash> Eq for GVertex<V> {}
impl<V: Clone + Eq + std::hash::Hash> std::hash::Hash for GVertex<V> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) { self.id.hash(state); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vertex_new() {
        let v = GVertex::new(1);
        assert_eq!(v.id, 1);
        assert!(v.label.is_none());
    }

    #[test]
    fn vertex_with_label() {
        let v = GVertex::with_label("main", "main()");
        assert_eq!(v.label.as_deref(), Some("main()"));
    }

    #[test]
    fn vertex_data() {
        let mut v = GVertex::new(1);
        v.set_data("addr", "0x1000");
        assert_eq!(v.get_data("addr"), Some("0x1000"));
    }

    #[test]
    fn vertex_display() {
        let v = GVertex::with_label(42, "func");
        assert_eq!(v.to_string(), "func(42)");
    }
}
