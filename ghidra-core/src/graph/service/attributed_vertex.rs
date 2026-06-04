//! Port of `ghidra.service.graph.AttributedVertex`.
//!
//! A vertex in an [`AttributedGraph`] with a string id and named attributes.

use std::collections::HashMap;

use super::attributed::{Attributed, AttributeMap};

/// A vertex in an attributed graph.
///
/// Mirrors `ghidra.service.graph.AttributedVertex`.
#[derive(Debug, Clone)]
pub struct AttributedVertex {
    /// Unique id for this vertex.
    id: String,
    /// Display name.
    name: String,
    /// The vertex type (e.g., "function", "basic_block").
    vertex_type: Option<String>,
    /// Named attributes.
    attributes: AttributeMap,
}

impl AttributedVertex {
    /// Create a new vertex with the given id and name.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            vertex_type: None,
            attributes: AttributeMap::new(),
        }
    }

    /// Create a vertex with a type.
    pub fn with_type(
        id: impl Into<String>,
        name: impl Into<String>,
        vertex_type: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            vertex_type: Some(vertex_type.into()),
            attributes: AttributeMap::new(),
        }
    }

    /// Get the vertex id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the vertex name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the vertex name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// Get the vertex type, if set.
    pub fn vertex_type(&self) -> Option<&str> {
        self.vertex_type.as_deref()
    }

    /// Set the vertex type.
    pub fn set_vertex_type(&mut self, vtype: impl Into<String>) {
        self.vertex_type = Some(vtype.into());
    }
}

impl Attributed for AttributedVertex {
    fn get(&self, name: &str) -> Option<&str> {
        self.attributes.get(name)
    }

    fn put(&mut self, name: &str, value: &str) {
        self.attributes.put(name, value);
    }

    fn keys(&self) -> Vec<&str> {
        self.attributes.keys()
    }

    fn attributes(&self) -> &HashMap<String, String> {
        self.attributes.attributes()
    }

    fn attributes_mut(&mut self) -> &mut HashMap<String, String> {
        self.attributes.attributes_mut()
    }
}

impl PartialEq for AttributedVertex {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for AttributedVertex {}

impl std::hash::Hash for AttributedVertex {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl std::fmt::Display for AttributedVertex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vertex_basic() {
        let v = AttributedVertex::new("v1", "Node A");
        assert_eq!(v.id(), "v1");
        assert_eq!(v.name(), "Node A");
        assert!(v.vertex_type().is_none());
    }

    #[test]
    fn test_vertex_with_type() {
        let v = AttributedVertex::with_type("v2", "func_main", "function");
        assert_eq!(v.vertex_type(), Some("function"));
    }

    #[test]
    fn test_vertex_attributes() {
        let mut v = AttributedVertex::new("v1", "Test");
        v.put("color", "red");
        v.put("size", "10");
        assert_eq!(v.get("color"), Some("red"));
        assert_eq!(v.attribute_count(), 2);
    }

    #[test]
    fn test_vertex_set_name() {
        let mut v = AttributedVertex::new("v1", "Old Name");
        v.set_name("New Name");
        assert_eq!(v.name(), "New Name");
    }

    #[test]
    fn test_vertex_set_type() {
        let mut v = AttributedVertex::new("v1", "Test");
        assert!(v.vertex_type().is_none());
        v.set_vertex_type("basic_block");
        assert_eq!(v.vertex_type(), Some("basic_block"));
    }

    #[test]
    fn test_vertex_equality_by_id() {
        let v1 = AttributedVertex::new("v1", "A");
        let v2 = AttributedVertex::new("v1", "B"); // different name, same id
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_vertex_display() {
        let v = AttributedVertex::new("v1", "MyVertex");
        assert_eq!(v.to_string(), "MyVertex");
    }
}
