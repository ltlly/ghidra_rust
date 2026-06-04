//! Port of `ghidra.service.graph.AttributedEdge`.
//!
//! A directed edge in an [`AttributedGraph`] connecting two vertices.

use std::collections::HashMap;

use super::attributed::{Attributed, AttributeMap};

/// A directed edge in an attributed graph.
///
/// Mirrors `ghidra.service.graph.AttributedEdge`.
#[derive(Debug, Clone)]
pub struct AttributedEdge {
    /// Unique id for this edge.
    id: String,
    /// The source vertex id.
    start_id: String,
    /// The target vertex id.
    end_id: String,
    /// The edge type (e.g., "call", "branch", "fall-through").
    edge_type: Option<String>,
    /// Named attributes.
    attributes: AttributeMap,
}

impl AttributedEdge {
    /// Create a new edge.
    pub fn new(
        id: impl Into<String>,
        start_id: impl Into<String>,
        end_id: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            start_id: start_id.into(),
            end_id: end_id.into(),
            edge_type: None,
            attributes: AttributeMap::new(),
        }
    }

    /// Create an edge with a type.
    pub fn with_type(
        id: impl Into<String>,
        start_id: impl Into<String>,
        end_id: impl Into<String>,
        edge_type: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            start_id: start_id.into(),
            end_id: end_id.into(),
            edge_type: Some(edge_type.into()),
            attributes: AttributeMap::new(),
        }
    }

    /// Get the edge id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the source vertex id.
    pub fn start_id(&self) -> &str {
        &self.start_id
    }

    /// Get the target vertex id.
    pub fn end_id(&self) -> &str {
        &self.end_id
    }

    /// Get the edge type, if set.
    pub fn edge_type(&self) -> Option<&str> {
        self.edge_type.as_deref()
    }

    /// Set the edge type.
    pub fn set_edge_type(&mut self, etype: impl Into<String>) {
        self.edge_type = Some(etype.into());
    }
}

impl Attributed for AttributedEdge {
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

impl PartialEq for AttributedEdge {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for AttributedEdge {}

impl std::hash::Hash for AttributedEdge {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl std::fmt::Display for AttributedEdge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.start_id, self.end_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_basic() {
        let e = AttributedEdge::new("e1", "v1", "v2");
        assert_eq!(e.id(), "e1");
        assert_eq!(e.start_id(), "v1");
        assert_eq!(e.end_id(), "v2");
        assert!(e.edge_type().is_none());
    }

    #[test]
    fn test_edge_with_type() {
        let e = AttributedEdge::with_type("e2", "a", "b", "call");
        assert_eq!(e.edge_type(), Some("call"));
    }

    #[test]
    fn test_edge_attributes() {
        let mut e = AttributedEdge::new("e1", "v1", "v2");
        e.put("weight", "5");
        assert_eq!(e.get("weight"), Some("5"));
    }

    #[test]
    fn test_edge_display() {
        let e = AttributedEdge::new("e1", "main", "printf");
        assert_eq!(e.to_string(), "main -> printf");
    }

    #[test]
    fn test_edge_set_type() {
        let mut e = AttributedEdge::new("e1", "v1", "v2");
        e.set_edge_type("fall-through");
        assert_eq!(e.edge_type(), Some("fall-through"));
    }
}
