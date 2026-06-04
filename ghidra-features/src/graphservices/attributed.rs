//! Attributed graph model.
//!
//! Ported from Ghidra's `ghidra.service.graph` Java package.
//!
//! Provides [`AttributedGraph`], [`AttributedVertex`], and [`AttributedEdge`]
//! -- a general-purpose directed graph where vertices and edges carry
//! string key-value attributes.

use std::collections::HashMap;

/// A map of string key-value pairs describing an entity.
pub type AttributeMap = HashMap<String, String>;

/// Trait for objects that carry a set of string attributes.
pub trait Attributed {
    /// Return a reference to the attribute map.
    fn attributes(&self) -> &AttributeMap;

    /// Return a mutable reference to the attribute map.
    fn attributes_mut(&mut self) -> &mut AttributeMap;

    /// Get a single attribute value by key.
    fn get(&self, key: &str) -> Option<&str> {
        self.attributes().get(key).map(|s| s.as_str())
    }

    /// Set an attribute value.
    fn set(&mut self, key: &str, value: &str) {
        self.attributes_mut().insert(key.to_string(), value.to_string());
    }
}

/// A vertex in an attributed graph.
#[derive(Debug, Clone)]
pub struct AttributedVertex {
    id: String,
    name: String,
    attributes: AttributeMap,
}

impl AttributedVertex {
    /// Create a new vertex with the given id and name.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        let name_s = name.into();
        let mut attributes = AttributeMap::new();
        attributes.insert("Name".to_string(), name_s.clone());
        Self {
            id: id.into(),
            name: name_s,
            attributes,
        }
    }

    /// The unique identifier for this vertex.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The display name of this vertex.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Attributed for AttributedVertex {
    fn attributes(&self) -> &AttributeMap {
        &self.attributes
    }

    fn attributes_mut(&mut self) -> &mut AttributeMap {
        &mut self.attributes
    }
}

/// An edge in an attributed graph.
#[derive(Debug, Clone)]
pub struct AttributedEdge {
    id: String,
    source_id: String,
    target_id: String,
    edge_type: Option<String>,
    attributes: AttributeMap,
}

impl AttributedEdge {
    /// Create a new edge between two vertices.
    pub fn new(
        id: impl Into<String>,
        source_id: impl Into<String>,
        target_id: impl Into<String>,
        edge_type: Option<String>,
    ) -> Self {
        let mut attributes = AttributeMap::new();
        if let Some(ref etype) = edge_type {
            attributes.insert("EdgeType".to_string(), etype.clone());
        }
        Self {
            id: id.into(),
            source_id: source_id.into(),
            target_id: target_id.into(),
            edge_type,
            attributes,
        }
    }

    /// The unique identifier for this edge.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The id of the source vertex.
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// The id of the target vertex.
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    /// The edge type, if any.
    pub fn edge_type(&self) -> Option<&str> {
        self.edge_type.as_deref()
    }
}

impl Attributed for AttributedEdge {
    fn attributes(&self) -> &AttributeMap {
        &self.attributes
    }

    fn attributes_mut(&mut self) -> &mut AttributeMap {
        &mut self.attributes
    }
}

/// An attributed directed graph.
///
/// Vertices are identified by string ids and edges connect pairs of vertices.
/// Both vertices and edges carry string attributes.
///
/// Ported from Ghidra's `AttributedGraph` class.
#[derive(Debug, Clone)]
pub struct AttributedGraph {
    name: String,
    graph_type: String,
    vertices: HashMap<String, AttributedVertex>,
    edges: HashMap<String, AttributedEdge>,
    adjacency: HashMap<String, Vec<String>>, // vertex_id -> [edge_id]
    next_edge_id: u64,
}

impl AttributedGraph {
    /// Create a new empty graph.
    pub fn new(name: impl Into<String>, graph_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            graph_type: graph_type.into(),
            vertices: HashMap::new(),
            edges: HashMap::new(),
            adjacency: HashMap::new(),
            next_edge_id: 0,
        }
    }

    /// The graph name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The graph type (e.g. "Function Call Graph", "Control Flow Graph").
    pub fn graph_type(&self) -> &str {
        &self.graph_type
    }

    /// Add a vertex to the graph.
    pub fn add_vertex(&mut self, vertex: AttributedVertex) {
        let id = vertex.id.clone();
        self.adjacency.entry(id.clone()).or_default();
        self.vertices.insert(id, vertex);
    }

    /// Add an edge between two vertices.
    ///
    /// Returns the edge id. Panics if source or target vertex does not exist.
    pub fn add_edge(
        &mut self,
        source_id: &str,
        target_id: &str,
        edge_type: Option<String>,
    ) -> String {
        assert!(
            self.vertices.contains_key(source_id),
            "source vertex not found"
        );
        assert!(
            self.vertices.contains_key(target_id),
            "target vertex not found"
        );
        let id = format!("edge_{}", self.next_edge_id);
        self.next_edge_id += 1;
        let edge = AttributedEdge::new(&id, source_id, target_id, edge_type);
        self.adjacency
            .entry(source_id.to_string())
            .or_default()
            .push(id.clone());
        self.edges.insert(id.clone(), edge);
        id
    }

    /// Get a vertex by id.
    pub fn vertex(&self, id: &str) -> Option<&AttributedVertex> {
        self.vertices.get(id)
    }

    /// Get an edge by id.
    pub fn edge(&self, id: &str) -> Option<&AttributedEdge> {
        self.edges.get(id)
    }

    /// All vertex ids.
    pub fn vertex_ids(&self) -> impl Iterator<Item = &str> {
        self.vertices.keys().map(|s| s.as_str())
    }

    /// All vertices.
    pub fn vertices(&self) -> impl Iterator<Item = &AttributedVertex> {
        self.vertices.values()
    }

    /// All edges.
    pub fn edges(&self) -> impl Iterator<Item = &AttributedEdge> {
        self.edges.values()
    }

    /// Number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Get edge ids incident from a vertex (outgoing edges).
    pub fn incident_edges(&self, vertex_id: &str) -> &[String] {
        self.adjacency
            .get(vertex_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

impl Default for AttributedGraph {
    fn default() -> Self {
        Self::new("unnamed", "generic")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_basic() {
        let mut g = AttributedGraph::new("test", "cfg");
        let mut v1 = AttributedVertex::new("A", "Block A");
        v1.set("color", "red");
        let v2 = AttributedVertex::new("B", "Block B");
        g.add_vertex(v1);
        g.add_vertex(v2);
        let e_id = g.add_edge("A", "B", Some("fallthrough".to_string()));

        assert_eq!(g.vertex_count(), 2);
        assert_eq!(g.edge_count(), 1);
        assert_eq!(g.vertex("A").unwrap().name(), "Block A");
        assert_eq!(
            g.edge(&e_id).unwrap().edge_type(),
            Some("fallthrough")
        );
    }

    #[test]
    fn test_graph_adjacency() {
        let mut g = AttributedGraph::new("test", "cfg");
        g.add_vertex(AttributedVertex::new("A", "A"));
        g.add_vertex(AttributedVertex::new("B", "B"));
        g.add_edge("A", "B", None);

        let edges = g.incident_edges("A");
        assert_eq!(edges.len(), 1);
        assert_eq!(g.incident_edges("B").len(), 0);
    }

    #[test]
    fn test_vertex_attributes() {
        let mut v = AttributedVertex::new("v1", "start");
        assert_eq!(v.get("Name"), Some("start"));
        v.set("color", "blue");
        assert_eq!(v.get("color"), Some("blue"));
    }

    #[test]
    fn test_default_graph() {
        let g = AttributedGraph::default();
        assert_eq!(g.name(), "unnamed");
        assert_eq!(g.graph_type(), "generic");
    }
}
