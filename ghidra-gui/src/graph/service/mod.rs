//! Service-layer graph types: attributed graphs, display options, graph types.
//!
//! Ports `ghidra.service.graph` package.

use std::collections::HashMap;

/// An attribute bag (string key/value pairs) attached to graph elements.
#[derive(Debug, Clone, Default)]
pub struct Attributed {
    attributes: HashMap<String, String>,
}

impl Attributed {
    /// Create an empty attribute bag.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set an attribute.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }

    /// Get an attribute.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(|s| s.as_str())
    }

    /// All attribute keys.
    pub fn keys(&self) -> Vec<&str> {
        self.attributes.keys().map(|s| s.as_str()).collect()
    }

    /// Number of attributes.
    pub fn len(&self) -> usize {
        self.attributes.len()
    }

    /// Whether there are no attributes.
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }
}

/// A vertex in an attributed graph.
#[derive(Debug, Clone)]
pub struct AttributedVertex {
    /// Unique vertex id.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Attributes.
    pub attributes: Attributed,
}

impl AttributedVertex {
    /// Create a new attributed vertex.
    pub fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            attributes: Attributed::new(),
        }
    }
}

/// An edge in an attributed graph.
#[derive(Debug, Clone)]
pub struct AttributedEdge {
    /// Unique edge id.
    pub id: String,
    /// Source vertex id.
    pub from_id: String,
    /// Destination vertex id.
    pub to_id: String,
    /// Attributes.
    pub attributes: Attributed,
}

impl AttributedEdge {
    /// Create a new attributed edge.
    pub fn new(
        id: impl Into<String>,
        from_id: impl Into<String>,
        to_id: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            from_id: from_id.into(),
            to_id: to_id.into(),
            attributes: Attributed::new(),
        }
    }
}

/// A complete attributed graph (vertices + edges + attributes).
///
/// Ports `ghidra.service.graph.AttributedGraph`.
#[derive(Debug, Clone)]
pub struct AttributedGraph {
    /// Graph name.
    pub name: String,
    /// Graph type identifier.
    pub graph_type: String,
    vertices: HashMap<String, AttributedVertex>,
    edges: HashMap<String, AttributedEdge>,
    /// Adjacency: vertex_id → list of edge_ids
    out_edges: HashMap<String, Vec<String>>,
    in_edges: HashMap<String, Vec<String>>,
}

impl AttributedGraph {
    /// Create an empty attributed graph.
    pub fn new(name: impl Into<String>, graph_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            graph_type: graph_type.into(),
            vertices: HashMap::new(),
            edges: HashMap::new(),
            out_edges: HashMap::new(),
            in_edges: HashMap::new(),
        }
    }

    /// Add a vertex.
    pub fn add_vertex(&mut self, vertex: AttributedVertex) {
        let id = vertex.id.clone();
        self.out_edges.entry(id.clone()).or_default();
        self.in_edges.entry(id.clone()).or_default();
        self.vertices.insert(id, vertex);
    }

    /// Add an edge.
    pub fn add_edge(&mut self, edge: AttributedEdge) {
        let eid = edge.id.clone();
        let from = edge.from_id.clone();
        let to = edge.to_id.clone();
        self.out_edges.entry(from).or_default().push(eid.clone());
        self.in_edges.entry(to).or_default().push(eid.clone());
        self.edges.insert(eid, edge);
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
    pub fn vertex_ids(&self) -> Vec<&str> {
        self.vertices.keys().map(|s| s.as_str()).collect()
    }

    /// All edge ids.
    pub fn edge_ids(&self) -> Vec<&str> {
        self.edges.keys().map(|s| s.as_str()).collect()
    }

    /// Number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Outgoing edges from a vertex.
    pub fn out_edges(&self, vertex_id: &str) -> Vec<&AttributedEdge> {
        self.out_edges
            .get(vertex_id)
            .map(|ids| ids.iter().filter_map(|eid| self.edges.get(eid.as_str())).collect())
            .unwrap_or_default()
    }

    /// Incoming edges to a vertex.
    pub fn in_edges(&self, vertex_id: &str) -> Vec<&AttributedEdge> {
        self.in_edges
            .get(vertex_id)
            .map(|ids| ids.iter().filter_map(|eid| self.edges.get(eid.as_str())).collect())
            .unwrap_or_default()
    }

    /// Successor vertex ids.
    pub fn successors(&self, vertex_id: &str) -> Vec<&str> {
        self.out_edges(vertex_id)
            .into_iter()
            .map(|e| e.to_id.as_str())
            .collect()
    }

    /// Predecessor vertex ids.
    pub fn predecessors(&self, vertex_id: &str) -> Vec<&str> {
        self.in_edges(vertex_id)
            .into_iter()
            .map(|e| e.from_id.as_str())
            .collect()
    }
}

/// Label position on graph vertices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphLabelPosition {
    /// No label.
    None,
    /// Label above vertex.
    Top,
    /// Label below vertex.
    Bottom,
    /// Label to the left.
    Left,
    /// Label to the right.
    Right,
    /// Label centered on vertex.
    Center,
}

/// Graph display options controlling colors, shapes, and label positions.
#[derive(Debug, Clone)]
pub struct GraphDisplayOptions {
    /// Default vertex fill color (CSS hex string).
    pub default_vertex_color: String,
    /// Default edge color.
    pub default_edge_color: String,
    /// Label position.
    pub label_position: GraphLabelPosition,
    /// Whether to show edge labels.
    pub show_edge_labels: bool,
}

impl Default for GraphDisplayOptions {
    fn default() -> Self {
        Self {
            default_vertex_color: "#FFFFFF".to_string(),
            default_edge_color: "#000000".to_string(),
            label_position: GraphLabelPosition::Center,
            show_edge_labels: false,
        }
    }
}

/// Vertex shape for rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VertexShape {
    /// Rectangle.
    Rectangle,
    /// Rounded rectangle.
    RoundedRectangle,
    /// Ellipse.
    Ellipse,
    /// Diamond.
    Diamond,
}

impl Default for VertexShape {
    fn default() -> Self {
        Self::RoundedRectangle
    }
}

/// A named graph type with a set of vertex types.
#[derive(Debug, Clone)]
pub struct GraphType {
    /// Unique type name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Vertex type names in this graph type.
    pub vertex_types: Vec<String>,
}

impl GraphType {
    /// Create a new graph type.
    pub fn new(name: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            vertex_types: Vec::new(),
        }
    }

    /// Add a vertex type.
    pub fn add_vertex_type(&mut self, vertex_type: impl Into<String>) {
        self.vertex_types.push(vertex_type.into());
    }
}

/// Empty (default) graph type.
pub fn empty_graph_type() -> GraphType {
    GraphType::new("Empty", "Empty")
}

/// Common layout algorithm names.
pub mod layout_names {
    /// Hierarchical (Sugiyama) layout.
    pub const HIERARCHICAL: &str = "Hierarchical";
    /// Circular layout.
    pub const CIRCULAR: &str = "Circular";
    /// Force-directed (Fruchterman-Reingold) layout.
    pub const FORCE_DIRECTED: &str = "ForceDirected";
    /// Grid layout.
    pub const GRID: &str = "Grid";
    /// Organic layout.
    pub const ORGANIC: &str = "Organic";
}
