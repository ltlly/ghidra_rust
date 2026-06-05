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

// ============================================================================
// GraphDisplayOptionsBuilder
// ============================================================================

/// Builder for constructing [`GraphDisplayOptions`] with a fluent API.
///
/// Ports `ghidra.service.graph.GraphDisplayOptionsBuilder`.
///
/// # Example
///
/// ```
/// use ghidra_gui::graph::service::{GraphDisplayOptionsBuilder, GraphLabelPosition};
///
/// let opts = GraphDisplayOptionsBuilder::new("cfg")
///     .default_vertex_color("#FFE0E0")
///     .default_edge_color("#333333")
///     .label_position(GraphLabelPosition::Top)
///     .show_edge_labels(true)
///     .build();
/// assert_eq!(opts.default_vertex_color, "#FFE0E0");
/// ```
pub struct GraphDisplayOptionsBuilder {
    graph_type_name: String,
    options: GraphDisplayOptions,
}

impl GraphDisplayOptionsBuilder {
    /// Create a new builder for the given graph type.
    pub fn new(graph_type_name: impl Into<String>) -> Self {
        Self {
            graph_type_name: graph_type_name.into(),
            options: GraphDisplayOptions::default(),
        }
    }

    /// Set the default vertex fill color.
    pub fn default_vertex_color(mut self, color: impl Into<String>) -> Self {
        self.options.default_vertex_color = color.into();
        self
    }

    /// Set the default edge color.
    pub fn default_edge_color(mut self, color: impl Into<String>) -> Self {
        self.options.default_edge_color = color.into();
        self
    }

    /// Set the label position.
    pub fn label_position(mut self, position: GraphLabelPosition) -> Self {
        self.options.label_position = position;
        self
    }

    /// Set whether to show edge labels.
    pub fn show_edge_labels(mut self, show: bool) -> Self {
        self.options.show_edge_labels = show;
        self
    }

    /// Build the final [`GraphDisplayOptions`].
    pub fn build(self) -> GraphDisplayOptions {
        self.options
    }

    /// Get the graph type name.
    pub fn graph_type_name(&self) -> &str {
        &self.graph_type_name
    }
}

/// Pre-configured default display options for common graph types.
pub struct DefaultGraphDisplayOptions;

impl DefaultGraphDisplayOptions {
    /// Default display options for control-flow graphs.
    pub fn cfg_options() -> GraphDisplayOptions {
        GraphDisplayOptionsBuilder::new("cfg")
            .default_vertex_color("#FFFFFF")
            .default_edge_color("#000000")
            .label_position(GraphLabelPosition::Center)
            .show_edge_labels(false)
            .build()
    }

    /// Default display options for data-flow graphs.
    pub fn dfg_options() -> GraphDisplayOptions {
        GraphDisplayOptionsBuilder::new("dfg")
            .default_vertex_color("#E0F0FF")
            .default_edge_color("#0066CC")
            .label_position(GraphLabelPosition::Center)
            .show_edge_labels(true)
            .build()
    }

    /// Default display options for call graphs.
    pub fn call_graph_options() -> GraphDisplayOptions {
        GraphDisplayOptionsBuilder::new("callgraph")
            .default_vertex_color("#E0FFE0")
            .default_edge_color("#336633")
            .label_position(GraphLabelPosition::Bottom)
            .show_edge_labels(false)
            .build()
    }
}

/// Builder for constructing [`GraphType`] with a fluent API.
///
/// Ports `ghidra.service.graph.GraphTypeBuilder`.
pub struct GraphTypeBuilder {
    name: String,
    display_name: String,
    vertex_types: Vec<String>,
}

impl GraphTypeBuilder {
    /// Create a new graph type builder.
    pub fn new(name: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            vertex_types: Vec::new(),
        }
    }

    /// Add a vertex type.
    pub fn vertex_type(mut self, vtype: impl Into<String>) -> Self {
        self.vertex_types.push(vtype.into());
        self
    }

    /// Build the [`GraphType`].
    pub fn build(self) -> GraphType {
        GraphType {
            name: self.name,
            display_name: self.display_name,
            vertex_types: self.vertex_types,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Attributed tests ---

    #[test]
    fn attributed_basic() {
        let mut a = Attributed::new();
        assert!(a.is_empty());
        a.set("color", "red");
        assert_eq!(a.get("color"), Some("red"));
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn attributed_keys() {
        let mut a = Attributed::new();
        a.set("x", "1");
        a.set("y", "2");
        let keys = a.keys();
        assert_eq!(keys.len(), 2);
    }

    // --- AttributedVertex tests ---

    #[test]
    fn attributed_vertex() {
        let v = AttributedVertex::new("n1", "Node 1");
        assert_eq!(v.id, "n1");
        assert_eq!(v.label, "Node 1");
    }

    // --- AttributedEdge tests ---

    #[test]
    fn attributed_edge() {
        let e = AttributedEdge::new("e1", "n1", "n2");
        assert_eq!(e.from_id, "n1");
        assert_eq!(e.to_id, "n2");
    }

    // --- AttributedGraph tests ---

    #[test]
    fn graph_add_vertex_and_edge() {
        let mut g = AttributedGraph::new("test", "cfg");
        g.add_vertex(AttributedVertex::new("a", "A"));
        g.add_vertex(AttributedVertex::new("b", "B"));
        g.add_edge(AttributedEdge::new("ab", "a", "b"));
        assert_eq!(g.vertex_count(), 2);
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn graph_successors_predecessors() {
        let mut g = AttributedGraph::new("test", "cfg");
        g.add_vertex(AttributedVertex::new("a", "A"));
        g.add_vertex(AttributedVertex::new("b", "B"));
        g.add_edge(AttributedEdge::new("ab", "a", "b"));
        let succ = g.successors("a");
        assert_eq!(succ, vec!["b"]);
        let pred = g.predecessors("b");
        assert_eq!(pred, vec!["a"]);
    }

    // --- GraphLabelPosition tests ---

    #[test]
    fn label_position_variants() {
        assert_ne!(GraphLabelPosition::Top, GraphLabelPosition::Bottom);
    }

    // --- GraphDisplayOptions tests ---

    #[test]
    fn display_options_default() {
        let opts = GraphDisplayOptions::default();
        assert_eq!(opts.default_vertex_color, "#FFFFFF");
        assert_eq!(opts.label_position, GraphLabelPosition::Center);
    }

    // --- VertexShape tests ---

    #[test]
    fn vertex_shape_default() {
        assert_eq!(VertexShape::default(), VertexShape::RoundedRectangle);
    }

    // --- GraphType tests ---

    #[test]
    fn graph_type_new() {
        let mut gt = GraphType::new("cfg", "Control Flow Graph");
        gt.add_vertex_type("basic_block");
        assert_eq!(gt.name, "cfg");
        assert_eq!(gt.vertex_types.len(), 1);
    }

    // --- GraphDisplayOptionsBuilder tests ---

    #[test]
    fn builder_fluent_api() {
        let opts = GraphDisplayOptionsBuilder::new("dfg")
            .default_vertex_color("#E0F0FF")
            .default_edge_color("#0066CC")
            .label_position(GraphLabelPosition::Top)
            .show_edge_labels(true)
            .build();
        assert_eq!(opts.default_vertex_color, "#E0F0FF");
        assert_eq!(opts.default_edge_color, "#0066CC");
        assert_eq!(opts.label_position, GraphLabelPosition::Top);
        assert!(opts.show_edge_labels);
    }

    #[test]
    fn builder_defaults_preserved() {
        let opts = GraphDisplayOptionsBuilder::new("test").build();
        assert_eq!(opts.default_vertex_color, "#FFFFFF");
        assert_eq!(opts.label_position, GraphLabelPosition::Center);
        assert!(!opts.show_edge_labels);
    }

    #[test]
    fn builder_graph_type_name() {
        let builder = GraphDisplayOptionsBuilder::new("cfg");
        assert_eq!(builder.graph_type_name(), "cfg");
    }

    // --- DefaultGraphDisplayOptions tests ---

    #[test]
    fn default_cfg_options() {
        let opts = DefaultGraphDisplayOptions::cfg_options();
        assert_eq!(opts.default_vertex_color, "#FFFFFF");
    }

    #[test]
    fn default_dfg_options() {
        let opts = DefaultGraphDisplayOptions::dfg_options();
        assert_eq!(opts.default_vertex_color, "#E0F0FF");
        assert!(opts.show_edge_labels);
    }

    #[test]
    fn default_call_graph_options() {
        let opts = DefaultGraphDisplayOptions::call_graph_options();
        assert_eq!(opts.label_position, GraphLabelPosition::Bottom);
    }

    // --- GraphTypeBuilder tests ---

    #[test]
    fn graph_type_builder() {
        let gt = GraphTypeBuilder::new("cfg", "Control Flow Graph")
            .vertex_type("basic_block")
            .vertex_type("entry")
            .vertex_type("exit")
            .build();
        assert_eq!(gt.name, "cfg");
        assert_eq!(gt.display_name, "Control Flow Graph");
        assert_eq!(gt.vertex_types.len(), 3);
        assert_eq!(gt.vertex_types[0], "basic_block");
    }

    // --- empty_graph_type ---

    #[test]
    fn test_empty_graph_type() {
        let gt = super::empty_graph_type();
        assert_eq!(gt.name, "Empty");
    }

    // --- layout_names ---

    #[test]
    fn layout_names_present() {
        assert_eq!(layout_names::HIERARCHICAL, "Hierarchical");
        assert_eq!(layout_names::FORCE_DIRECTED, "ForceDirected");
    }
}
