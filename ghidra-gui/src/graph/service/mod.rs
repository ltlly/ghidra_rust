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
///
/// Ports Ghidra's `ghidra.service.graph.VertexShape` with all 9 shape types.
/// Each shape has geometry properties that control how vertices are drawn:
/// - `label_position` controls where the label sits relative to the shape
/// - `shape_to_label_ratio` scales the shape relative to its label
/// - `max_width_to_height_ratio` limits aspect ratio distortion
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VertexShape {
    /// Rectangle -- the default shape.
    Rectangle,
    /// Rounded rectangle.
    RoundedRectangle,
    /// Ellipse.
    Ellipse,
    /// Diamond (rotated square).
    Diamond,
    /// Triangle pointing up.
    TriangleUp,
    /// Triangle pointing down.
    TriangleDown,
    /// Five-pointed star.
    Star,
    /// Five-sided pentagon.
    Pentagon,
    /// Six-sided hexagon.
    Hexagon,
    /// Eight-sided octagon.
    Octagon,
}

impl Default for VertexShape {
    fn default() -> Self {
        Self::Rectangle
    }
}

impl VertexShape {
    /// All available shape variants in display order.
    pub const ALL: &[VertexShape] = &[
        VertexShape::Rectangle,
        VertexShape::RoundedRectangle,
        VertexShape::Ellipse,
        VertexShape::Diamond,
        VertexShape::TriangleUp,
        VertexShape::TriangleDown,
        VertexShape::Star,
        VertexShape::Pentagon,
        VertexShape::Hexagon,
        VertexShape::Octagon,
    ];

    /// Human-readable name for the shape.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Rectangle => "Rectangle",
            Self::RoundedRectangle => "Rounded Rectangle",
            Self::Ellipse => "Ellipse",
            Self::Diamond => "Diamond",
            Self::TriangleUp => "Triangle Up",
            Self::TriangleDown => "Triangle Down",
            Self::Star => "Star",
            Self::Pentagon => "Pentagon",
            Self::Hexagon => "Hexagon",
            Self::Octagon => "Octagon",
        }
    }

    /// Look up a shape by name (case-insensitive).
    pub fn from_name(name: &str) -> Option<Self> {
        let lower = name.to_lowercase();
        Self::ALL.iter().copied().find(|s| s.name().to_lowercase() == lower)
    }

    /// Sorted list of all shape names.
    pub fn shape_names() -> Vec<&'static str> {
        let mut names: Vec<&str> = Self::ALL.iter().map(|s| s.name()).collect();
        names.sort();
        names
    }

    /// Relative label position within the shape (0.0 = top, 1.0 = bottom).
    ///
    /// Shapes like triangles need labels pushed toward the wide end so text
    /// does not overflow the narrow part of the shape.
    pub fn label_position(&self) -> f64 {
        match self {
            Self::Rectangle | Self::RoundedRectangle => 0.5,
            Self::Ellipse => 0.5,
            Self::Diamond => 0.5,
            Self::TriangleUp => 0.90,
            Self::TriangleDown => 0.10,
            Self::Star => 0.5,
            Self::Pentagon | Self::Hexagon | Self::Octagon => 0.5,
        }
    }

    /// Scale factor for the shape relative to its label.
    ///
    /// Shapes with narrow tips (triangles, stars) need to be larger than
    /// rectangles so the label text fits inside.
    pub fn shape_to_label_ratio(&self) -> f64 {
        match self {
            Self::Rectangle | Self::RoundedRectangle => 1.0,
            Self::Ellipse => 1.4,
            Self::Diamond => 1.6,
            Self::TriangleUp | Self::TriangleDown => 1.6,
            Self::Star => 2.0,
            Self::Pentagon | Self::Hexagon | Self::Octagon => 1.4,
        }
    }

    /// Maximum width-to-height ratio before the shape becomes too distorted.
    pub fn max_width_to_height_ratio(&self) -> u32 {
        match self {
            Self::Rectangle | Self::RoundedRectangle => 10,
            Self::Ellipse => 10,
            Self::Diamond => 10,
            Self::TriangleUp | Self::TriangleDown => 10,
            Self::Star => 10,
            Self::Pentagon | Self::Hexagon | Self::Octagon => 2,
        }
    }

    /// Generate polygon points for this shape (normalized to a unit circle).
    ///
    /// Returns a list of (x, y) vertices forming the shape boundary.
    /// The shape is centered at (0, 0) with radius 1.0.
    pub fn polygon_points(&self) -> Vec<(f64, f64)> {
        match self {
            Self::Rectangle | Self::RoundedRectangle => {
                vec![(-1.0, -1.0), (1.0, -1.0), (1.0, 1.0), (-1.0, 1.0)]
            }
            Self::Ellipse => {
                // Approximate ellipse with 32 segments
                (0..32)
                    .map(|i| {
                        let angle = std::f64::consts::TAU * i as f64 / 32.0;
                        (angle.cos(), angle.sin())
                    })
                    .collect()
            }
            Self::Diamond => {
                vec![(0.0, -1.0), (-1.0, 0.0), (0.0, 1.0), (1.0, 0.0)]
            }
            Self::TriangleUp => {
                vec![(-1.0, 1.0), (1.0, 1.0), (0.0, -1.0)]
            }
            Self::TriangleDown => {
                vec![(-1.0, -1.0), (1.0, -1.0), (0.0, 1.0)]
            }
            Self::Star => {
                let num_points = 7;
                let outer_radius = 2.0;
                let inner_radius = 1.0;
                let delta_angle = std::f64::consts::PI / num_points as f64;
                let mut angle = 3.0 * std::f64::consts::PI / 2.0;
                let mut points = Vec::new();
                points.push((outer_radius * angle.cos(), outer_radius * angle.sin()));
                for _ in 0..num_points {
                    angle += delta_angle;
                    points.push((inner_radius * angle.cos(), inner_radius * angle.sin()));
                    angle += delta_angle;
                    points.push((outer_radius * angle.cos(), outer_radius * angle.sin()));
                }
                points
            }
            Self::Pentagon => equilateral_polygon(5, std::f64::consts::PI + std::f64::consts::PI / 10.0),
            Self::Hexagon => equilateral_polygon(6, 0.0),
            Self::Octagon => equilateral_polygon(8, 0.0),
        }
    }
}

impl std::fmt::Display for VertexShape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Generate points for an equilateral polygon with `num_sides` sides,
/// starting at `start_angle` radians.
fn equilateral_polygon(num_sides: usize, start_angle: f64) -> Vec<(f64, f64)> {
    let delta_angle = std::f64::consts::TAU / num_sides as f64;
    let mut angle = start_angle;
    (0..num_sides)
        .map(|_| {
            let pt = (angle.cos(), angle.sin());
            angle += delta_angle;
            pt
        })
        .collect()
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
        assert_eq!(VertexShape::default(), VertexShape::Rectangle);
    }

    #[test]
    fn vertex_shape_name() {
        assert_eq!(VertexShape::Rectangle.name(), "Rectangle");
        assert_eq!(VertexShape::TriangleUp.name(), "Triangle Up");
        assert_eq!(VertexShape::Star.name(), "Star");
    }

    #[test]
    fn vertex_shape_from_name() {
        assert_eq!(VertexShape::from_name("Ellipse"), Some(VertexShape::Ellipse));
        assert_eq!(VertexShape::from_name("ellipse"), Some(VertexShape::Ellipse));
        assert_eq!(VertexShape::from_name("STAR"), Some(VertexShape::Star));
        assert_eq!(VertexShape::from_name("Nonexistent"), None);
    }

    #[test]
    fn vertex_shape_all_count() {
        assert_eq!(VertexShape::ALL.len(), 10);
    }

    #[test]
    fn vertex_shape_names() {
        let names = VertexShape::shape_names();
        assert!(names.contains(&"Rectangle"));
        assert!(names.contains(&"Hexagon"));
    }

    #[test]
    fn vertex_shape_label_position() {
        assert!((VertexShape::TriangleUp.label_position() - 0.90).abs() < 1e-6);
        assert!((VertexShape::TriangleDown.label_position() - 0.10).abs() < 1e-6);
        assert!((VertexShape::Rectangle.label_position() - 0.5).abs() < 1e-6);
    }

    #[test]
    fn vertex_shape_ratio() {
        assert!((VertexShape::Rectangle.shape_to_label_ratio() - 1.0).abs() < 1e-6);
        assert!((VertexShape::Star.shape_to_label_ratio() - 2.0).abs() < 1e-6);
        assert!((VertexShape::Ellipse.shape_to_label_ratio() - 1.4).abs() < 1e-6);
    }

    #[test]
    fn vertex_shape_polygon_points() {
        let rect = VertexShape::Rectangle.polygon_points();
        assert_eq!(rect.len(), 4);
        let tri = VertexShape::TriangleUp.polygon_points();
        assert_eq!(tri.len(), 3);
        let pent = VertexShape::Pentagon.polygon_points();
        assert_eq!(pent.len(), 5);
        let hex = VertexShape::Hexagon.polygon_points();
        assert_eq!(hex.len(), 6);
        let oct = VertexShape::Octagon.polygon_points();
        assert_eq!(oct.len(), 8);
        let star = VertexShape::Star.polygon_points();
        assert!(star.len() > 10); // 7 points * 2 + 1
        let ellipse = VertexShape::Ellipse.polygon_points();
        assert_eq!(ellipse.len(), 32);
    }

    #[test]
    fn vertex_shape_display() {
        assert_eq!(format!("{}", VertexShape::Diamond), "Diamond");
        assert_eq!(format!("{}", VertexShape::Hexagon), "Hexagon");
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
