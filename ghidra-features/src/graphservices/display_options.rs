//! Graph display options and rendering configuration.
//!
//! Ported from Ghidra's `ghidra.service.graph.GraphDisplayOptions`,
//! `ghidra.visualization.DefaultGraphDisplayOptions`, and
//! `ghidra.graph.visualization.GraphRenderer` Java interface.
//!
//! Provides color, shape, font, and priority configuration for
//! rendering vertices and edges in an attributed graph display.

use std::collections::HashMap;

use super::attributed::{Attributed, AttributedEdge, AttributedVertex};

// ---------------------------------------------------------------------------
// Vertex shapes
// ---------------------------------------------------------------------------

/// Shape types available for graph vertices.
///
/// Maps to Ghidra's `VertexShape` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VertexShape {
    Rectangle,
    RoundedRectangle,
    Ellipse,
    Triangle,
    Diamond,
    Star,
    Hexagon,
    Pentagon,
    Octagon,
}

impl VertexShape {
    /// The ratio of the shape's bounding box to the label size.
    /// Shapes like triangles need more space than rectangles.
    pub fn shape_to_label_ratio(&self) -> f64 {
        match self {
            Self::Rectangle => 1.0,
            Self::RoundedRectangle => 1.0,
            Self::Ellipse => 1.2,
            Self::Triangle => 2.5,
            Self::Diamond => 1.8,
            Self::Star => 2.0,
            Self::Hexagon => 1.4,
            Self::Pentagon => 1.4,
            Self::Octagon => 1.3,
        }
    }

    /// Maximum width-to-height ratio to keep shapes from becoming too thin.
    pub fn max_width_to_height_ratio(&self) -> u32 {
        match self {
            Self::Rectangle => 4,
            Self::RoundedRectangle => 4,
            Self::Ellipse => 4,
            Self::Triangle => 3,
            Self::Diamond => 3,
            Self::Star => 2,
            Self::Hexagon => 3,
            Self::Pentagon => 3,
            Self::Octagon => 3,
        }
    }

    /// Vertical label position inside the shape (0.0 = top, 0.5 = center, 1.0 = bottom).
    pub fn label_position(&self) -> f64 {
        match self {
            Self::Rectangle => 0.5,
            Self::RoundedRectangle => 0.5,
            Self::Ellipse => 0.5,
            Self::Triangle => 0.7,
            Self::Diamond => 0.5,
            Self::Star => 0.5,
            Self::Hexagon => 0.5,
            Self::Pentagon => 0.5,
            Self::Octagon => 0.5,
        }
    }
}

impl Default for VertexShape {
    fn default() -> Self {
        Self::RoundedRectangle
    }
}

// ---------------------------------------------------------------------------
// Colors
// ---------------------------------------------------------------------------

/// An RGBA color.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    /// Create a new color.
    pub const fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Create an opaque color.
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// Convert to a hex color string (#RRGGBB).
    pub fn to_hex(&self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.r, self.g, self.b)
    }
}

/// Well-known Ghidra theme colors.
impl Color {
    pub const BLACK: Self = Self::rgb(0, 0, 0);
    pub const WHITE: Self = Self::rgb(255, 255, 255);
    pub const LIGHT_GRAY: Self = Self::rgb(192, 192, 192);
    pub const DARK_GRAY: Self = Self::rgb(64, 64, 64);
    pub const RED: Self = Self::rgb(200, 0, 0);
    pub const GREEN: Self = Self::rgb(0, 160, 0);
    pub const BLUE: Self = Self::rgb(0, 0, 200);
    pub const YELLOW: Self = Self::rgb(255, 255, 0);
    pub const ORANGE: Self = Self::rgb(255, 165, 0);
    pub const PURPLE: Self = Self::rgb(128, 0, 128);
}

// ---------------------------------------------------------------------------
// Graph label position
// ---------------------------------------------------------------------------

/// Position of the label relative to the vertex shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GraphLabelPosition {
    Auto,
    Center,
    North,
    South,
    East,
    West,
    Northeast,
    Northwest,
    Southeast,
    Southwest,
}

impl Default for GraphLabelPosition {
    fn default() -> Self {
        Self::Center
    }
}

// ---------------------------------------------------------------------------
// Edge rendering style
// ---------------------------------------------------------------------------

/// Visual style for drawing an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeStyle {
    Solid,
    Dashed,
    Dotted,
    Bold,
}

impl Default for EdgeStyle {
    fn default() -> Self {
        Self::Solid
    }
}

// ---------------------------------------------------------------------------
// GraphDisplayOptions
// ---------------------------------------------------------------------------

/// Configuration for how vertices and edges are rendered.
///
/// Maps to Ghidra's `GraphDisplayOptions` class.
///
/// Each edge type and vertex type can have its own color, shape,
/// and priority. Default options are provided for common graph types.
#[derive(Debug, Clone)]
pub struct GraphDisplayOptions {
    /// Graph type name (e.g. "Control Flow Graph", "Function Call Graph").
    graph_type: String,
    /// Default vertex shape.
    default_vertex_shape: VertexShape,
    /// Default vertex color.
    default_vertex_color: Color,
    /// Default edge color.
    default_edge_color: Color,
    /// Default vertex label color.
    default_label_color: Color,
    /// Default edge selection color.
    edge_selection_color: Color,
    /// Default vertex selection color.
    vertex_selection_color: Color,
    /// Arrow length in pixels.
    arrow_length: u32,
    /// Whether to use icon rendering mode.
    use_icons: bool,
    /// Font size for labels.
    font_size: u32,
    /// Font family for labels.
    font_family: String,
    /// Label position relative to vertex.
    label_position: GraphLabelPosition,
    /// Favored edge type for layout algorithms.
    favored_edge_type: Option<String>,
    /// Per-vertex-type shape overrides.
    vertex_shapes: HashMap<String, VertexShape>,
    /// Per-vertex-type color overrides.
    vertex_colors: HashMap<String, Color>,
    /// Per-edge-type color overrides.
    edge_colors: HashMap<String, Color>,
    /// Per-edge-type style overrides.
    edge_styles: HashMap<String, EdgeStyle>,
    /// Per-edge-type priority (lower number = higher priority).
    edge_priorities: HashMap<String, i32>,
    /// Per-vertex-type label text overrides.
    vertex_labels: HashMap<String, String>,
}

impl GraphDisplayOptions {
    /// Create a new display options with the given graph type name.
    pub fn new(graph_type: impl Into<String>) -> Self {
        Self {
            graph_type: graph_type.into(),
            default_vertex_shape: VertexShape::RoundedRectangle,
            default_vertex_color: Color::rgb(227, 242, 253), // light blue #e3f2fd
            default_edge_color: Color::rgb(130, 130, 130),
            default_label_color: Color::rgb(33, 33, 33),
            edge_selection_color: Color::rgb(255, 0, 0),
            vertex_selection_color: Color::rgb(255, 0, 0),
            arrow_length: 10,
            use_icons: false,
            font_size: 11,
            font_family: "monospace".to_string(),
            label_position: GraphLabelPosition::Center,
            favored_edge_type: None,
            vertex_shapes: HashMap::new(),
            vertex_colors: HashMap::new(),
            edge_colors: HashMap::new(),
            edge_styles: HashMap::new(),
            edge_priorities: HashMap::new(),
            vertex_labels: HashMap::new(),
        }
    }

    /// Get the graph type name.
    pub fn graph_type(&self) -> &str {
        &self.graph_type
    }

    // -- Vertex display --

    /// Get the shape for a vertex, considering its vertex type.
    pub fn get_vertex_shape(&self, vertex: &AttributedVertex) -> VertexShape {
        let vtype = vertex
            .get("VertexType")
            .or_else(|| vertex.get("node_type"))
            .unwrap_or("default");
        self.vertex_shapes
            .get(vtype)
            .copied()
            .unwrap_or(self.default_vertex_shape)
    }

    /// Get the color for a vertex, considering its vertex type.
    pub fn get_vertex_color(&self, vertex: &AttributedVertex) -> Color {
        let vtype = vertex
            .get("VertexType")
            .or_else(|| vertex.get("node_type"))
            .unwrap_or("default");
        self.vertex_colors
            .get(vtype)
            .copied()
            .unwrap_or(self.default_vertex_color)
    }

    /// Get the display label for a vertex.
    pub fn get_vertex_label(&self, vertex: &AttributedVertex) -> String {
        let vtype = vertex
            .get("VertexType")
            .or_else(|| vertex.get("node_type"))
            .unwrap_or("default");
        self.vertex_labels
            .get(vtype)
            .cloned()
            .unwrap_or_else(|| {
                let name = vertex.name();
                if name.is_empty() {
                    vertex.id().to_string()
                } else {
                    name.to_string()
                }
            })
    }

    /// Get the selection color for vertices.
    pub fn get_vertex_selection_color(&self) -> Color {
        self.vertex_selection_color
    }

    // -- Edge display --

    /// Get the color for an edge, considering its edge type.
    pub fn get_edge_color(&self, edge: &AttributedEdge) -> Color {
        let etype = edge.edge_type().unwrap_or("default");
        self.edge_colors
            .get(etype)
            .copied()
            .unwrap_or(self.default_edge_color)
    }

    /// Get the display style for an edge.
    pub fn get_edge_style(&self, edge: &AttributedEdge) -> EdgeStyle {
        let etype = edge.edge_type().unwrap_or("default");
        self.edge_styles.get(etype).copied().unwrap_or_default()
    }

    /// Get the priority for an edge type (lower = higher priority).
    pub fn get_edge_priority(&self, edge_type: &str) -> i32 {
        self.edge_priorities
            .get(edge_type)
            .copied()
            .unwrap_or(i32::MAX)
    }

    /// Get the selection color for edges.
    pub fn get_edge_selection_color(&self) -> Color {
        self.edge_selection_color
    }

    /// Get the favored edge type for layout.
    pub fn get_favored_edge_type(&self) -> Option<&str> {
        self.favored_edge_type.as_deref()
    }

    // -- General --

    /// Whether this display uses icon rendering mode.
    pub fn uses_icons(&self) -> bool {
        self.use_icons
    }

    /// Arrow length in pixels.
    pub fn get_arrow_length(&self) -> u32 {
        self.arrow_length
    }

    /// Font size.
    pub fn get_font_size(&self) -> u32 {
        self.font_size
    }

    /// Font family.
    pub fn get_font_family(&self) -> &str {
        &self.font_family
    }

    /// Label position.
    pub fn get_label_position(&self) -> GraphLabelPosition {
        self.label_position
    }

    // -- Builders for setting overrides --

    /// Set the shape for a specific vertex type.
    pub fn set_vertex_shape(&mut self, vertex_type: &str, shape: VertexShape) {
        self.vertex_shapes.insert(vertex_type.to_string(), shape);
    }

    /// Set the color for a specific vertex type.
    pub fn set_vertex_color(&mut self, vertex_type: &str, color: Color) {
        self.vertex_colors.insert(vertex_type.to_string(), color);
    }

    /// Set the color for a specific edge type.
    pub fn set_edge_color(&mut self, edge_type: &str, color: Color) {
        self.edge_colors.insert(edge_type.to_string(), color);
    }

    /// Set the style for a specific edge type.
    pub fn set_edge_style(&mut self, edge_type: &str, style: EdgeStyle) {
        self.edge_styles.insert(edge_type.to_string(), style);
    }

    /// Set the priority for a specific edge type.
    pub fn set_edge_priority(&mut self, edge_type: &str, priority: i32) {
        self.edge_priorities
            .insert(edge_type.to_string(), priority);
    }

    /// Set the label override for a specific vertex type.
    pub fn set_vertex_label(&mut self, vertex_type: &str, label: &str) {
        self.vertex_labels
            .insert(vertex_type.to_string(), label.to_string());
    }

    /// Set the favored edge type.
    pub fn set_favored_edge_type(&mut self, edge_type: &str) {
        self.favored_edge_type = Some(edge_type.to_string());
    }

    /// Set the default vertex shape.
    pub fn set_default_vertex_shape(&mut self, shape: VertexShape) {
        self.default_vertex_shape = shape;
    }

    /// Set the arrow length.
    pub fn set_arrow_length(&mut self, length: u32) {
        self.arrow_length = length;
    }

    /// Set whether to use icons.
    pub fn set_use_icons(&mut self, use_icons: bool) {
        self.use_icons = use_icons;
    }

    /// Set the label position.
    pub fn set_label_position(&mut self, position: GraphLabelPosition) {
        self.label_position = position;
    }
}

impl Default for GraphDisplayOptions {
    fn default() -> Self {
        Self::new("generic")
    }
}

// ---------------------------------------------------------------------------
// Default CFG display options
// ---------------------------------------------------------------------------

/// Create display options pre-configured for a Control Flow Graph.
///
/// Sets colors and styles for standard CFG edge types: fallthrough,
/// conditional branch, unconditional branch, call, return, etc.
pub fn cfg_display_options() -> GraphDisplayOptions {
    let mut opts = GraphDisplayOptions::new("Control Flow Graph");

    // Vertex types
    opts.set_vertex_shape("Entry", VertexShape::RoundedRectangle);
    opts.set_vertex_color("Entry", Color::rgb(200, 230, 201)); // light green
    opts.set_vertex_shape("Exit", VertexShape::RoundedRectangle);
    opts.set_vertex_color("Exit", Color::rgb(255, 205, 210)); // light red
    opts.set_vertex_shape("Call", VertexShape::Rectangle);

    // Edge types with Ghidra-standard colors
    opts.set_edge_color("fallthrough", Color::rgb(46, 125, 50)); // green
    opts.set_edge_color("conditional_branch", Color::rgb(21, 101, 192)); // blue
    opts.set_edge_color("unconditional_branch", Color::rgb(21, 101, 192)); // blue
    opts.set_edge_color("call", Color::rgb(106, 27, 154)); // purple
    opts.set_edge_color("return", Color::rgb(78, 52, 46)); // brown
    opts.set_edge_color("indirect", Color::rgb(245, 127, 23)); // orange

    opts.set_edge_style("conditional_branch", EdgeStyle::Dashed);
    opts.set_edge_style("return", EdgeStyle::Dashed);

    // Edge priorities
    opts.set_edge_priority("fallthrough", 0);
    opts.set_edge_priority("conditional_branch", 1);
    opts.set_edge_priority("unconditional_branch", 2);
    opts.set_edge_priority("call", 3);
    opts.set_edge_priority("return", 4);
    opts.set_edge_priority("indirect", 5);

    opts.set_favored_edge_type("fallthrough");

    opts
}

/// Create display options pre-configured for a Function Call Graph.
pub fn fcall_display_options() -> GraphDisplayOptions {
    let mut opts = GraphDisplayOptions::new("Function Call Graph");

    opts.set_edge_color("call", Color::rgb(21, 101, 192));
    opts.set_edge_priority("call", 0);
    opts.set_favored_edge_type("call");

    opts
}

/// Create display options pre-configured for a Tree graph.
pub fn tree_display_options() -> GraphDisplayOptions {
    let mut opts = GraphDisplayOptions::new("Tree");

    opts.set_default_vertex_shape(VertexShape::Ellipse);
    opts.set_edge_color("parent", Color::rgb(46, 125, 50));
    opts.set_edge_priority("parent", 0);
    opts.set_favored_edge_type("parent");

    opts
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphservices::attributed::{AttributedEdge, AttributedVertex};

    #[test]
    fn test_default_options() {
        let opts = GraphDisplayOptions::default();
        assert_eq!(opts.graph_type(), "generic");
        assert_eq!(opts.get_font_size(), 11);
        assert_eq!(opts.get_arrow_length(), 10);
    }

    #[test]
    fn test_cfg_options() {
        let opts = cfg_display_options();
        assert_eq!(opts.graph_type(), "Control Flow Graph");
        assert_eq!(opts.get_favored_edge_type(), Some("fallthrough"));
        assert_eq!(opts.get_edge_priority("fallthrough"), 0);
        assert_eq!(opts.get_edge_priority("call"), 3);
    }

    #[test]
    fn test_vertex_shape_for_type() {
        let mut opts = GraphDisplayOptions::new("test");
        opts.set_vertex_shape("Entry", VertexShape::Diamond);

        let mut v = AttributedVertex::new("v1", "entry");
        v.set("VertexType", "Entry");
        assert_eq!(opts.get_vertex_shape(&v), VertexShape::Diamond);

        // Default fallback
        let v2 = AttributedVertex::new("v2", "other");
        assert_eq!(
            opts.get_vertex_shape(&v2),
            VertexShape::RoundedRectangle
        );
    }

    #[test]
    fn test_vertex_color_for_type() {
        let opts = cfg_display_options();
        let mut v = AttributedVertex::new("v1", "entry");
        v.set("VertexType", "Entry");
        let color = opts.get_vertex_color(&v);
        assert_eq!(color.r, 200);
        assert_eq!(color.g, 230);
        assert_eq!(color.b, 201);
    }

    #[test]
    fn test_edge_color_for_type() {
        let opts = cfg_display_options();
        let edge = AttributedEdge::new("e1", "A", "B", Some("fallthrough".to_string()));
        let color = opts.get_edge_color(&edge);
        assert_eq!(color, Color::rgb(46, 125, 50));
    }

    #[test]
    fn test_edge_priority_ordering() {
        let opts = cfg_display_options();
        assert!(opts.get_edge_priority("fallthrough") < opts.get_edge_priority("call"));
        assert!(opts.get_edge_priority("call") < opts.get_edge_priority("return"));
    }

    #[test]
    fn test_vertex_shape_properties() {
        let s = VertexShape::Triangle;
        assert!(s.shape_to_label_ratio() > 1.0);
        assert_eq!(s.max_width_to_height_ratio(), 3);
        assert!(s.label_position() > 0.5);
    }

    #[test]
    fn test_color_to_hex() {
        let c = Color::rgb(255, 128, 0);
        assert_eq!(c.to_hex(), "#ff8000");
    }

    #[test]
    fn test_fcall_options() {
        let opts = fcall_display_options();
        assert_eq!(opts.get_favored_edge_type(), Some("call"));
    }

    #[test]
    fn test_tree_options() {
        let opts = tree_display_options();
        assert_eq!(opts.get_favored_edge_type(), Some("parent"));
    }

    #[test]
    fn test_set_vertex_label() {
        let mut opts = GraphDisplayOptions::new("test");
        opts.set_vertex_label("Entry", "ENTRY NODE");
        let mut v = AttributedVertex::new("v1", "original");
        v.set("VertexType", "Entry");
        assert_eq!(opts.get_vertex_label(&v), "ENTRY NODE");
    }

    #[test]
    fn test_edge_style_defaults() {
        let opts = cfg_display_options();
        let e = AttributedEdge::new("e", "A", "B", Some("fallthrough".to_string()));
        assert_eq!(opts.get_edge_style(&e), EdgeStyle::Solid);

        let e2 = AttributedEdge::new("e2", "A", "B", Some("conditional_branch".to_string()));
        assert_eq!(opts.get_edge_style(&e2), EdgeStyle::Dashed);
    }

    #[test]
    fn test_use_icons_toggle() {
        let mut opts = GraphDisplayOptions::default();
        assert!(!opts.uses_icons());
        opts.set_use_icons(true);
        assert!(opts.uses_icons());
    }
}
