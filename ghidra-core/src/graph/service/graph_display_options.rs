//! Port of `ghidra.service.graph.GraphDisplayOptions`.
//!
//! Configuration for how a graph is rendered (colors, shapes, fonts).

use super::graph_type::GraphType;
use super::graph_label_position::GraphLabelPosition;
use super::vertex_shape::VertexShape;

/// Color representation (RGB + optional alpha).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct GraphColor {
    /// Red component (0-255).
    pub r: u8,
    /// Green component (0-255).
    pub g: u8,
    /// Blue component (0-255).
    pub b: u8,
    /// Alpha component (0-255, 255 = opaque).
    pub a: u8,
}

impl GraphColor {
    /// Create a new color.
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// Create a color with alpha.
    pub const fn with_alpha(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// White color constant.
    pub const WHITE: Self = Self::new(255, 255, 255);
    /// Black color constant.
    pub const BLACK: Self = Self::new(0, 0, 0);
    /// Red color constant.
    pub const RED: Self = Self::new(255, 0, 0);
    /// Green color constant.
    pub const GREEN: Self = Self::new(0, 255, 0);
    /// Blue color constant.
    pub const BLUE: Self = Self::new(0, 0, 255);
    /// Yellow color constant.
    pub const YELLOW: Self = Self::new(255, 255, 0);
    /// Gray color constant.
    pub const GRAY: Self = Self::new(128, 128, 128);
    /// Light gray color constant.
    pub const LIGHT_GRAY: Self = Self::new(192, 192, 192);
    /// Dark gray color constant.
    pub const DARK_GRAY: Self = Self::new(64, 64, 64);

    /// Parse a hex color string (e.g., "#FF0000" or "FF0000" or "#RRGGBBAA").
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim().strip_prefix('#').unwrap_or(s);
        match s.len() {
            6 => {
                let r = u8::from_str_radix(&s[0..2], 16).ok()?;
                let g = u8::from_str_radix(&s[2..4], 16).ok()?;
                let b = u8::from_str_radix(&s[4..6], 16).ok()?;
                Some(Self::new(r, g, b))
            }
            8 => {
                let r = u8::from_str_radix(&s[0..2], 16).ok()?;
                let g = u8::from_str_radix(&s[2..4], 16).ok()?;
                let b = u8::from_str_radix(&s[4..6], 16).ok()?;
                let a = u8::from_str_radix(&s[6..8], 16).ok()?;
                Some(Self::with_alpha(r, g, b, a))
            }
            _ => None,
        }
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        if self.a == 255 {
            format!("#{:02X}{:02X}{:02X}", self.r, self.g, self.b)
        } else {
            format!("#{:02X}{:02X}{:02X}{:02X}", self.r, self.g, self.b, self.a)
        }
    }
}

impl std::fmt::Display for GraphColor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Configuration for how graph vertices and edges are displayed.
///
/// Mirrors `ghidra.service.graph.GraphDisplayOptions`.
#[derive(Debug, Clone)]
pub struct GraphDisplayOptions {
    /// The graph type these options apply to.
    graph_type: GraphType,
    /// Default vertex shape.
    default_vertex_shape: VertexShape,
    /// Default vertex color.
    vertex_color: GraphColor,
    /// Default vertex border color.
    vertex_border_color: GraphColor,
    /// Default edge color.
    edge_color: GraphColor,
    /// Default label position.
    label_position: GraphLabelPosition,
    /// Default font size.
    font_size: u32,
    /// Vertex selection color.
    vertex_selection_color: GraphColor,
    /// Edge selection color.
    edge_selection_color: GraphColor,
    /// Maximum node count before warning.
    max_node_count: usize,
    /// Whether to use animation on layout changes.
    animate_layout: bool,
}

impl GraphDisplayOptions {
    /// Create default display options for the given graph type.
    pub fn new(graph_type: GraphType) -> Self {
        Self {
            graph_type,
            default_vertex_shape: VertexShape::default(),
            vertex_color: GraphColor::new(220, 220, 255),
            vertex_border_color: GraphColor::new(100, 100, 150),
            edge_color: GraphColor::new(128, 128, 128),
            label_position: GraphLabelPosition::default(),
            font_size: 12,
            vertex_selection_color: GraphColor::new(100, 150, 255),
            edge_selection_color: GraphColor::new(255, 100, 100),
            max_node_count: 5000,
            animate_layout: true,
        }
    }

    /// Get the graph type.
    pub fn graph_type(&self) -> &GraphType {
        &self.graph_type
    }

    /// Get the default vertex shape.
    pub fn vertex_shape(&self) -> VertexShape {
        self.default_vertex_shape
    }

    /// Set the default vertex shape.
    pub fn set_vertex_shape(&mut self, shape: VertexShape) {
        self.default_vertex_shape = shape;
    }

    /// Get the vertex color.
    pub fn vertex_color(&self) -> GraphColor {
        self.vertex_color
    }

    /// Set the vertex color.
    pub fn set_vertex_color(&mut self, color: GraphColor) {
        self.vertex_color = color;
    }

    /// Get the vertex border color.
    pub fn vertex_border_color(&self) -> GraphColor {
        self.vertex_border_color
    }

    /// Set the vertex border color.
    pub fn set_vertex_border_color(&mut self, color: GraphColor) {
        self.vertex_border_color = color;
    }

    /// Get the edge color.
    pub fn edge_color(&self) -> GraphColor {
        self.edge_color
    }

    /// Set the edge color.
    pub fn set_edge_color(&mut self, color: GraphColor) {
        self.edge_color = color;
    }

    /// Get the label position.
    pub fn label_position(&self) -> GraphLabelPosition {
        self.label_position
    }

    /// Set the label position.
    pub fn set_label_position(&mut self, pos: GraphLabelPosition) {
        self.label_position = pos;
    }

    /// Get the font size.
    pub fn font_size(&self) -> u32 {
        self.font_size
    }

    /// Set the font size.
    pub fn set_font_size(&mut self, size: u32) {
        self.font_size = size;
    }

    /// Get the vertex selection color.
    pub fn vertex_selection_color(&self) -> GraphColor {
        self.vertex_selection_color
    }

    /// Get the edge selection color.
    pub fn edge_selection_color(&self) -> GraphColor {
        self.edge_selection_color
    }

    /// Get the max node count.
    pub fn max_node_count(&self) -> usize {
        self.max_node_count
    }

    /// Set the max node count.
    pub fn set_max_node_count(&mut self, count: usize) {
        self.max_node_count = count;
    }

    /// Whether to animate layout changes.
    pub fn animate_layout(&self) -> bool {
        self.animate_layout
    }

    /// Set whether to animate layout changes.
    pub fn set_animate_layout(&mut self, animate: bool) {
        self.animate_layout = animate;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_color_hex() {
        let c = GraphColor::new(255, 0, 0);
        assert_eq!(c.to_hex(), "#FF0000");

        let parsed = GraphColor::from_hex("#FF0000").unwrap();
        assert_eq!(parsed, c);

        let parsed2 = GraphColor::from_hex("00FF00").unwrap();
        assert_eq!(parsed2, GraphColor::GREEN);
    }

    #[test]
    fn test_graph_color_alpha() {
        let c = GraphColor::with_alpha(255, 0, 0, 128);
        assert_eq!(c.to_hex(), "#FF000080");

        let parsed = GraphColor::from_hex("#FF000080").unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn test_graph_color_display() {
        assert_eq!(GraphColor::RED.to_string(), "#FF0000");
    }

    #[test]
    fn test_display_options_defaults() {
        let gt = GraphType::new("cfg", "CFG");
        let opts = GraphDisplayOptions::new(gt);
        assert_eq!(opts.vertex_shape(), VertexShape::Box);
        assert_eq!(opts.label_position(), GraphLabelPosition::Center);
        assert_eq!(opts.font_size(), 12);
        assert!(opts.animate_layout());
    }

    #[test]
    fn test_display_options_setters() {
        let gt = GraphType::new("cfg", "CFG");
        let mut opts = GraphDisplayOptions::new(gt);
        opts.set_vertex_shape(VertexShape::Ellipse);
        opts.set_label_position(GraphLabelPosition::Top);
        opts.set_font_size(14);

        assert_eq!(opts.vertex_shape(), VertexShape::Ellipse);
        assert_eq!(opts.label_position(), GraphLabelPosition::Top);
        assert_eq!(opts.font_size(), 14);
    }
}
