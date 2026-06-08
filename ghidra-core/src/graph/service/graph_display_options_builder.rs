//! Port of `ghidra.service.graph.GraphDisplayOptionsBuilder`.
//!
//! Builder for constructing [`GraphDisplayOptions`] instances.

use super::graph_type::GraphType;
use super::graph_display_options::{GraphColor, GraphDisplayOptions};
use super::graph_label_position::GraphLabelPosition;
use super::vertex_shape::VertexShape;

/// Builder for constructing [`GraphDisplayOptions`].
///
/// Mirrors `ghidra.service.graph.GraphDisplayOptionsBuilder`.
#[derive(Debug)]
pub struct GraphDisplayOptionsBuilder {
    graph_type: GraphType,
    vertex_shape: VertexShape,
    vertex_color: GraphColor,
    vertex_border_color: GraphColor,
    edge_color: GraphColor,
    label_position: GraphLabelPosition,
    font_size: u32,
    _vertex_selection_color: GraphColor,
    _edge_selection_color: GraphColor,
    max_node_count: usize,
    animate_layout: bool,
}

impl GraphDisplayOptionsBuilder {
    /// Create a new builder for the given graph type.
    pub fn new(graph_type: GraphType) -> Self {
        Self {
            graph_type,
            vertex_shape: VertexShape::default(),
            vertex_color: GraphColor::new(220, 220, 255),
            vertex_border_color: GraphColor::new(100, 100, 150),
            edge_color: GraphColor::new(128, 128, 128),
            label_position: GraphLabelPosition::default(),
            font_size: 12,
            _vertex_selection_color: GraphColor::new(100, 150, 255),
            _edge_selection_color: GraphColor::new(255, 100, 100),
            max_node_count: 5000,
            animate_layout: true,
        }
    }

    /// Set the default vertex shape.
    pub fn vertex_shape(mut self, shape: VertexShape) -> Self {
        self.vertex_shape = shape;
        self
    }

    /// Set the vertex color.
    pub fn vertex_color(mut self, color: GraphColor) -> Self {
        self.vertex_color = color;
        self
    }

    /// Set the vertex border color.
    pub fn vertex_border_color(mut self, color: GraphColor) -> Self {
        self.vertex_border_color = color;
        self
    }

    /// Set the edge color.
    pub fn edge_color(mut self, color: GraphColor) -> Self {
        self.edge_color = color;
        self
    }

    /// Set the label position.
    pub fn label_position(mut self, pos: GraphLabelPosition) -> Self {
        self.label_position = pos;
        self
    }

    /// Set the font size.
    pub fn font_size(mut self, size: u32) -> Self {
        self.font_size = size;
        self
    }

    /// Set the max node count.
    pub fn max_node_count(mut self, count: usize) -> Self {
        self.max_node_count = count;
        self
    }

    /// Enable or disable layout animation.
    pub fn animate_layout(mut self, animate: bool) -> Self {
        self.animate_layout = animate;
        self
    }

    /// Build the [`GraphDisplayOptions`].
    pub fn build(self) -> GraphDisplayOptions {
        let mut opts = GraphDisplayOptions::new(self.graph_type);
        opts.set_vertex_shape(self.vertex_shape);
        opts.set_vertex_color(self.vertex_color);
        opts.set_vertex_border_color(self.vertex_border_color);
        opts.set_edge_color(self.edge_color);
        opts.set_label_position(self.label_position);
        opts.set_font_size(self.font_size);
        opts.set_max_node_count(self.max_node_count);
        opts.set_animate_layout(self.animate_layout);
        opts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let gt = GraphType::new("test", "Test");
        let opts = GraphDisplayOptionsBuilder::new(gt).build();
        assert_eq!(opts.vertex_shape(), VertexShape::Box);
        assert_eq!(opts.font_size(), 12);
    }

    #[test]
    fn test_builder_custom() {
        let gt = GraphType::new("test", "Test");
        let opts = GraphDisplayOptionsBuilder::new(gt)
            .vertex_shape(VertexShape::Ellipse)
            .font_size(16)
            .label_position(GraphLabelPosition::Top)
            .max_node_count(1000)
            .build();
        assert_eq!(opts.vertex_shape(), VertexShape::Ellipse);
        assert_eq!(opts.font_size(), 16);
        assert_eq!(opts.label_position(), GraphLabelPosition::Top);
        assert_eq!(opts.max_node_count(), 1000);
    }
}
