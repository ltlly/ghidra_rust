//! Edge label rendering.
//!
//! Ports `ghidra.graph.viewer.renderer.VisualGraphEdgeLabelRenderer`.

use crate::graph::viewer::Point2D;

/// Position of an edge label relative to the edge midpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeLabelPosition {
    /// Above the edge.
    Above,
    /// Below the edge.
    Below,
    /// Centered on the edge.
    Center,
}

impl Default for EdgeLabelPosition {
    fn default() -> Self {
        Self::Above
    }
}

/// Renders text labels on graph edges.
#[derive(Debug, Clone)]
pub struct VisualGraphEdgeLabelRenderer {
    /// Font size for edge labels.
    pub font_size: f32,
    /// Label color (CSS hex).
    pub color: String,
    /// Background color behind label text.
    pub background_color: Option<String>,
    /// Padding around label text.
    pub padding: f32,
    /// Label position relative to edge.
    pub position: EdgeLabelPosition,
}

impl VisualGraphEdgeLabelRenderer {
    /// Create a new edge label renderer.
    pub fn new() -> Self {
        Self {
            font_size: 10.0,
            color: "#666666".to_string(),
            background_color: Some("#FFFFFFEE".to_string()),
            padding: 2.0,
            position: EdgeLabelPosition::default(),
        }
    }

    /// Compute the position for an edge label.
    pub fn compute_label_position(
        &self,
        edge_midpoint: Point2D,
        label_offset: f64,
    ) -> Point2D {
        let offset_y = match self.position {
            EdgeLabelPosition::Above => -label_offset,
            EdgeLabelPosition::Below => label_offset,
            EdgeLabelPosition::Center => 0.0,
        };
        Point2D::new(edge_midpoint.x, edge_midpoint.y + offset_y)
    }
}

impl Default for VisualGraphEdgeLabelRenderer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_position_above() {
        let renderer = VisualGraphEdgeLabelRenderer::new();
        let pos = renderer.compute_label_position(Point2D::new(50.0, 50.0), 10.0);
        assert_eq!(pos.y, 40.0);
    }

    #[test]
    fn test_label_position_below() {
        let mut renderer = VisualGraphEdgeLabelRenderer::new();
        renderer.position = EdgeLabelPosition::Below;
        let pos = renderer.compute_label_position(Point2D::new(50.0, 50.0), 10.0);
        assert_eq!(pos.y, 60.0);
    }
}
