//! Basic edge label renderer.
//!
//! Ports `ghidra.graph.viewer.edge.BasicEdgeLabelRenderer`.
//!
//! A custom edge label renderer that overrides the default label placement
//! to position edge labels at the midpoint of the edge path.

use super::super::{Point2D, VisualEdge};

/// Edge label position relative to the edge path.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EdgeLabelPosition {
    /// Place the label at the midpoint of the edge.
    Midpoint,
    /// Place the label at the source vertex.
    Source,
    /// Place the label at the target vertex.
    Target,
    /// Place the label at a specific fraction along the edge (0.0 = source, 1.0 = target).
    Fraction(f64),
}

impl Default for EdgeLabelPosition {
    fn default() -> Self {
        Self::Midpoint
    }
}

/// A rendered edge label with its position.
#[derive(Debug, Clone)]
pub struct EdgeLabelRender {
    /// The label text.
    pub text: String,
    /// The position where the label should be drawn.
    pub position: Point2D,
    /// Font size for the label.
    pub font_size: f32,
    /// Text color (CSS hex).
    pub color: String,
}

/// Edge label renderer that computes label positions for visual edges.
///
/// Ports `ghidra.graph.viewer.edge.BasicEdgeLabelRenderer`.
/// This is not a pixel renderer in the traditional sense; rather, it
/// computes the position and content of edge labels given the edge
/// and its layout positions.
#[derive(Debug, Clone)]
pub struct BasicEdgeLabelRenderer {
    /// Default label position.
    pub position: EdgeLabelPosition,
    /// Default font size.
    pub font_size: f32,
    /// Default text color.
    pub color: String,
    /// Vertical offset from the edge path (to avoid overlap).
    pub y_offset: f64,
}

impl BasicEdgeLabelRenderer {
    /// Create a new edge label renderer with default settings.
    pub fn new() -> Self {
        Self {
            position: EdgeLabelPosition::Midpoint,
            font_size: 10.0,
            color: "#555555".to_string(),
            y_offset: -8.0,
        }
    }

    /// Render a label for an edge given its path points.
    pub fn render_label(
        &self,
        edge: &VisualEdge,
        path_points: &[Point2D],
    ) -> Option<EdgeLabelRender> {
        let text = edge.label.as_ref()?;
        if text.is_empty() || path_points.len() < 2 {
            return None;
        }

        let position = match self.position {
            EdgeLabelPosition::Midpoint => {
                let mid = path_points.len() / 2;
                if path_points.len() % 2 == 0 && mid > 0 {
                    path_points[mid - 1].lerp(&path_points[mid], 0.5)
                } else {
                    path_points[mid]
                }
            }
            EdgeLabelPosition::Source => path_points[0],
            EdgeLabelPosition::Target => *path_points.last().unwrap(),
            EdgeLabelPosition::Fraction(f) => {
                let idx = (f * (path_points.len() - 1) as f64) as usize;
                let idx = idx.min(path_points.len() - 1);
                path_points[idx]
            }
        };

        Some(EdgeLabelRender {
            text: text.clone(),
            position: Point2D::new(position.x, position.y + self.y_offset),
            font_size: self.font_size,
            color: self.color.clone(),
        })
    }
}

impl Default for BasicEdgeLabelRenderer {
    fn default() -> Self {
        Self::new()
    }
}

/// Visual graph edge satellite renderer.
///
/// Ports `ghidra.graph.viewer.edge.VisualGraphEdgeSatelliteRenderer`.
/// Renders edges in the satellite (overview) view with simplified rendering.
#[derive(Debug, Clone, Default)]
pub struct VisualGraphEdgeSatelliteRenderer {
    /// Edge color in the satellite view.
    pub edge_color: String,
    /// Edge stroke width.
    pub stroke_width: f32,
}

impl VisualGraphEdgeSatelliteRenderer {
    /// Create a new satellite edge renderer.
    pub fn new() -> Self {
        Self {
            edge_color: "#AAAAAA".to_string(),
            stroke_width: 0.5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::viewer::VisualEdge;

    #[test]
    fn basic_edge_label_renderer_new() {
        let renderer = BasicEdgeLabelRenderer::new();
        assert_eq!(renderer.position, EdgeLabelPosition::Midpoint);
        assert_eq!(renderer.font_size, 10.0);
    }

    #[test]
    fn render_label_at_midpoint() {
        let renderer = BasicEdgeLabelRenderer::new();
        let edge = VisualEdge::with_label("e1", "a", "b", "call");
        let points = vec![
            Point2D::new(0.0, 0.0),
            Point2D::new(100.0, 100.0),
        ];
        let label = renderer.render_label(&edge, &points);
        assert!(label.is_some());
        let label = label.unwrap();
        assert_eq!(label.text, "call");
        assert!((label.position.x - 50.0).abs() < 1.0);
    }

    #[test]
    fn render_label_no_label() {
        let renderer = BasicEdgeLabelRenderer::new();
        let edge = VisualEdge::new("e1", "a", "b");
        let points = vec![Point2D::new(0.0, 0.0), Point2D::new(100.0, 0.0)];
        let label = renderer.render_label(&edge, &points);
        assert!(label.is_none());
    }

    #[test]
    fn render_label_single_point() {
        let renderer = BasicEdgeLabelRenderer::new();
        let edge = VisualEdge::with_label("e1", "a", "b", "label");
        let points = vec![Point2D::new(50.0, 50.0)];
        let label = renderer.render_label(&edge, &points);
        assert!(label.is_none());
    }

    #[test]
    fn label_position_source() {
        let mut renderer = BasicEdgeLabelRenderer::new();
        renderer.position = EdgeLabelPosition::Source;
        let edge = VisualEdge::with_label("e1", "a", "b", "src");
        let points = vec![Point2D::new(0.0, 0.0), Point2D::new(200.0, 0.0)];
        let label = renderer.render_label(&edge, &points).unwrap();
        assert!((label.position.x - 0.0).abs() < 1.0);
    }

    #[test]
    fn label_position_target() {
        let mut renderer = BasicEdgeLabelRenderer::new();
        renderer.position = EdgeLabelPosition::Target;
        let edge = VisualEdge::with_label("e1", "a", "b", "tgt");
        let points = vec![Point2D::new(0.0, 0.0), Point2D::new(200.0, 0.0)];
        let label = renderer.render_label(&edge, &points).unwrap();
        assert!((label.position.x - 200.0).abs() < 1.0);
    }

    #[test]
    fn satellite_renderer_new() {
        let renderer = VisualGraphEdgeSatelliteRenderer::new();
        assert_eq!(renderer.stroke_width, 0.5);
    }
}
