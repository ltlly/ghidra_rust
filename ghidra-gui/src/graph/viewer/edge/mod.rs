//! Visual edge rendering and routing.
//!
//! Ports `ghidra.graph.viewer.edge` package.

pub mod routing;

use crate::graph::viewer::{Point2D, VisualEdge, VisualVertex};

/// Calculates arrow positions for directed edges.
#[derive(Debug, Clone, Default)]
pub struct EdgeArrowRenderer {
    /// Arrow size in pixels.
    pub arrow_size: f64,
}

impl EdgeArrowRenderer {
    /// Create a new arrow renderer with default arrow size.
    pub fn new() -> Self {
        Self { arrow_size: 10.0 }
    }

    /// Compute the arrowhead transform for an edge.
    ///
    /// Returns the tip point, left wing, and right wing of the arrowhead.
    pub fn arrow_points(
        &self,
        from: &Point2D,
        to: &Point2D,
    ) -> (Point2D, Point2D, Point2D) {
        let dx = to.x - from.x;
        let dy = to.y - from.y;
        let len = (dx * dx + dy * dy).sqrt();
        if len == 0.0 {
            return (*to, *to, *to);
        }

        let ux = dx / len;
        let uy = dy / len;
        // Perpendicular
        let px = -uy;
        let py = ux;

        let tip = *to;
        let half = self.arrow_size / 2.0;
        let back = self.arrow_size;

        let left = Point2D::new(to.x - ux * back + px * half, to.y - uy * back + py * half);
        let right = Point2D::new(to.x - ux * back - px * half, to.y - uy * back - py * half);

        (tip, left, right)
    }
}

/// Edge stroke style for rendering.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EdgeStrokeStyle {
    /// Solid line.
    Solid,
    /// Dashed line.
    Dashed,
    /// Dotted line.
    Dotted,
}

impl Default for EdgeStrokeStyle {
    fn default() -> Self {
        Self::Solid
    }
}

/// Rendering configuration for a visual edge.
#[derive(Debug, Clone)]
pub struct EdgeRenderConfig {
    /// Stroke width in pixels.
    pub stroke_width: f32,
    /// Stroke style.
    pub stroke_style: EdgeStrokeStyle,
    /// Edge color (CSS hex string).
    pub color: String,
    /// Highlighted edge color.
    pub highlight_color: String,
    /// Whether to show the arrowhead.
    pub show_arrow: bool,
}

impl Default for EdgeRenderConfig {
    fn default() -> Self {
        Self {
            stroke_width: 1.5,
            stroke_style: EdgeStrokeStyle::Solid,
            color: "#666666".to_string(),
            highlight_color: "#FF0000".to_string(),
            show_arrow: true,
        }
    }
}

/// Edge path highlighter that tracks which edges should be visually
/// emphasized based on user interaction.
#[derive(Debug, Clone, Default)]
pub struct EdgePathHighlighter {
    /// Currently highlighted edge paths (edge id -> highlight color).
    highlights: std::collections::HashMap<String, String>,
}

impl EdgePathHighlighter {
    /// Create a new edge path highlighter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Highlight an edge.
    pub fn highlight(&mut self, edge_id: impl Into<String>, color: impl Into<String>) {
        self.highlights.insert(edge_id.into(), color.into());
    }

    /// Remove highlight from an edge.
    pub fn unhighlight(&mut self, edge_id: &str) {
        self.highlights.remove(edge_id);
    }

    /// Check if an edge is highlighted.
    pub fn is_highlighted(&self, edge_id: &str) -> bool {
        self.highlights.contains_key(edge_id)
    }

    /// Get highlight color for an edge.
    pub fn highlight_color(&self, edge_id: &str) -> Option<&str> {
        self.highlights.get(edge_id).map(|s| s.as_str())
    }

    /// Clear all highlights.
    pub fn clear(&mut self) {
        self.highlights.clear();
    }

    /// Number of highlighted edges.
    pub fn count(&self) -> usize {
        self.highlights.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::viewer::Point2D;

    #[test]
    fn arrow_renderer_straight_horizontal() {
        let renderer = EdgeArrowRenderer::new();
        let from = Point2D::new(0.0, 0.0);
        let to = Point2D::new(100.0, 0.0);
        let (tip, left, right) = renderer.arrow_points(&from, &to);
        assert_eq!(tip, to);
        assert!((left.y - right.y).abs() > 0.01);
    }

    #[test]
    fn arrow_renderer_zero_length() {
        let renderer = EdgeArrowRenderer::new();
        let p = Point2D::new(50.0, 50.0);
        let (tip, left, right) = renderer.arrow_points(&p, &p);
        assert_eq!(tip, p);
        assert_eq!(left, p);
        assert_eq!(right, p);
    }

    #[test]
    fn edge_path_highlighter() {
        let mut h = EdgePathHighlighter::new();
        assert!(!h.is_highlighted("e1"));
        h.highlight("e1", "#FF0000");
        assert!(h.is_highlighted("e1"));
        assert_eq!(h.highlight_color("e1"), Some("#FF0000"));
        assert_eq!(h.count(), 1);
        h.unhighlight("e1");
        assert!(!h.is_highlighted("e1"));
    }

    #[test]
    fn edge_render_config_default() {
        let config = EdgeRenderConfig::default();
        assert_eq!(config.stroke_width, 1.5);
        assert_eq!(config.stroke_style, EdgeStrokeStyle::Solid);
        assert!(config.show_arrow);
    }

    #[test]
    fn edge_stroke_styles() {
        assert_eq!(EdgeStrokeStyle::Solid, EdgeStrokeStyle::Solid);
        assert_ne!(EdgeStrokeStyle::Solid, EdgeStrokeStyle::Dashed);
    }
}
