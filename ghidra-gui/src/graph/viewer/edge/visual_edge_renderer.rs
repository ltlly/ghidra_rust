//! Edge rendering for visual graphs.
//!
//! Ports `ghidra.graph.viewer.edge.VisualEdgeRenderer`.


/// Rendering style for edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeStyle {
    /// Solid line.
    Solid,
    /// Dashed line.
    Dashed,
    /// Dotted line.
    Dotted,
}

impl Default for EdgeStyle {
    fn default() -> Self {
        Self::Solid
    }
}

/// Renders edges in the visual graph.
#[derive(Debug, Clone)]
pub struct VisualEdgeRenderer {
    /// Default edge color (CSS hex).
    pub color: String,
    /// Edge line width.
    pub line_width: f32,
    /// Default edge style.
    pub style: EdgeStyle,
    /// Arrow size.
    pub arrow_size: f32,
    /// Whether to render anti-aliased edges.
    pub antialiased: bool,
    /// Highlight color for selected/hovered edges.
    pub highlight_color: String,
    /// Highlight line width multiplier.
    pub highlight_width_factor: f32,
}

impl VisualEdgeRenderer {
    /// Create a new edge renderer.
    pub fn new() -> Self {
        Self {
            color: "#666666".to_string(),
            line_width: 1.5,
            style: EdgeStyle::default(),
            arrow_size: 8.0,
            antialiased: true,
            highlight_color: "#6699CC".to_string(),
            highlight_width_factor: 2.0,
        }
    }

    /// Get the effective line width for a highlighted edge.
    pub fn highlighted_line_width(&self) -> f32 {
        self.line_width * self.highlight_width_factor
    }
}

impl Default for VisualEdgeRenderer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_renderer() {
        let r = VisualEdgeRenderer::new();
        assert_eq!(r.style, EdgeStyle::Solid);
        assert_eq!(r.highlighted_line_width(), 3.0);
    }

    #[test]
    fn test_edge_style_default() {
        assert_eq!(EdgeStyle::default(), EdgeStyle::Solid);
    }
}
