//! Edge stroke transformation for visual state.
//!
//! Ports `ghidra.graph.viewer.edge.VisualGraphEdgeStrokeTransformer`.

use super::visual_edge_renderer::EdgeStyle;

/// Transforms an edge's visual state into its rendering stroke.
#[derive(Debug, Clone)]
pub struct EdgeStrokeTransformer {
    /// Default line width.
    pub default_width: f32,
    /// Selected line width.
    pub selected_width: f32,
    /// Hovered line width.
    pub hovered_width: f32,
    /// In-path line width.
    pub in_path_width: f32,
}

impl EdgeStrokeTransformer {
    /// Create a new transformer.
    pub fn new() -> Self {
        Self {
            default_width: 1.5,
            selected_width: 3.0,
            hovered_width: 2.5,
            in_path_width: 3.0,
        }
    }

    /// Get the stroke width for an edge based on its state.
    pub fn get_width(&self, selected: bool, hovered: bool, in_path: bool) -> f32 {
        if in_path {
            self.in_path_width
        } else if selected {
            self.selected_width
        } else if hovered {
            self.hovered_width
        } else {
            self.default_width
        }
    }

    /// Get the stroke style for an edge.
    pub fn get_style(&self, _selected: bool, _hovered: bool, in_path: bool) -> EdgeStyle {
        if in_path {
            EdgeStyle::Solid
        } else {
            EdgeStyle::Solid
        }
    }
}

impl Default for EdgeStrokeTransformer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stroke_widths() {
        let t = EdgeStrokeTransformer::new();
        assert_eq!(t.get_width(false, false, false), 1.5);
        assert_eq!(t.get_width(true, false, false), 3.0);
        assert_eq!(t.get_width(false, true, false), 2.5);
        assert_eq!(t.get_width(false, false, true), 3.0);
    }

    #[test]
    fn test_stroke_style() {
        let t = EdgeStrokeTransformer::new();
        assert_eq!(t.get_style(false, false, false), EdgeStyle::Solid);
    }
}
