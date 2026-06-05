//! Main vertex renderer for the visual graph system.
//!
//! Ports `ghidra.graph.viewer.vertex.VisualVertexRenderer`.

use super::abstract_visual_vertex::AbstractVisualVertex;
use crate::graph::viewer::Rect2D;

/// Rendering effects that can be applied to a vertex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VertexRenderEffect {
    /// No special effects.
    None,
    /// Drop shadow effect.
    DropShadow,
    /// Highlight ring effect.
    Highlight,
    /// Both drop shadow and highlight.
    Both,
}

/// Main vertex renderer.
///
/// Handles the rendering pipeline for vertices: clipping, geometry
/// setup, and effects (drop shadow, highlight).
pub struct VisualVertexRenderer {
    /// Whether drop shadows are enabled.
    pub drop_shadows_enabled: bool,
    /// Whether highlights are rendered.
    pub highlights_enabled: bool,
    /// Drop shadow offset (pixels).
    pub shadow_offset: f64,
    /// Drop shadow dark color.
    pub shadow_dark_color: String,
    /// Drop shadow light color.
    pub shadow_light_color: String,
    /// Highlight ring color.
    pub highlight_color: String,
    /// Highlight ring offset (pixels).
    pub highlight_offset: f64,
    /// Zoom threshold below which vertex interaction is disabled.
    pub interaction_zoom_threshold: f64,
}

impl VisualVertexRenderer {
    /// Create a new renderer.
    pub fn new() -> Self {
        Self {
            drop_shadows_enabled: true,
            highlights_enabled: true,
            shadow_offset: 5.0,
            shadow_dark_color: "#333333".to_string(),
            shadow_light_color: "#CCCCCC".to_string(),
            highlight_color: "#6699FF".to_string(),
            highlight_offset: 10.0,
            interaction_zoom_threshold: 0.2,
        }
    }

    /// Check if the view is scaled past the interaction threshold.
    pub fn is_scaled_past_interaction(&self, scale: f64) -> bool {
        scale < self.interaction_zoom_threshold
    }

    /// Compute the highlight bounds for a vertex.
    pub fn compute_highlight_bounds(&self, vertex: &AbstractVisualVertex) -> Rect2D {
        let r = vertex.bounding_rect();
        Rect2D::new(
            r.x - self.highlight_offset,
            r.y - self.highlight_offset,
            r.width + self.highlight_offset * 2.0,
            r.height + self.highlight_offset * 2.0,
        )
    }

    /// Compute the shadow bounds for a vertex.
    pub fn compute_shadow_bounds(&self, vertex: &AbstractVisualVertex) -> Rect2D {
        let r = vertex.bounding_rect();
        Rect2D::new(
            r.x + self.shadow_offset,
            r.y + self.shadow_offset,
            r.width,
            r.height,
        )
    }

    /// Get the effect to apply for a vertex.
    pub fn get_effect(&self, vertex: &AbstractVisualVertex) -> VertexRenderEffect {
        let has_shadow = self.drop_shadows_enabled
            && !self.is_scaled_past_interaction(1.0);
        let has_highlight = self.highlights_enabled && vertex.is_selected();
        match (has_shadow, has_highlight) {
            (true, true) => VertexRenderEffect::Both,
            (true, false) => VertexRenderEffect::DropShadow,
            (false, true) => VertexRenderEffect::Highlight,
            (false, false) => VertexRenderEffect::None,
        }
    }
}

impl Default for VisualVertexRenderer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_renderer_default() {
        let r = VisualVertexRenderer::new();
        assert!(r.drop_shadows_enabled);
        assert!(r.highlights_enabled);
    }

    #[test]
    fn test_scaled_past_interaction() {
        let r = VisualVertexRenderer::new();
        assert!(r.is_scaled_past_interaction(0.1));
        assert!(!r.is_scaled_past_interaction(0.5));
    }

    #[test]
    fn test_highlight_bounds() {
        let renderer = VisualVertexRenderer::new();
        let vertex = AbstractVisualVertex::new(1, 100.0, 100.0, 50.0, 50.0);
        let hb = renderer.compute_highlight_bounds(&vertex);
        assert_eq!(hb.x, 65.0); // 75 - 10
        assert_eq!(hb.width, 70.0); // 50 + 20
    }

    #[test]
    fn test_get_effect() {
        let renderer = VisualVertexRenderer::new();
        let mut vertex = AbstractVisualVertex::new(1, 0.0, 0.0, 10.0, 10.0);

        assert_eq!(renderer.get_effect(&vertex), VertexRenderEffect::DropShadow);

        vertex.set_selected(true);
        assert_eq!(renderer.get_effect(&vertex), VertexRenderEffect::Both);
    }
}
