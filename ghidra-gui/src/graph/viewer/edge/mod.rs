//! Visual edge rendering and routing.
//!
//! Ports `ghidra.graph.viewer.edge` package.
//!
//! Includes:
//! - [`EdgeArrowRenderer`]: computes arrowhead geometry.
//! - [`EdgePathHighlighter`]: tracks highlighted edge paths.
//! - [`PathHighlightListener`]: trait for path highlight change events.

pub mod routing;

// New modules ported from Ghidra's graph viewer edge package
pub mod visual_edge_renderer;
pub mod abstract_visual_edge;
pub mod edge_stroke_transformer;
pub mod path_highlighter;
pub mod basic_edge_label_renderer;

use crate::graph::viewer::Point2D;

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

    /// Get all highlighted edge IDs.
    pub fn highlighted_edges(&self) -> Vec<&str> {
        self.highlights.keys().map(|s| s.as_str()).collect()
    }
}

// ============================================================================
// PathHighlightListener (port of ghidra.graph.viewer.PathHighlightListener)
// ============================================================================

/// Trait for receiving path highlight change events.
///
/// When a user hovers over or selects a vertex, the graph framework
/// highlights the incoming and outgoing edge paths. Implementations
/// of this trait are notified when these paths change.
///
/// Ported from `ghidra.graph.viewer.PathHighlightListener`.
pub trait PathHighlightListener: Send + Sync + std::fmt::Debug {
    /// Called when the hovered vertex path changes.
    fn hovered_path_changed(&self, vertex_id: Option<&str>, edge_ids: &[String]);

    /// Called when the focused vertex path changes.
    fn focused_path_changed(&self, vertex_id: Option<&str>, edge_ids: &[String]);

    /// Called when all path highlights are cleared.
    fn path_highlights_cleared(&self);
}

/// A no-op path highlight listener.
#[derive(Debug, Clone, Default)]
pub struct NullPathHighlightListener;

impl PathHighlightListener for NullPathHighlightListener {
    fn hovered_path_changed(&self, _vertex_id: Option<&str>, _edge_ids: &[String]) {}
    fn focused_path_changed(&self, _vertex_id: Option<&str>, _edge_ids: &[String]) {}
    fn path_highlights_cleared(&self) {}
}

/// Manages the hovered/focused edge paths and notifies listeners.
///
/// This is a higher-level wrapper that combines `EdgePathHighlighter`
/// with the `PathHighlightListener` notifications.
#[derive(Debug)]
pub struct PathHighlightManager {
    /// The edge path highlighter.
    highlighter: EdgePathHighlighter,
    /// The currently hovered vertex (if any).
    pub hovered_vertex: Option<String>,
    /// The currently focused vertex (if any).
    pub focused_vertex: Option<String>,
    /// Registered listeners.
    listeners: Vec<Box<dyn PathHighlightListener>>,
}

impl PathHighlightManager {
    /// Create a new path highlight manager.
    pub fn new() -> Self {
        Self {
            highlighter: EdgePathHighlighter::new(),
            hovered_vertex: None,
            focused_vertex: None,
            listeners: Vec::new(),
        }
    }

    /// Register a path highlight listener.
    pub fn add_listener(&mut self, listener: Box<dyn PathHighlightListener>) {
        self.listeners.push(listener);
    }

    /// Set the hovered vertex and update edge path highlights.
    pub fn set_hovered_vertex(&mut self, vertex_id: Option<String>, edge_ids: Vec<String>) {
        self.hovered_vertex = vertex_id;
        for id in &edge_ids {
            self.highlighter.highlight(id.clone(), "#FFFF00");
        }
        for listener in &self.listeners {
            listener.hovered_path_changed(
                self.hovered_vertex.as_deref(),
                &edge_ids,
            );
        }
    }

    /// Set the focused vertex and update edge path highlights.
    pub fn set_focused_vertex(&mut self, vertex_id: Option<String>, edge_ids: Vec<String>) {
        self.focused_vertex = vertex_id;
        for id in &edge_ids {
            self.highlighter.highlight(id.clone(), "#00FFFF");
        }
        for listener in &self.listeners {
            listener.focused_path_changed(
                self.focused_vertex.as_deref(),
                &edge_ids,
            );
        }
    }

    /// Clear all path highlights.
    pub fn clear(&mut self) {
        self.highlighter.clear();
        self.hovered_vertex = None;
        self.focused_vertex = None;
        for listener in &self.listeners {
            listener.path_highlights_cleared();
        }
    }

    /// Get the underlying highlighter.
    pub fn highlighter(&self) -> &EdgePathHighlighter {
        &self.highlighter
    }

    /// Get the underlying highlighter mutably.
    pub fn highlighter_mut(&mut self) -> &mut EdgePathHighlighter {
        &mut self.highlighter
    }
}

impl Default for PathHighlightManager {
    fn default() -> Self {
        Self::new()
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

    #[test]
    fn path_highlight_manager_new() {
        let mgr = PathHighlightManager::new();
        assert!(mgr.hovered_vertex.is_none());
        assert!(mgr.focused_vertex.is_none());
        assert_eq!(mgr.highlighter().count(), 0);
    }

    #[test]
    fn path_highlight_manager_set_hovered() {
        let mut mgr = PathHighlightManager::new();
        mgr.set_hovered_vertex(
            Some("v1".into()),
            vec!["e1".into(), "e2".into()],
        );
        assert_eq!(mgr.hovered_vertex.as_deref(), Some("v1"));
        assert!(mgr.highlighter().is_highlighted("e1"));
        assert!(mgr.highlighter().is_highlighted("e2"));
    }

    #[test]
    fn path_highlight_manager_set_focused() {
        let mut mgr = PathHighlightManager::new();
        mgr.set_focused_vertex(Some("v1".into()), vec!["e1".into()]);
        assert_eq!(mgr.focused_vertex.as_deref(), Some("v1"));
        assert!(mgr.highlighter().is_highlighted("e1"));
    }

    #[test]
    fn path_highlight_manager_clear() {
        let mut mgr = PathHighlightManager::new();
        mgr.set_hovered_vertex(Some("v1".into()), vec!["e1".into()]);
        mgr.clear();
        assert!(mgr.hovered_vertex.is_none());
        assert_eq!(mgr.highlighter().count(), 0);
    }

    #[test]
    fn path_highlight_manager_null_listener() {
        let listener = NullPathHighlightListener;
        let edges = vec!["e1".to_string()];
        listener.hovered_path_changed(Some("v1"), &edges);
        listener.focused_path_changed(Some("v1"), &edges);
        listener.path_highlights_cleared();
    }

    #[test]
    fn edge_path_highlighter_highlighted_edges() {
        let mut h = EdgePathHighlighter::new();
        h.highlight("e1", "#FF0000");
        h.highlight("e2", "#00FF00");
        let edges = h.highlighted_edges();
        assert_eq!(edges.len(), 2);
        assert!(edges.contains(&"e1"));
        assert!(edges.contains(&"e2"));
    }
}
