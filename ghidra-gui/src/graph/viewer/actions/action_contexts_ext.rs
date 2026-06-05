//! Extended action context types for graph viewer actions.
//!
//! Ports Ghidra's visual graph action context classes:
//! - [`VisualGraphSatelliteActionContext`] -- action context for satellite view.
//! - [`VisualGraphVertexActionContext`] -- action context when a vertex is selected.

use super::action_context::VisualGraphActionContext;

/// Action context for the satellite (overview) view.
///
/// Ports `ghidra.graph.viewer.actions.VisualGraphSatelliteActionContext`.
/// Provides context information for actions that operate in the satellite view,
/// such as zoom-to-fit, reset view, etc.
#[derive(Debug, Clone)]
pub struct VisualGraphSatelliteActionContext {
    /// The base action context.
    pub base: VisualGraphActionContext,
    /// The current viewport bounds in the satellite view.
    pub viewport_bounds: Option<crate::graph::viewer::Rect2D>,
    /// The current zoom level.
    pub zoom_level: f64,
}

impl VisualGraphSatelliteActionContext {
    /// Create a new satellite action context.
    pub fn new() -> Self {
        Self {
            base: VisualGraphActionContext::graph_context(),
            viewport_bounds: None,
            zoom_level: 1.0,
        }
    }

    /// Set the viewport bounds.
    pub fn with_viewport_bounds(mut self, bounds: crate::graph::viewer::Rect2D) -> Self {
        self.viewport_bounds = Some(bounds);
        self
    }

    /// Set the zoom level.
    pub fn with_zoom_level(mut self, zoom: f64) -> Self {
        self.zoom_level = zoom;
        self
    }

    /// Whether the context has a defined viewport.
    pub fn has_viewport(&self) -> bool {
        self.viewport_bounds.is_some()
    }
}

/// Action context for when a specific vertex is selected.
///
/// Ports `ghidra.graph.viewer.actions.VisualGraphVertexActionContext`.
/// Provides the vertex ID and metadata for vertex-specific actions
/// such as "center on vertex", "expand children", "focus vertex", etc.
#[derive(Debug, Clone)]
pub struct VisualGraphVertexActionContext {
    /// The base action context.
    pub base: VisualGraphActionContext,
    /// The ID of the selected vertex.
    pub vertex_id: String,
    /// The vertex label.
    pub vertex_label: String,
    /// The vertex position.
    pub vertex_position: crate::graph::viewer::Point2D,
    /// IDs of adjacent vertices (predecessors and successors).
    pub adjacent_vertices: Vec<String>,
}

impl VisualGraphVertexActionContext {
    /// Create a new vertex action context.
    pub fn new(
        vertex_id: impl Into<String>,
        label: impl Into<String>,
    ) -> Self {
        Self {
            base: VisualGraphActionContext::graph_context(),
            vertex_id: vertex_id.into(),
            vertex_label: label.into(),
            vertex_position: crate::graph::viewer::Point2D::ZERO,
            adjacent_vertices: Vec::new(),
        }
    }

    /// Set the vertex position.
    pub fn with_position(mut self, pos: crate::graph::viewer::Point2D) -> Self {
        self.vertex_position = pos;
        self
    }

    /// Add adjacent vertices.
    pub fn with_adjacent(mut self, adjacent: Vec<String>) -> Self {
        self.adjacent_vertices = adjacent;
        self
    }

    /// Whether this vertex has any adjacent vertices.
    pub fn has_adjacent(&self) -> bool {
        !self.adjacent_vertices.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::viewer::{Point2D, Rect2D};

    #[test]
    fn satellite_action_context_new() {
        let ctx = VisualGraphSatelliteActionContext::new();
        assert!(ctx.viewport_bounds.is_none());
        assert_eq!(ctx.zoom_level, 1.0);
    }

    #[test]
    fn satellite_action_context_with_viewport() {
        let ctx = VisualGraphSatelliteActionContext::new()
            .with_viewport_bounds(Rect2D::new(0.0, 0.0, 800.0, 600.0))
            .with_zoom_level(2.0);
        assert!(ctx.has_viewport());
        assert_eq!(ctx.zoom_level, 2.0);
    }

    #[test]
    fn vertex_action_context_new() {
        let ctx = VisualGraphVertexActionContext::new("v1", "main");
        assert_eq!(ctx.vertex_id, "v1");
        assert_eq!(ctx.vertex_label, "main");
        assert!(!ctx.has_adjacent());
    }

    #[test]
    fn vertex_action_context_with_adjacent() {
        let ctx = VisualGraphVertexActionContext::new("v1", "func")
            .with_position(Point2D::new(100.0, 200.0))
            .with_adjacent(vec!["v2".into(), "v3".into()]);
        assert!(ctx.has_adjacent());
        assert_eq!(ctx.adjacent_vertices.len(), 2);
        assert_eq!(ctx.vertex_position, Point2D::new(100.0, 200.0));
    }
}
