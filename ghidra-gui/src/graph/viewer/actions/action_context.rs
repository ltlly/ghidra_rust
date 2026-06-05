//! Action contexts for the visual graph system.
//!
//! Ports `ghidra.graph.viewer.actions.VisualGraphActionContext`,
//! `VgActionContext`, and related types.

use crate::graph::viewer::Rect2D;

/// Marker for the type of graph action context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionContextKind {
    /// General graph context (background).
    Graph,
    /// Vertex-specific context.
    Vertex,
    /// Satellite context.
    Satellite,
}

/// Context for actions on the visual graph.
///
/// Provides information about the current graph state when an action
/// is invoked, including the selected vertices/edges and the location
/// of the mouse.
#[derive(Debug, Clone)]
pub struct VisualGraphActionContext {
    /// The kind of context.
    pub kind: ActionContextKind,
    /// Selected vertex IDs.
    pub selected_vertices: Vec<u64>,
    /// Selected edge IDs.
    pub selected_edges: Vec<u64>,
    /// Mouse position in graph coordinates.
    pub mouse_position: Option<(f64, f64)>,
    /// Viewport bounds.
    pub viewport: Option<Rect2D>,
}

impl VisualGraphActionContext {
    /// Create a graph-level context.
    pub fn graph_context() -> Self {
        Self {
            kind: ActionContextKind::Graph,
            selected_vertices: Vec::new(),
            selected_edges: Vec::new(),
            mouse_position: None,
            viewport: None,
        }
    }

    /// Create a vertex-level context.
    pub fn vertex_context(vertex_id: u64) -> Self {
        Self {
            kind: ActionContextKind::Vertex,
            selected_vertices: vec![vertex_id],
            selected_edges: Vec::new(),
            mouse_position: None,
            viewport: None,
        }
    }

    /// Create a satellite context.
    pub fn satellite_context() -> Self {
        Self {
            kind: ActionContextKind::Satellite,
            selected_vertices: Vec::new(),
            selected_edges: Vec::new(),
            mouse_position: None,
            viewport: None,
        }
    }

    /// Check if any vertices are selected.
    pub fn has_selection(&self) -> bool {
        !self.selected_vertices.is_empty()
    }

    /// Check if exactly one vertex is selected.
    pub fn has_single_vertex(&self) -> bool {
        self.selected_vertices.len() == 1
    }
}

/// Simplified action context for graph background actions.
#[derive(Debug, Clone)]
pub struct VgActionContext {
    /// The underlying action context.
    pub inner: VisualGraphActionContext,
}

impl VgActionContext {
    /// Create from a VisualGraphActionContext.
    pub fn new(inner: VisualGraphActionContext) -> Self {
        Self { inner }
    }
}

/// Context for vertex-specific actions.
#[derive(Debug, Clone)]
pub struct VgVertexContext {
    /// The action context.
    pub inner: VisualGraphActionContext,
    /// The vertex ID under the cursor.
    pub vertex_id: u64,
}

impl VgVertexContext {
    /// Create a new vertex context.
    pub fn new(context: VisualGraphActionContext, vertex_id: u64) -> Self {
        Self {
            inner: context,
            vertex_id,
        }
    }
}

/// Context for satellite actions.
#[derive(Debug, Clone)]
pub struct VgSatelliteContext {
    /// The action context.
    pub inner: VisualGraphActionContext,
}

impl VgSatelliteContext {
    /// Create a new satellite context.
    pub fn new(context: VisualGraphActionContext) -> Self {
        Self { inner: context }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_context() {
        let ctx = VisualGraphActionContext::graph_context();
        assert_eq!(ctx.kind, ActionContextKind::Graph);
        assert!(!ctx.has_selection());
    }

    #[test]
    fn test_vertex_context() {
        let ctx = VisualGraphActionContext::vertex_context(42);
        assert_eq!(ctx.kind, ActionContextKind::Vertex);
        assert!(ctx.has_single_vertex());
        assert_eq!(ctx.selected_vertices[0], 42);
    }

    #[test]
    fn test_satellite_context() {
        let ctx = VisualGraphActionContext::satellite_context();
        assert_eq!(ctx.kind, ActionContextKind::Satellite);
    }
}
