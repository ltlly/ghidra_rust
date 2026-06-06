//! Action contexts for graph viewer interactions.
//!
//! Ports Ghidra's `ghidra.graph.viewer.actions` package.
//! Provides typed action contexts that carry information about the
//! current graph state when an action is invoked.

use std::collections::HashSet;

/// Marker for the type of context that triggered an action.
///
/// Ports `ghidra.graph.viewer.actions.VisualGraphContextMarker`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VisualGraphContextMarker {
    /// Action was triggered from a vertex context.
    Vertex,
    /// Action was triggered from an edge context.
    Edge,
    /// Action was triggered from the graph background.
    Background,
    /// Action was triggered from the satellite view.
    Satellite,
}

/// Base context for all visual graph actions.
///
/// Ports `ghidra.graph.viewer.actions.VisualGraphActionContext`.
#[derive(Debug, Clone)]
pub struct VisualGraphActionContext {
    /// The marker identifying the context source.
    pub marker: VisualGraphContextMarker,
    /// Currently selected vertex IDs.
    pub selected_vertices: HashSet<usize>,
    /// Currently selected edge IDs.
    pub selected_edges: HashSet<usize>,
    /// The focused vertex ID, if any.
    pub focused_vertex: Option<usize>,
    /// Whether the graph is currently being laid out.
    pub is_layouting: bool,
}

impl VisualGraphActionContext {
    /// Create a new action context.
    pub fn new(marker: VisualGraphContextMarker) -> Self {
        Self {
            marker,
            selected_vertices: HashSet::new(),
            selected_edges: HashSet::new(),
            focused_vertex: None,
            is_layouting: false,
        }
    }

    /// Check if there is a vertex context.
    pub fn has_vertex(&self) -> bool {
        self.marker == VisualGraphContextMarker::Vertex
    }

    /// Check if there is an edge context.
    pub fn has_edge(&self) -> bool {
        self.marker == VisualGraphContextMarker::Edge
    }

    /// Check if there is a background context.
    pub fn has_background(&self) -> bool {
        self.marker == VisualGraphContextMarker::Background
    }

    /// Get the number of selected vertices.
    pub fn selected_vertex_count(&self) -> usize {
        self.selected_vertices.len()
    }

    /// Whether there is exactly one selected vertex.
    pub fn has_single_vertex_selected(&self) -> bool {
        self.selected_vertices.len() == 1
    }
}

/// Context for vertex-specific actions.
///
/// Ports `ghidra.graph.viewer.actions.VisualGraphVertexActionContext`.
#[derive(Debug, Clone)]
pub struct VisualGraphVertexActionContext {
    /// The base context.
    pub base: VisualGraphActionContext,
    /// The vertex ID that this action targets.
    pub vertex_id: usize,
}

impl VisualGraphVertexActionContext {
    /// Create a new vertex action context.
    pub fn new(vertex_id: usize, selected: HashSet<usize>, focused: Option<usize>) -> Self {
        let mut base = VisualGraphActionContext::new(VisualGraphContextMarker::Vertex);
        base.selected_vertices = selected;
        base.focused_vertex = focused;
        Self { base, vertex_id }
    }
}

/// Context for satellite-view actions.
///
/// Ports `ghidra.graph.viewer.actions.VisualGraphSatelliteActionContext`.
#[derive(Debug, Clone)]
pub struct VisualGraphSatelliteActionContext {
    /// The base context.
    pub base: VisualGraphActionContext,
}

impl VisualGraphSatelliteActionContext {
    /// Create a new satellite action context.
    pub fn new() -> Self {
        Self {
            base: VisualGraphActionContext::new(VisualGraphContextMarker::Satellite),
        }
    }
}

impl Default for VisualGraphSatelliteActionContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Simplified action context for the graph viewer.
///
/// Ports `ghidra.graph.viewer.actions.VgActionContext`.
#[derive(Debug, Clone, Default)]
pub struct VgActionContext {
    /// Selected vertex IDs.
    pub selected_vertices: HashSet<usize>,
    /// Selected edge IDs.
    pub selected_edges: HashSet<usize>,
}

/// Context for satellite view actions.
///
/// Ports `ghidra.graph.viewer.actions.VgSatelliteContext`.
#[derive(Debug, Clone, Default)]
pub struct VgSatelliteContext {
    /// The current zoom level in the satellite view.
    pub zoom: f64,
}

/// Context for vertex-specific actions.
///
/// Ports `ghidra.graph.viewer.actions.VgVertexContext`.
#[derive(Debug, Clone)]
pub struct VgVertexContext {
    /// The vertex ID.
    pub vertex_id: usize,
    /// Whether the vertex is selected.
    pub selected: bool,
}

impl VgVertexContext {
    /// Create a new vertex context.
    pub fn new(vertex_id: usize) -> Self {
        Self {
            vertex_id,
            selected: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_context_markers() {
        let ctx = VisualGraphActionContext::new(VisualGraphContextMarker::Vertex);
        assert!(ctx.has_vertex());
        assert!(!ctx.has_edge());
        assert!(!ctx.has_background());
    }

    #[test]
    fn test_vertex_action_context() {
        let mut selected = HashSet::new();
        selected.insert(5);
        let ctx = VisualGraphVertexActionContext::new(42, selected, Some(42));
        assert_eq!(ctx.vertex_id, 42);
        assert!(ctx.base.has_single_vertex_selected());
    }

    #[test]
    fn test_vg_vertex_context() {
        let ctx = VgVertexContext::new(7);
        assert_eq!(ctx.vertex_id, 7);
        assert!(!ctx.selected);
    }
}
