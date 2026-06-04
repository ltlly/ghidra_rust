//! Picking event handling for graph element selection.
//!
//! Ports `ghidra.graph.viewer.event.picking` package.

use crate::graph::viewer::Point2D;

/// Information about a vertex pick event.
#[derive(Debug, Clone)]
pub struct VertexPickInfo {
    /// The picked vertex id.
    pub vertex_id: String,
    /// Whether this was a double-click.
    pub is_double_click: bool,
    /// Pick position in graph coordinates.
    pub graph_point: Point2D,
    /// Whether shift was held during the pick.
    pub shift_held: bool,
    /// Whether ctrl was held during the pick.
    pub ctrl_held: bool,
}

impl VertexPickInfo {
    /// Create new vertex pick info.
    pub fn new(vertex_id: impl Into<String>, graph_point: Point2D) -> Self {
        Self {
            vertex_id: vertex_id.into(),
            is_double_click: false,
            graph_point,
            shift_held: false,
            ctrl_held: false,
        }
    }
}

/// Information about an edge pick event.
#[derive(Debug, Clone)]
pub struct EdgePickInfo {
    /// The picked edge id.
    pub edge_id: String,
    /// Pick position in graph coordinates.
    pub graph_point: Point2D,
}

impl EdgePickInfo {
    /// Create new edge pick info.
    pub fn new(edge_id: impl Into<String>, graph_point: Point2D) -> Self {
        Self {
            edge_id: edge_id.into(),
            graph_point,
        }
    }
}

/// Listener for graph picking events.
pub trait GraphPickingListener: Send + Sync {
    /// Called when a vertex is picked.
    fn on_vertex_picked(&mut self, info: &VertexPickInfo);

    /// Called when an edge is picked.
    fn on_edge_picked(&mut self, info: &EdgePickInfo);

    /// Called when the background is picked (deselect).
    fn on_background_picked(&mut self, graph_point: Point2D);
}

/// Manages the current selection state for graph elements.
#[derive(Debug, Clone, Default)]
pub struct SelectionManager {
    /// Currently selected vertex ids.
    selected_vertices: Vec<String>,
    /// Currently selected edge ids.
    selected_edges: Vec<String>,
    /// Whether multi-select mode is active.
    multi_select: bool,
}

impl SelectionManager {
    /// Create a new selection manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Select a vertex. If multi-select is off, clears previous selection.
    pub fn select_vertex(&mut self, vertex_id: impl Into<String>) {
        let id = vertex_id.into();
        if !self.multi_select {
            self.selected_vertices.clear();
            self.selected_edges.clear();
        }
        if !self.selected_vertices.contains(&id) {
            self.selected_vertices.push(id);
        }
    }

    /// Deselect a vertex.
    pub fn deselect_vertex(&mut self, vertex_id: &str) {
        self.selected_vertices.retain(|id| id != vertex_id);
    }

    /// Select an edge.
    pub fn select_edge(&mut self, edge_id: impl Into<String>) {
        let id = edge_id.into();
        if !self.multi_select {
            self.selected_vertices.clear();
            self.selected_edges.clear();
        }
        if !self.selected_edges.contains(&id) {
            self.selected_edges.push(id);
        }
    }

    /// Clear all selections.
    pub fn clear(&mut self) {
        self.selected_vertices.clear();
        self.selected_edges.clear();
    }

    /// Get selected vertex ids.
    pub fn selected_vertices(&self) -> &[String] {
        &self.selected_vertices
    }

    /// Get selected edge ids.
    pub fn selected_edges(&self) -> &[String] {
        &self.selected_edges
    }

    /// Whether a vertex is selected.
    pub fn is_vertex_selected(&self, vertex_id: &str) -> bool {
        self.selected_vertices.iter().any(|id| id == vertex_id)
    }

    /// Whether an edge is selected.
    pub fn is_edge_selected(&self, edge_id: &str) -> bool {
        self.selected_edges.iter().any(|id| id == edge_id)
    }

    /// Set multi-select mode.
    pub fn set_multi_select(&mut self, multi: bool) {
        self.multi_select = multi;
    }

    /// Whether anything is selected.
    pub fn has_selection(&self) -> bool {
        !self.selected_vertices.is_empty() || !self.selected_edges.is_empty()
    }

    /// Total number of selected elements.
    pub fn selection_count(&self) -> usize {
        self.selected_vertices.len() + self.selected_edges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_single_mode() {
        let mut sm = SelectionManager::new();
        sm.select_vertex("v1");
        sm.select_vertex("v2");
        assert_eq!(sm.selected_vertices().len(), 1); // v1 replaced by v2
        assert!(sm.is_vertex_selected("v2"));
        assert!(!sm.is_vertex_selected("v1"));
    }

    #[test]
    fn selection_multi_mode() {
        let mut sm = SelectionManager::new();
        sm.set_multi_select(true);
        sm.select_vertex("v1");
        sm.select_vertex("v2");
        assert_eq!(sm.selected_vertices().len(), 2);
        assert!(sm.is_vertex_selected("v1"));
        assert!(sm.is_vertex_selected("v2"));
    }

    #[test]
    fn clear_selection() {
        let mut sm = SelectionManager::new();
        sm.set_multi_select(true);
        sm.select_vertex("v1");
        sm.select_edge("e1");
        assert!(sm.has_selection());
        sm.clear();
        assert!(!sm.has_selection());
    }

    #[test]
    fn deselect_vertex() {
        let mut sm = SelectionManager::new();
        sm.set_multi_select(true);
        sm.select_vertex("v1");
        sm.select_vertex("v2");
        sm.deselect_vertex("v1");
        assert_eq!(sm.selected_vertices().len(), 1);
        assert!(!sm.is_vertex_selected("v1"));
    }

    #[test]
    fn vertex_pick_info() {
        let info = VertexPickInfo::new("v1", Point2D::new(10.0, 20.0));
        assert_eq!(info.vertex_id, "v1");
        assert!(!info.is_double_click);
    }
}
