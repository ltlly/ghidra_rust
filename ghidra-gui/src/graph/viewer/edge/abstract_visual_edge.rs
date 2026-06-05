//! Base visual edge with shared state.
//!
//! Ports `ghidra.graph.viewer.edge.AbstractVisualEdge`.

use crate::graph::viewer::Point2D;

/// Base visual edge with common rendering state.
#[derive(Debug, Clone)]
pub struct AbstractVisualEdge {
    /// Unique edge ID.
    pub id: u64,
    /// Source vertex ID.
    pub start_vertex_id: u64,
    /// Target vertex ID.
    pub end_vertex_id: u64,
    /// Articulation (bend) points.
    pub articulations: Vec<Point2D>,
    /// Whether this edge is selected.
    pub selected: bool,
    /// Whether this edge is hovered.
    pub hovered: bool,
    /// Whether this edge is in a shortest path.
    pub in_path: bool,
    /// Edge label text.
    pub label: Option<String>,
}

impl AbstractVisualEdge {
    /// Create a new edge.
    pub fn new(id: u64, start: u64, end: u64) -> Self {
        Self {
            id,
            start_vertex_id: start,
            end_vertex_id: end,
            articulations: Vec::new(),
            selected: false,
            hovered: false,
            in_path: false,
            label: None,
        }
    }

    /// Set articulation points.
    pub fn set_articulation_points(&mut self, points: Vec<Point2D>) {
        self.articulations = points;
    }

    /// Get the articulation points.
    pub fn get_articulation_points(&self) -> &[Point2D] {
        &self.articulations
    }

    /// Select this edge.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    /// Check if selected.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Set hover state.
    pub fn set_hovered(&mut self, hovered: bool) {
        self.hovered = hovered;
    }

    /// Mark as in a shortest path.
    pub fn set_in_path(&mut self, in_path: bool) {
        self.in_path = in_path;
    }

    /// Set the edge label.
    pub fn set_label(&mut self, label: impl Into<String>) {
        self.label = Some(label.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_creation() {
        let e = AbstractVisualEdge::new(1, 10, 20);
        assert_eq!(e.start_vertex_id, 10);
        assert_eq!(e.end_vertex_id, 20);
        assert!(e.articulations.is_empty());
    }

    #[test]
    fn test_edge_articulations() {
        let mut e = AbstractVisualEdge::new(1, 10, 20);
        e.set_articulation_points(vec![Point2D::new(50.0, 50.0)]);
        assert_eq!(e.get_articulation_points().len(), 1);
    }

    #[test]
    fn test_edge_state() {
        let mut e = AbstractVisualEdge::new(1, 10, 20);
        e.set_selected(true);
        assert!(e.is_selected());
        e.set_in_path(true);
        assert!(e.in_path);
        e.set_label("weight=5");
        assert_eq!(e.label.as_deref(), Some("weight=5"));
    }
}
