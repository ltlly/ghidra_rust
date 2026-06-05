//! Path highlighting for graph edges.
//!
//! Ports `ghidra.graph.viewer.edge.VisualGraphPathHighlighter`.

use std::collections::HashSet;

/// Highlights paths in the graph by marking edges as being in a path.
pub struct VisualGraphPathHighlighter {
    /// Edge IDs that are in the highlighted path.
    highlighted_edges: HashSet<u64>,
    /// Vertex IDs that are in the highlighted path.
    highlighted_vertices: HashSet<u64>,
    /// The highlight color.
    pub highlight_color: String,
}

impl VisualGraphPathHighlighter {
    /// Create a new path highlighter.
    pub fn new() -> Self {
        Self {
            highlighted_edges: HashSet::new(),
            highlighted_vertices: HashSet::new(),
            highlight_color: "#FF6600".to_string(),
        }
    }

    /// Set the highlighted path.
    pub fn set_path(&mut self, vertex_ids: Vec<u64>, edge_ids: Vec<u64>) {
        self.highlighted_vertices = vertex_ids.into_iter().collect();
        self.highlighted_edges = edge_ids.into_iter().collect();
    }

    /// Clear the highlighted path.
    pub fn clear(&mut self) {
        self.highlighted_edges.clear();
        self.highlighted_vertices.clear();
    }

    /// Check if an edge is highlighted.
    pub fn is_edge_highlighted(&self, edge_id: u64) -> bool {
        self.highlighted_edges.contains(&edge_id)
    }

    /// Check if a vertex is highlighted.
    pub fn is_vertex_highlighted(&self, vertex_id: u64) -> bool {
        self.highlighted_vertices.contains(&vertex_id)
    }

    /// Check if any path is currently highlighted.
    pub fn has_highlighted_path(&self) -> bool {
        !self.highlighted_edges.is_empty()
    }
}

impl Default for VisualGraphPathHighlighter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_highlighter() {
        let mut h = VisualGraphPathHighlighter::new();
        assert!(!h.has_highlighted_path());
        h.set_path(vec![1, 2, 3], vec![10, 20]);
        assert!(h.has_highlighted_path());
        assert!(h.is_edge_highlighted(10));
        assert!(h.is_vertex_highlighted(2));
        assert!(!h.is_vertex_highlighted(5));
        h.clear();
        assert!(!h.has_highlighted_path());
    }
}
