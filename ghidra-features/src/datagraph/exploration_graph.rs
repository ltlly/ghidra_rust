//! Abstract exploration graph base.
//!
//! Ported from Ghidra's `datagraph.graph.explore` Java package.

use std::collections::HashMap;

/// A vertex in an exploration graph.
#[derive(Debug, Clone)]
pub struct EgVertex {
    pub id: u64,
    pub label: String,
    pub address: u64,
}

/// An edge in an exploration graph.
#[derive(Debug, Clone)]
pub struct EgEdge {
    pub id: u64,
    pub source_id: u64,
    pub target_id: u64,
}

/// Abstract exploration graph for data traversal.
#[derive(Debug)]
pub struct AbstractExplorationGraph {
    pub vertices: HashMap<u64, EgVertex>,
    pub edges: HashMap<u64, EgEdge>,
    next_edge_id: u64,
}

impl AbstractExplorationGraph {
    pub fn new() -> Self {
        Self {
            vertices: HashMap::new(),
            edges: HashMap::new(),
            next_edge_id: 1,
        }
    }

    pub fn add_vertex(&mut self, vertex: EgVertex) {
        self.vertices.insert(vertex.id, vertex);
    }

    pub fn add_edge(&mut self, source_id: u64, target_id: u64) -> u64 {
        let id = self.next_edge_id;
        self.next_edge_id += 1;
        self.edges.insert(id, EgEdge { id, source_id, target_id });
        id
    }

    pub fn vertex_count(&self) -> usize { self.vertices.len() }
    pub fn edge_count(&self) -> usize { self.edges.len() }
}

impl Default for AbstractExplorationGraph {
    fn default() -> Self { Self::new() }
}

/// Location map for graph vertex positions.
#[derive(Debug, Default)]
pub struct GraphLocationMap {
    positions: HashMap<u64, (f64, f64)>,
}

impl GraphLocationMap {
    pub fn new() -> Self { Self::default() }
    pub fn set_position(&mut self, vertex_id: u64, x: f64, y: f64) {
        self.positions.insert(vertex_id, (x, y));
    }
    pub fn get_position(&self, vertex_id: u64) -> Option<(f64, f64)> {
        self.positions.get(&vertex_id).copied()
    }
}

/// Edge renderer for exploration graph edges.
#[derive(Debug)]
pub struct EgEdgeRenderer {
    pub stroke_width: f32,
    pub color: String,
}

impl Default for EgEdgeRenderer {
    fn default() -> Self {
        Self { stroke_width: 1.0, color: "#000000".to_string() }
    }
}

/// Edge shape transformer for exploration graph edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgEdgeShape {
    Line,
    QuadCurve,
    CubicCurve,
    Orthogonal,
}

impl Default for EgEdgeShape {
    fn default() -> Self { Self::QuadCurve }
}

/// Layout algorithm for exploration graphs.
#[derive(Debug)]
pub struct EgGraphLayout {
    pub horizontal_spacing: f64,
    pub vertical_spacing: f64,
}

impl Default for EgGraphLayout {
    fn default() -> Self {
        Self { horizontal_spacing: 120.0, vertical_spacing: 80.0 }
    }
}

impl EgGraphLayout {
    pub fn compute_layout(&self, vertex_ids: &[u64]) -> HashMap<u64, (f64, f64)> {
        let mut positions = HashMap::new();
        for (i, &vid) in vertex_ids.iter().enumerate() {
            let col = i % 6;
            let row = i / 6;
            positions.insert(vid, (col as f64 * self.horizontal_spacing, row as f64 * self.vertical_spacing));
        }
        positions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exploration_graph() {
        let mut g = AbstractExplorationGraph::new();
        g.add_vertex(EgVertex { id: 1, label: "a".into(), address: 0x1000 });
        g.add_vertex(EgVertex { id: 2, label: "b".into(), address: 0x2000 });
        g.add_edge(1, 2);
        assert_eq!(g.vertex_count(), 2);
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn test_location_map() {
        let mut m = GraphLocationMap::new();
        m.set_position(1, 10.0, 20.0);
        assert_eq!(m.get_position(1), Some((10.0, 20.0)));
        assert_eq!(m.get_position(2), None);
    }

    #[test]
    fn test_eg_layout() {
        let layout = EgGraphLayout::default();
        let positions = layout.compute_layout(&[1, 2, 3]);
        assert_eq!(positions.len(), 3);
    }

    #[test]
    fn test_edge_shape_default() {
        assert_eq!(EgEdgeShape::default(), EgEdgeShape::QuadCurve);
    }
}
