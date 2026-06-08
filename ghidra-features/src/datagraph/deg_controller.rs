//! Controller for the data exploration graph.
//!
//! Ported from Ghidra's `datagraph.data.graph.DegController` Java class.

use super::data_exploration_graph::DataExplorationGraph;
use super::deg_layout::{DegLayout, DegLayoutConfig};

/// Controller managing the data exploration graph state.
pub struct DegController {
    /// The graph.
    pub graph: DataExplorationGraph,
    /// Layout engine.
    pub layout: DegLayout,
    /// Current zoom level (1.0 = 100%).
    pub zoom: f64,
    /// View offset X.
    pub view_x: f64,
    /// View offset Y.
    pub view_y: f64,
}

impl DegController {
    pub fn new(graph: DataExplorationGraph, config: DegLayoutConfig) -> Self {
        Self {
            graph,
            layout: DegLayout::new(config),
            zoom: 1.0,
            view_x: 0.0,
            view_y: 0.0,
        }
    }

    pub fn recompute_layout(&mut self) {
        let ids: Vec<u64> = self.graph.vertices.keys().copied().collect();
        self.layout.compute_layout(&ids);
    }

    pub fn zoom_in(&mut self) { self.zoom = (self.zoom * 1.25).min(10.0); }
    pub fn zoom_out(&mut self) { self.zoom = (self.zoom / 1.25).max(0.1); }
    pub fn reset_view(&mut self) { self.zoom = 1.0; self.view_x = 0.0; self.view_y = 0.0; }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::deg_vertex::DegVertex;

    #[test]
    fn test_controller() {
        let mut graph = DataExplorationGraph::new("test");
        graph.add_vertex(DegVertex::code(0, 0x1000));
        graph.add_vertex(DegVertex::code(0, 0x2000));
        let mut ctrl = DegController::new(graph, DegLayoutConfig::default());
        ctrl.recompute_layout();
        assert_eq!(ctrl.layout.positions.len(), 2);
    }

    #[test]
    fn test_zoom() {
        let graph = DataExplorationGraph::new("test");
        let mut ctrl = DegController::new(graph, DegLayoutConfig::default());
        assert_eq!(ctrl.zoom, 1.0);
        ctrl.zoom_in();
        assert!(ctrl.zoom > 1.0);
        ctrl.zoom_out();
        ctrl.zoom_out();
        assert!(ctrl.zoom < 1.0);
        ctrl.reset_view();
        assert_eq!(ctrl.zoom, 1.0);
    }
}
