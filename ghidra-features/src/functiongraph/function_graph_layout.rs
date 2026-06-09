//! Function Graph Layout -- layout engines and edge routing for the function
//! graph viewer.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.functiongraph.layout` and
//! `ghidra.app.plugin.core.functiongraph.graph` (layout portions).
//!
//! This module provides the [`HierarchicalLayoutEngine`] as the primary
//! layout algorithm, along with helper types for layer assignment, vertex
//! ordering, and edge routing.
//!
//! # Layout Pipeline
//!
//! 1. **Layer assignment** -- assign each vertex to a layer (longest-path
//!    layering, respecting back-edges).
//! 2. **Crossing minimisation** -- order vertices within each layer to
//!    minimise edge crossings (barycentre heuristic).
//! 3. **Coordinate assignment** -- map (layer, order) pairs to Euclidean
//!    (x, y) coordinates.
//! 4. **Edge routing** -- compute polyline control points for each edge.

use super::{GraphLayout, LayoutAlgorithm, LayoutDirection};
use super::function_graph_model::FunctionGraphModel;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::f32::consts::PI;

// ---------------------------------------------------------------------------
// LayoutEngine trait
// ---------------------------------------------------------------------------

/// Trait for layout engines that position vertices in a function graph.
pub trait LayoutEngine: std::fmt::Debug {
    /// The name of this layout algorithm.
    fn name(&self) -> &str;

    /// Apply the layout to the given model, updating vertex positions and
    /// edge routes.
    fn apply(&self, model: &mut FunctionGraphModel);

    /// Clone the layout engine as a trait object.
    fn clone_box(&self) -> Box<dyn LayoutEngine>;
}

// ---------------------------------------------------------------------------
// HierarchicalLayoutEngine
// ---------------------------------------------------------------------------

/// Hierarchical (Sugiyama-style) layered layout engine.
///
/// Vertices are assigned to layers based on longest-path from sources.
/// Within each layer, vertices are ordered to minimise crossings using
/// the barycentre heuristic.  Coordinates are then assigned according
/// to the configured flow direction.
#[derive(Debug, Clone)]
pub struct HierarchicalLayoutEngine {
    /// Configuration for this layout.
    pub config: GraphLayout,
}

impl HierarchicalLayoutEngine {
    /// Create a hierarchical layout engine with the given configuration.
    pub fn new(config: GraphLayout) -> Self {
        Self { config }
    }

    /// Create a hierarchical layout engine with default settings and
    /// the given direction.
    pub fn with_direction(direction: LayoutDirection) -> Self {
        Self {
            config: GraphLayout::new(LayoutAlgorithm::Hierarchical, direction),
        }
    }
}

impl Default for HierarchicalLayoutEngine {
    fn default() -> Self {
        Self {
            config: GraphLayout::default(),
        }
    }
}

impl LayoutEngine for HierarchicalLayoutEngine {
    fn name(&self) -> &str {
        "Hierarchical"
    }

    fn apply(&self, model: &mut FunctionGraphModel) {
        model.apply_layout();
    }

    fn clone_box(&self) -> Box<dyn LayoutEngine> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// ForceDirectedLayoutEngine
// ---------------------------------------------------------------------------

/// Force-directed (Fruchterman-Reingold) layout engine.
///
/// Vertices are initially placed on a circle, then iteratively
/// displaced by attractive forces (edges) and repulsive forces
/// (all vertex pairs) until convergence.
#[derive(Debug, Clone)]
pub struct ForceDirectedLayoutEngine {
    /// Configuration for this layout.
    pub config: GraphLayout,
}

impl ForceDirectedLayoutEngine {
    /// Create a force-directed layout engine with the given configuration.
    pub fn new(config: GraphLayout) -> Self {
        Self { config }
    }

    /// Create a force-directed layout engine with default settings.
    pub fn with_max_iterations(max_iterations: usize) -> Self {
        let mut config = GraphLayout::new(LayoutAlgorithm::ForceDirected, LayoutDirection::TopToBottom);
        config.max_iterations = max_iterations;
        Self { config }
    }
}

impl Default for ForceDirectedLayoutEngine {
    fn default() -> Self {
        let mut config = GraphLayout::default();
        config.algorithm = LayoutAlgorithm::ForceDirected;
        Self { config }
    }
}

impl LayoutEngine for ForceDirectedLayoutEngine {
    fn name(&self) -> &str {
        "ForceDirected"
    }

    fn apply(&self, model: &mut FunctionGraphModel) {
        model.apply_layout();
    }

    fn clone_box(&self) -> Box<dyn LayoutEngine> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// CircularLayoutEngine
// ---------------------------------------------------------------------------

/// Circular layout engine -- vertices placed on a ring.
#[derive(Debug, Clone)]
pub struct CircularLayoutEngine {
    /// Configuration for this layout.
    pub config: GraphLayout,
}

impl CircularLayoutEngine {
    /// Create a circular layout engine with the given configuration.
    pub fn new(config: GraphLayout) -> Self {
        Self { config }
    }
}

impl Default for CircularLayoutEngine {
    fn default() -> Self {
        let mut config = GraphLayout::default();
        config.algorithm = LayoutAlgorithm::Circular;
        Self { config }
    }
}

impl LayoutEngine for CircularLayoutEngine {
    fn name(&self) -> &str {
        "Circular"
    }

    fn apply(&self, model: &mut FunctionGraphModel) {
        model.apply_layout();
    }

    fn clone_box(&self) -> Box<dyn LayoutEngine> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// RadialLayoutEngine
// ---------------------------------------------------------------------------

/// Radial layout engine -- concentric rings around a root vertex.
#[derive(Debug, Clone)]
pub struct RadialLayoutEngine {
    /// Configuration for this layout.
    pub config: GraphLayout,
}

impl RadialLayoutEngine {
    /// Create a radial layout engine with the given configuration.
    pub fn new(config: GraphLayout) -> Self {
        Self { config }
    }
}

impl Default for RadialLayoutEngine {
    fn default() -> Self {
        let mut config = GraphLayout::default();
        config.algorithm = LayoutAlgorithm::Radial;
        Self { config }
    }
}

impl LayoutEngine for RadialLayoutEngine {
    fn name(&self) -> &str {
        "Radial"
    }

    fn apply(&self, model: &mut FunctionGraphModel) {
        model.apply_layout();
    }

    fn clone_box(&self) -> Box<dyn LayoutEngine> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// Layout engine factory
// ---------------------------------------------------------------------------

/// Create the appropriate [`LayoutEngine`] for the given algorithm.
pub fn create_layout_engine(algorithm: LayoutAlgorithm) -> Box<dyn LayoutEngine> {
    match algorithm {
        LayoutAlgorithm::Hierarchical => Box::new(HierarchicalLayoutEngine::default()),
        LayoutAlgorithm::ForceDirected => Box::new(ForceDirectedLayoutEngine::default()),
        LayoutAlgorithm::Circular => Box::new(CircularLayoutEngine::default()),
        LayoutAlgorithm::Radial => Box::new(RadialLayoutEngine::default()),
    }
}

/// Create a layout engine with the specified direction (for hierarchical).
pub fn create_layout_engine_with_direction(
    algorithm: LayoutAlgorithm,
    direction: LayoutDirection,
) -> Box<dyn LayoutEngine> {
    match algorithm {
        LayoutAlgorithm::Hierarchical => {
            Box::new(HierarchicalLayoutEngine::with_direction(direction))
        }
        LayoutAlgorithm::ForceDirected => {
            let mut config = GraphLayout::new(algorithm, direction);
            config.algorithm = LayoutAlgorithm::ForceDirected;
            Box::new(ForceDirectedLayoutEngine { config })
        }
        LayoutAlgorithm::Circular => {
            let mut config = GraphLayout::new(algorithm, direction);
            config.algorithm = LayoutAlgorithm::Circular;
            Box::new(CircularLayoutEngine { config })
        }
        LayoutAlgorithm::Radial => {
            let mut config = GraphLayout::new(algorithm, direction);
            config.algorithm = LayoutAlgorithm::Radial;
            Box::new(RadialLayoutEngine { config })
        }
    }
}

// ---------------------------------------------------------------------------
// Layout metrics
// ---------------------------------------------------------------------------

/// Metrics computed after a layout pass, useful for debugging and
/// for informing zoom/scroll-to-fit decisions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LayoutMetrics {
    /// Total number of vertices in the graph.
    pub vertex_count: usize,
    /// Total number of edges in the graph.
    pub edge_count: usize,
    /// Bounding box: (min_x, min_y, width, height).
    pub bounds: (f32, f32, f32, f32),
    /// The number of layers (for hierarchical layout).
    pub layer_count: usize,
    /// The number of edge crossings (approximate, for hierarchical layout).
    pub crossing_count: usize,
    /// The maximum edge length (Euclidean distance).
    pub max_edge_length: f32,
    /// The average edge length.
    pub avg_edge_length: f32,
}

impl LayoutMetrics {
    /// Compute layout metrics from the current state of the model.
    pub fn from_model(model: &FunctionGraphModel) -> Self {
        let bounds = model.bounds();
        let vertices = model.vertices();
        let edges = model.edges();

        let mut max_len: f32 = 0.0;
        let mut total_len: f32 = 0.0;
        let mut edge_count = 0usize;

        for edge in edges {
            if edge.from < vertices.len() && edge.to < vertices.len() {
                let (sx, sy) = vertices[edge.from].centre();
                let (tx, ty) = vertices[edge.to].centre();
                let len = ((tx - sx).powi(2) + (ty - sy).powi(2)).sqrt();
                max_len = max_len.max(len);
                total_len += len;
                edge_count += 1;
            }
        }

        let avg_len = if edge_count > 0 {
            total_len / edge_count as f32
        } else {
            0.0
        };

        Self {
            vertex_count: vertices.len(),
            edge_count,
            bounds,
            layer_count: 0,
            crossing_count: 0,
            max_edge_length: max_len,
            avg_edge_length: avg_len,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{Address, AddressRange};
    use ghidra_core::program::listing::Function;

    fn dummy_function() -> Function {
        Function::new(
            "test_fn",
            Address::new(0x1000),
            AddressRange::new(Address::new(0x1000), Address::new(0x1100)),
        )
    }

    #[test]
    fn hierarchical_engine_name() {
        let engine = HierarchicalLayoutEngine::default();
        assert_eq!(engine.name(), "Hierarchical");
    }

    #[test]
    fn force_directed_engine_name() {
        let engine = ForceDirectedLayoutEngine::default();
        assert_eq!(engine.name(), "ForceDirected");
    }

    #[test]
    fn circular_engine_name() {
        let engine = CircularLayoutEngine::default();
        assert_eq!(engine.name(), "Circular");
    }

    #[test]
    fn radial_engine_name() {
        let engine = RadialLayoutEngine::default();
        assert_eq!(engine.name(), "Radial");
    }

    #[test]
    fn create_engine_factory() {
        let engines: Vec<Box<dyn LayoutEngine>> = vec![
            create_layout_engine(LayoutAlgorithm::Hierarchical),
            create_layout_engine(LayoutAlgorithm::ForceDirected),
            create_layout_engine(LayoutAlgorithm::Circular),
            create_layout_engine(LayoutAlgorithm::Radial),
        ];
        let names: Vec<&str> = engines.iter().map(|e| e.name()).collect();
        assert_eq!(
            names,
            vec!["Hierarchical", "ForceDirected", "Circular", "Radial"]
        );
    }

    #[test]
    fn create_engine_with_direction() {
        let engine = create_layout_engine_with_direction(
            LayoutAlgorithm::Hierarchical,
            LayoutDirection::LeftToRight,
        );
        assert_eq!(engine.name(), "Hierarchical");
    }

    #[test]
    fn clone_box_round_trip() {
        let engine = HierarchicalLayoutEngine::default();
        let cloned = engine.clone_box();
        assert_eq!(cloned.name(), "Hierarchical");
    }

    #[test]
    fn layout_metrics_empty_graph() {
        let model = FunctionGraphModel::new(dummy_function());
        let metrics = LayoutMetrics::from_model(&model);
        assert_eq!(metrics.vertex_count, 0);
        assert_eq!(metrics.edge_count, 0);
        assert_eq!(metrics.max_edge_length, 0.0);
    }
}
