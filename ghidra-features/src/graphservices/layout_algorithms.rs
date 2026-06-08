//! Layout algorithm registry and implementations for graph visualization.
//!
//! Ported from Ghidra's `ghidra.graph.visualization.LayoutFunction` and
//! `ghidra.graph.visualization.layout.JgtTidierTreeLayoutAlgorithm`
//! Java classes.
//!
//! Provides a registry of layout algorithms and concrete implementations
//! for positioning vertices in a graph. Layout algorithms compute x,y
//! coordinates for each vertex.

use std::collections::{HashMap, HashSet, VecDeque};

use super::attributed::AttributedGraph;
use super::display_options::GraphDisplayOptions;
use super::edge_comparator::EdgeComparator;

// ---------------------------------------------------------------------------
// Layout algorithm names
// ---------------------------------------------------------------------------

/// Well-known layout algorithm names from Ghidra.
pub const COMPACT_HIERARCHICAL: &str = "Compact Hierarchical";
pub const HIERARCHICAL: &str = "Hierarchical";
pub const CIRCLE: &str = "Circle";
pub const RADIAL: &str = "Radial";
pub const BALLOON: &str = "Balloon";
pub const FORCE_DIRECTED: &str = "Force Directed";
pub const FORCED_BALANCED: &str = "Forced Balanced";
pub const GEM: &str = "GEM";
pub const MIN_CROSS_TOP_DOWN: &str = "Min Cross (Top Down)";
pub const MIN_CROSS_LONGEST_PATH: &str = "Min Cross (Longest Path)";
pub const MIN_CROSS_NETWORK_SIMPLEX: &str = "Min Cross (Network Simplex)";
pub const MIN_CROSS_COFFMAN_GRAHAM: &str = "Min Cross (Coffman Graham)";

/// All available layout algorithm names in display order.
pub const ALL_LAYOUT_NAMES: &[&str] = &[
    COMPACT_HIERARCHICAL,
    HIERARCHICAL,
    CIRCLE,
    RADIAL,
    BALLOON,
    FORCE_DIRECTED,
    FORCED_BALANCED,
    GEM,
    MIN_CROSS_TOP_DOWN,
    MIN_CROSS_LONGEST_PATH,
    MIN_CROSS_NETWORK_SIMPLEX,
    MIN_CROSS_COFFMAN_GRAHAM,
];

// ---------------------------------------------------------------------------
// Layout algorithm trait
// ---------------------------------------------------------------------------

/// A computed vertex position.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VertexPosition {
    pub x: f64,
    pub y: f64,
}

/// The result of applying a layout algorithm.
#[derive(Debug, Clone)]
pub struct LayoutResult {
    /// Positions indexed by vertex id.
    pub positions: HashMap<String, VertexPosition>,
    /// The bounding box (min_x, min_y, width, height).
    pub bounds: (f64, f64, f64, f64),
}

impl LayoutResult {
    /// Create a new layout result from positions.
    pub fn new(positions: HashMap<String, VertexPosition>) -> Self {
        let bounds = Self::compute_bounds(&positions);
        Self { positions, bounds }
    }

    fn compute_bounds(positions: &HashMap<String, VertexPosition>) -> (f64, f64, f64, f64) {
        if positions.is_empty() {
            return (0.0, 0.0, 0.0, 0.0);
        }

        let mut min_x = f64::MAX;
        let mut max_x = f64::MIN;
        let mut min_y = f64::MAX;
        let mut max_y = f64::MIN;

        for pos in positions.values() {
            min_x = min_x.min(pos.x);
            max_x = max_x.max(pos.x);
            min_y = min_y.min(pos.y);
            max_y = max_y.max(pos.y);
        }

        (min_x, min_y, max_x - min_x, max_y - min_y)
    }

    /// Get the position for a specific vertex.
    pub fn position(&self, vertex_id: &str) -> Option<&VertexPosition> {
        self.positions.get(vertex_id)
    }
}

/// Trait for graph layout algorithms.
pub trait LayoutAlgorithm: Send + Sync {
    /// The name of this layout algorithm.
    fn name(&self) -> &str;

    /// Compute vertex positions for the given graph.
    ///
    /// `options` provides edge priority information for algorithms that
    /// consider edge ordering.
    fn compute_layout(
        &self,
        graph: &AttributedGraph,
        options: &GraphDisplayOptions,
    ) -> LayoutResult;
}

// ---------------------------------------------------------------------------
// Circular layout
// ---------------------------------------------------------------------------

/// Places vertices on a circle.
///
/// Vertices are evenly spaced around a circle centered at the origin.
/// The radius is chosen based on the number of vertices.
pub struct CircularLayoutAlgorithm {
    /// Radius of the circle. If `None`, computed automatically.
    pub radius: Option<f64>,
}

impl CircularLayoutAlgorithm {
    pub fn new() -> Self {
        Self { radius: None }
    }

    pub fn with_radius(radius: f64) -> Self {
        Self {
            radius: Some(radius),
        }
    }
}

impl Default for CircularLayoutAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

impl LayoutAlgorithm for CircularLayoutAlgorithm {
    fn name(&self) -> &str {
        CIRCLE
    }

    fn compute_layout(
        &self,
        graph: &AttributedGraph,
        _options: &GraphDisplayOptions,
    ) -> LayoutResult {
        let ids: Vec<String> = graph.vertex_ids().map(|s| s.to_string()).collect();
        let n = ids.len();
        if n == 0 {
            return LayoutResult::new(HashMap::new());
        }

        let radius = self.radius.unwrap_or_else(|| {
            // Auto-compute radius: at least 100px, scale with vertex count
            (n as f64 * 40.0 / std::f64::consts::TAU).max(100.0)
        });

        let mut positions = HashMap::new();
        for (i, id) in ids.iter().enumerate() {
            let angle = std::f64::consts::TAU * (i as f64) / (n as f64);
            positions.insert(
                id.clone(),
                VertexPosition {
                    x: radius * angle.cos(),
                    y: radius * angle.sin(),
                },
            );
        }

        LayoutResult::new(positions)
    }
}

// ---------------------------------------------------------------------------
// Hierarchical (Sugiyama-style) layout
// ---------------------------------------------------------------------------

/// Layering strategy for hierarchical layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayeringStrategy {
    /// Assign layers by longest path from root.
    LongestPath,
    /// Assign layers by topological order (top-down).
    TopDown,
    /// Network simplex layering (minimizes edge length).
    NetworkSimplex,
    /// Coffman-Graham layering (bounded width).
    CoffmanGraham,
}

impl Default for LayeringStrategy {
    fn default() -> Self {
        Self::LongestPath
    }
}

/// Hierarchical (Sugiyama-style) layout algorithm.
///
/// Vertices are arranged in layers, with edges flowing from top to bottom.
/// Uses a variant of the Sugiyama algorithm: layer assignment, crossing
/// reduction, and coordinate assignment.
pub struct HierarchicalLayoutAlgorithm {
    /// Horizontal spacing between vertices in the same layer.
    pub horizontal_spacing: f64,
    /// Vertical spacing between layers.
    pub vertical_spacing: f64,
    /// Layering strategy.
    pub layering: LayeringStrategy,
    /// Number of crossing reduction iterations.
    pub crossing_iterations: usize,
}

impl HierarchicalLayoutAlgorithm {
    pub fn new() -> Self {
        Self {
            horizontal_spacing: 80.0,
            vertical_spacing: 60.0,
            layering: LayeringStrategy::LongestPath,
            crossing_iterations: 24,
        }
    }

    pub fn with_layering(layering: LayeringStrategy) -> Self {
        Self {
            layering,
            ..Self::new()
        }
    }
}

impl Default for HierarchicalLayoutAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

impl LayoutAlgorithm for HierarchicalLayoutAlgorithm {
    fn name(&self) -> &str {
        HIERARCHICAL
    }

    fn compute_layout(
        &self,
        graph: &AttributedGraph,
        _options: &GraphDisplayOptions,
    ) -> LayoutResult {
        let ids: Vec<String> = graph.vertex_ids().map(|s| s.to_string()).collect();
        let n = ids.len();
        if n == 0 {
            return LayoutResult::new(HashMap::new());
        }

        let id_to_idx: HashMap<&str, usize> =
            ids.iter().enumerate().map(|(i, id)| (id.as_str(), i)).collect();

        // Build adjacency lists
        let mut successors: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); n];
        for edge in graph.edges() {
            if let (Some(&si), Some(&ti)) = (
                id_to_idx.get(edge.source_id()),
                id_to_idx.get(edge.target_id()),
            ) {
                successors[si].push(ti);
                predecessors[ti].push(si);
            }
        }

        // Step 1: Assign layers
        let layers = assign_layers(&ids, &predecessors, &successors, self.layering);

        // Step 2: Order vertices within layers (crossing reduction)
        let ordered_layers =
            reduce_crossings(&layers, &successors, &predecessors, self.crossing_iterations);

        // Step 3: Assign coordinates
        let mut positions = HashMap::new();
        for (layer_idx, layer) in ordered_layers.iter().enumerate() {
            let y = layer_idx as f64 * self.vertical_spacing;
            let layer_width = (layer.len() - 1) as f64 * self.horizontal_spacing;
            let x_start = -layer_width / 2.0;

            for (pos_idx, &vidx) in layer.iter().enumerate() {
                let x = x_start + pos_idx as f64 * self.horizontal_spacing;
                positions.insert(ids[vidx].clone(), VertexPosition { x, y });
            }
        }

        LayoutResult::new(positions)
    }
}

/// Assign each vertex to a layer using the chosen strategy.
fn assign_layers(
    ids: &[String],
    predecessors: &[Vec<usize>],
    successors: &[Vec<usize>],
    strategy: LayeringStrategy,
) -> Vec<Vec<usize>> {
    let n = ids.len();
    match strategy {
        LayeringStrategy::LongestPath | LayeringStrategy::TopDown => {
            // Longest path from any root
            let mut layer_of = vec![0usize; n];
            let mut visited = vec![false; n];

            // Find roots (no predecessors)
            let roots: Vec<usize> = (0..n)
                .filter(|&i| predecessors[i].is_empty())
                .collect();

            // If no roots, pick all vertices
            let start_nodes = if roots.is_empty() {
                (0..n).collect()
            } else {
                roots
            };

            // BFS from roots, assigning longest path
            let mut queue: VecDeque<usize> = VecDeque::new();
            for &r in &start_nodes {
                queue.push_back(r);
                visited[r] = true;
            }

            while let Some(u) = queue.pop_front() {
                for &succ in &successors[u] {
                    let new_layer = layer_of[u] + 1;
                    if new_layer > layer_of[succ] {
                        layer_of[succ] = new_layer;
                    }
                    if !visited[succ] {
                        visited[succ] = true;
                        queue.push_back(succ);
                    }
                }
            }

            // Handle disconnected vertices
            for i in 0..n {
                if !visited[i] {
                    layer_of[i] = 0;
                }
            }

            // Group by layer
            let max_layer = layer_of.iter().copied().max().unwrap_or(0);
            let mut layers: Vec<Vec<usize>> = vec![Vec::new(); max_layer + 1];
            for i in 0..n {
                layers[layer_of[i]].push(i);
            }

            // Sort within each layer for determinism
            for layer in &mut layers {
                layer.sort();
            }

            layers
        }
        LayeringStrategy::NetworkSimplex | LayeringStrategy::CoffmanGraham => {
            // Fall back to longest path for simplicity
            assign_layers(ids, predecessors, successors, LayeringStrategy::LongestPath)
        }
    }
}

/// Reduce edge crossings by reordering vertices within layers.
fn reduce_crossings(
    layers: &[Vec<usize>],
    successors: &[Vec<usize>],
    predecessors: &[Vec<usize>],
    iterations: usize,
) -> Vec<Vec<usize>> {
    let mut result: Vec<Vec<usize>> = layers.to_vec();

    for _ in 0..iterations {
        // Down-sweep: order each layer based on predecessors in the layer above
        for i in 1..result.len() {
            let above = &result[i - 1];
            let pos_above: HashMap<usize, usize> =
                above.iter().enumerate().map(|(p, &v)| (v, p)).collect();

            result[i].sort_by_key(|&v| {
                let preds: Vec<usize> = predecessors[v]
                    .iter()
                    .filter_map(|p| pos_above.get(p).copied())
                    .collect();
                if preds.is_empty() {
                    usize::MAX / 2
                } else {
                    // Median of predecessor positions
                    median(&preds)
                }
            });
        }

        // Up-sweep: order each layer based on successors in the layer below
        for i in (0..result.len() - 1).rev() {
            let below = &result[i + 1];
            let pos_below: HashMap<usize, usize> =
                below.iter().enumerate().map(|(p, &v)| (v, p)).collect();

            result[i].sort_by_key(|&v| {
                let succs: Vec<usize> = successors[v]
                    .iter()
                    .filter_map(|s| pos_below.get(s).copied())
                    .collect();
                if succs.is_empty() {
                    usize::MAX / 2
                } else {
                    median(&succs)
                }
            });
        }
    }

    result
}

/// Compute the median of a sorted list.
fn median(values: &[usize]) -> usize {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted[sorted.len() / 2]
}

// ---------------------------------------------------------------------------
// Compact hierarchical layout (tidier tree)
// ---------------------------------------------------------------------------

/// A compact hierarchical layout that produces tighter tree layouts.
///
/// Based on the tidier tree algorithm. Vertices use fixed spacing
/// (50x50) instead of being sized based on labels, which avoids
/// excessive spacing for large labels.
pub struct CompactHierarchicalLayoutAlgorithm {
    pub horizontal_spacing: f64,
    pub vertical_spacing: f64,
}

impl CompactHierarchicalLayoutAlgorithm {
    pub fn new() -> Self {
        Self {
            horizontal_spacing: 50.0,
            vertical_spacing: 50.0,
        }
    }
}

impl Default for CompactHierarchicalLayoutAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

impl LayoutAlgorithm for CompactHierarchicalLayoutAlgorithm {
    fn name(&self) -> &str {
        COMPACT_HIERARCHICAL
    }

    fn compute_layout(
        &self,
        graph: &AttributedGraph,
        options: &GraphDisplayOptions,
    ) -> LayoutResult {
        // Delegate to hierarchical with compact spacing
        let algo = HierarchicalLayoutAlgorithm {
            horizontal_spacing: self.horizontal_spacing,
            vertical_spacing: self.vertical_spacing,
            layering: LayeringStrategy::LongestPath,
            crossing_iterations: 24,
        };
        algo.compute_layout(graph, options)
    }
}

// ---------------------------------------------------------------------------
// Force-directed layout (Fruchterman-Reingold style)
// ---------------------------------------------------------------------------

/// Force-directed layout algorithm.
///
/// Uses a spring-electron model: edges act as springs pulling connected
/// vertices together, and all vertex pairs repel each other. Iterates
/// until convergence.
pub struct ForceDirectedLayoutAlgorithm {
    /// Number of iterations.
    pub iterations: usize,
    /// Initial temperature (controls maximum displacement per step).
    pub initial_temperature: f64,
    /// Optimal distance between connected vertices.
    pub optimal_distance: f64,
}

impl ForceDirectedLayoutAlgorithm {
    pub fn new() -> Self {
        Self {
            iterations: 100,
            initial_temperature: 100.0,
            optimal_distance: 100.0,
        }
    }
}

impl Default for ForceDirectedLayoutAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

impl LayoutAlgorithm for ForceDirectedLayoutAlgorithm {
    fn name(&self) -> &str {
        FORCE_DIRECTED
    }

    fn compute_layout(
        &self,
        graph: &AttributedGraph,
        _options: &GraphDisplayOptions,
    ) -> LayoutResult {
        let ids: Vec<String> = graph.vertex_ids().map(|s| s.to_string()).collect();
        let n = ids.len();
        if n == 0 {
            return LayoutResult::new(HashMap::new());
        }

        let id_to_idx: HashMap<&str, usize> =
            ids.iter().enumerate().map(|(i, id)| (id.as_str(), i)).collect();

        // Initialize positions randomly on a circle
        let radius = (n as f64).sqrt() * self.optimal_distance;
        let mut px: Vec<f64> = Vec::with_capacity(n);
        let mut py: Vec<f64> = Vec::with_capacity(n);
        for i in 0..n {
            let angle = std::f64::consts::TAU * (i as f64) / (n as f64);
            px.push(radius * angle.cos());
            py.push(radius * angle.sin());
        }

        // Build edge list
        let edges: Vec<(usize, usize)> = graph
            .edges()
            .filter_map(|e| {
                let s = id_to_idx.get(e.source_id())?;
                let t = id_to_idx.get(e.target_id())?;
                Some((*s, *t))
            })
            .collect();

        // Iterative force computation
        let mut temperature = self.initial_temperature;
        let cooling = temperature / self.iterations as f64;

        for _iter in 0..self.iterations {
            let mut dx = vec![0.0f64; n];
            let mut dy = vec![0.0f64; n];

            // Repulsive forces between all pairs
            for i in 0..n {
                for j in (i + 1)..n {
                    let ddx = px[i] - px[j];
                    let ddy = py[i] - py[j];
                    let dist = (ddx * ddx + ddy * ddy).sqrt().max(1.0);
                    let force = (self.optimal_distance * self.optimal_distance) / dist;
                    let fx = (ddx / dist) * force;
                    let fy = (ddy / dist) * force;
                    dx[i] += fx;
                    dy[i] += fy;
                    dx[j] -= fx;
                    dy[j] -= fy;
                }
            }

            // Attractive forces along edges
            for &(i, j) in &edges {
                let ddx = px[i] - px[j];
                let ddy = py[i] - py[j];
                let dist = (ddx * ddx + ddy * ddy).sqrt().max(1.0);
                let force = (dist * dist) / self.optimal_distance;
                let fx = (ddx / dist) * force;
                let fy = (ddy / dist) * force;
                dx[i] -= fx;
                dy[i] -= fy;
                dx[j] += fx;
                dy[j] += fy;
            }

            // Apply displacement with temperature limit
            for i in 0..n {
                let disp = (dx[i] * dx[i] + dy[i] * dy[i]).sqrt();
                if disp > 0.0 {
                    let scale = disp.min(temperature) / disp;
                    px[i] += dx[i] * scale;
                    py[i] += dy[i] * scale;
                }
            }

            temperature -= cooling;
        }

        let mut positions = HashMap::new();
        for i in 0..n {
            positions.insert(ids[i].clone(), VertexPosition { x: px[i], y: py[i] });
        }

        LayoutResult::new(positions)
    }
}

// ---------------------------------------------------------------------------
// Layout algorithm registry
// ---------------------------------------------------------------------------

/// Create a layout algorithm by name.
///
/// Returns `None` if the name is not recognized.
pub fn create_layout_algorithm(name: &str) -> Option<Box<dyn LayoutAlgorithm>> {
    match name {
        COMPACT_HIERARCHICAL => Some(Box::new(CompactHierarchicalLayoutAlgorithm::new())),
        HIERARCHICAL => Some(Box::new(HierarchicalLayoutAlgorithm::new())),
        CIRCLE => Some(Box::new(CircularLayoutAlgorithm::new())),
        FORCE_DIRECTED | FORCED_BALANCED | GEM => {
            Some(Box::new(ForceDirectedLayoutAlgorithm::new()))
        }
        RADIAL | BALLOON => Some(Box::new(CircularLayoutAlgorithm::new())),
        MIN_CROSS_TOP_DOWN => Some(Box::new(HierarchicalLayoutAlgorithm::with_layering(
            LayeringStrategy::TopDown,
        ))),
        MIN_CROSS_LONGEST_PATH => Some(Box::new(HierarchicalLayoutAlgorithm::with_layering(
            LayeringStrategy::LongestPath,
        ))),
        MIN_CROSS_NETWORK_SIMPLEX => Some(Box::new(HierarchicalLayoutAlgorithm::with_layering(
            LayeringStrategy::NetworkSimplex,
        ))),
        MIN_CROSS_COFFMAN_GRAHAM => Some(Box::new(HierarchicalLayoutAlgorithm::with_layering(
            LayeringStrategy::CoffmanGraham,
        ))),
        _ => None,
    }
}

/// Get the default (initial) layout algorithm for general graph display.
pub fn default_layout_algorithm() -> Box<dyn LayoutAlgorithm> {
    Box::new(CompactHierarchicalLayoutAlgorithm::new())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphservices::attributed::{AttributedGraph, AttributedVertex};

    fn sample_diamond_graph() -> AttributedGraph {
        let mut g = AttributedGraph::new("test", "cfg");
        g.add_vertex(AttributedVertex::new("A", "Entry"));
        g.add_vertex(AttributedVertex::new("B", "Left"));
        g.add_vertex(AttributedVertex::new("C", "Right"));
        g.add_vertex(AttributedVertex::new("D", "Merge"));
        g.add_edge("A", "B", Some("true_branch".to_string()));
        g.add_edge("A", "C", Some("false_branch".to_string()));
        g.add_edge("B", "D", Some("fallthrough".to_string()));
        g.add_edge("C", "D", Some("fallthrough".to_string()));
        g
    }

    fn linear_graph() -> AttributedGraph {
        let mut g = AttributedGraph::new("linear", "cfg");
        g.add_vertex(AttributedVertex::new("A", "A"));
        g.add_vertex(AttributedVertex::new("B", "B"));
        g.add_vertex(AttributedVertex::new("C", "C"));
        g.add_edge("A", "B", None);
        g.add_edge("B", "C", None);
        g
    }

    #[test]
    fn test_circular_layout_positions() {
        let g = sample_diamond_graph();
        let opts = GraphDisplayOptions::default();
        let algo = CircularLayoutAlgorithm::new();
        let result = algo.compute_layout(&g, &opts);

        assert_eq!(result.positions.len(), 4);
        // All vertices should have different positions
        let mut pos_set: Vec<(i64, i64)> = result
            .positions
            .values()
            .map(|p| (p.x as i64, p.y as i64))
            .collect();
        pos_set.sort();
        pos_set.dedup();
        assert_eq!(pos_set.len(), 4);
    }

    #[test]
    fn test_circular_layout_custom_radius() {
        let g = sample_diamond_graph();
        let opts = GraphDisplayOptions::default();
        let algo = CircularLayoutAlgorithm::with_radius(200.0);
        let result = algo.compute_layout(&g, &opts);

        // All positions should be roughly 200 units from origin
        for pos in result.positions.values() {
            let dist = (pos.x * pos.x + pos.y * pos.y).sqrt();
            assert!((dist - 200.0).abs() < 1.0);
        }
    }

    #[test]
    fn test_hierarchical_layout_layers() {
        let g = linear_graph();
        let opts = GraphDisplayOptions::default();
        let algo = HierarchicalLayoutAlgorithm::new();
        let result = algo.compute_layout(&g, &opts);

        assert_eq!(result.positions.len(), 3);
        // A should be at y=0, B at y=1*spacing, C at y=2*spacing
        let a = result.position("A").unwrap();
        let b = result.position("B").unwrap();
        let c = result.position("C").unwrap();
        assert_eq!(a.y, 0.0);
        assert!(b.y > a.y);
        assert!(c.y > b.y);
    }

    #[test]
    fn test_hierarchical_diamond() {
        let g = sample_diamond_graph();
        let opts = GraphDisplayOptions::default();
        let algo = HierarchicalLayoutAlgorithm::new();
        let result = algo.compute_layout(&g, &opts);

        assert_eq!(result.positions.len(), 4);
        // B and C should be on the same layer
        let b = result.position("B").unwrap();
        let c = result.position("C").unwrap();
        assert_eq!(b.y, c.y);
    }

    #[test]
    fn test_force_directed_layout() {
        let g = sample_diamond_graph();
        let opts = GraphDisplayOptions::default();
        let algo = ForceDirectedLayoutAlgorithm::new();
        let result = algo.compute_layout(&g, &opts);

        assert_eq!(result.positions.len(), 4);
        // All positions should be finite
        for pos in result.positions.values() {
            assert!(pos.x.is_finite());
            assert!(pos.y.is_finite());
        }
    }

    #[test]
    fn test_empty_graph() {
        let g = AttributedGraph::new("empty", "cfg");
        let opts = GraphDisplayOptions::default();
        let algo = CircularLayoutAlgorithm::new();
        let result = algo.compute_layout(&g, &opts);
        assert!(result.positions.is_empty());
    }

    #[test]
    fn test_create_layout_algorithm_by_name() {
        assert!(create_layout_algorithm(CIRCLE).is_some());
        assert!(create_layout_algorithm(HIERARCHICAL).is_some());
        assert!(create_layout_algorithm(FORCE_DIRECTED).is_some());
        assert!(create_layout_algorithm("Nonexistent").is_none());
    }

    #[test]
    fn test_all_layout_names_are_creatable() {
        for &name in ALL_LAYOUT_NAMES {
            assert!(
                create_layout_algorithm(name).is_some(),
                "No algorithm for '{}'",
                name
            );
        }
    }

    #[test]
    fn test_default_algorithm() {
        let algo = default_layout_algorithm();
        assert_eq!(algo.name(), COMPACT_HIERARCHICAL);
    }

    #[test]
    fn test_layout_result_bounds() {
        let mut positions = HashMap::new();
        positions.insert("A".to_string(), VertexPosition { x: 0.0, y: 0.0 });
        positions.insert("B".to_string(), VertexPosition { x: 100.0, y: 50.0 });
        let result = LayoutResult::new(positions);
        assert_eq!(result.bounds, (0.0, 0.0, 100.0, 50.0));
    }

    #[test]
    fn test_layout_result_position_lookup() {
        let g = sample_diamond_graph();
        let opts = GraphDisplayOptions::default();
        let algo = CircularLayoutAlgorithm::new();
        let result = algo.compute_layout(&g, &opts);
        assert!(result.position("A").is_some());
        assert!(result.position("nonexistent").is_none());
    }

    #[test]
    fn test_hierarchical_top_down_layering() {
        let g = sample_diamond_graph();
        let opts = GraphDisplayOptions::default();
        let algo = HierarchicalLayoutAlgorithm::with_layering(LayeringStrategy::TopDown);
        let result = algo.compute_layout(&g, &opts);
        assert_eq!(result.positions.len(), 4);
    }

    #[test]
    fn test_compact_hierarchical_spacing() {
        let g = linear_graph();
        let opts = GraphDisplayOptions::default();
        let algo = CompactHierarchicalLayoutAlgorithm::new();
        let result = algo.compute_layout(&g, &opts);

        let a = result.position("A").unwrap();
        let b = result.position("B").unwrap();
        // Vertical spacing should be 50
        assert_eq!(b.y - a.y, 50.0);
    }

    #[test]
    fn test_layering_strategy_default() {
        assert_eq!(LayeringStrategy::default(), LayeringStrategy::LongestPath);
    }
}
