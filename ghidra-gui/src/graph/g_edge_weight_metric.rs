//! Port of Ghidra's `ghidra.graph.GEdgeWeightMetric` interface.
//!
//! Provides a strategy for computing or retrieving edge weights in a graph.

use super::g_edge::GEdge;

/// A function object that computes the weight of an edge.
///
/// Mirrors Ghidra's `GEdgeWeightMetric<E>` which allows callers to plug
/// in different weighting strategies for the same graph (e.g., instruction
/// count, block size, edge frequency).
pub trait GEdgeWeightMetric<V, E: GEdge<V>>: Send + Sync + std::fmt::Debug {
    /// Compute the weight of the given edge.
    fn weight(&self, edge: &E) -> f64;
}

/// A constant weight metric -- every edge has weight 1.0.
#[derive(Debug, Clone, Default)]
pub struct UnitWeightMetric;

impl<V, E: GEdge<V>> GEdgeWeightMetric<V, E> for UnitWeightMetric {
    fn weight(&self, _edge: &E) -> f64 {
        1.0
    }
}

/// A weight metric that uses a stored per-edge weight.
#[derive(Debug, Clone)]
pub struct MapWeightMetric {
    weights: std::collections::HashMap<(usize, usize), f64>,
}

impl MapWeightMetric {
    /// Create an empty map metric.
    pub fn new() -> Self {
        Self { weights: std::collections::HashMap::new() }
    }

    /// Set the weight for a (from, to) edge pair.
    pub fn set(&mut self, from: usize, to: usize, weight: f64) {
        self.weights.insert((from, to), weight);
    }

    /// Get the stored weight for a (from, to) pair.
    pub fn get(&self, from: usize, to: usize) -> Option<f64> {
        self.weights.get(&(from, to)).copied()
    }
}

impl Default for MapWeightMetric {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestEdge { from: usize, to: usize }
    impl GEdge<usize> for TestEdge {
        fn start(&self) -> &usize { &self.from }
        fn end(&self) -> &usize { &self.to }
    }

    #[test]
    fn test_unit_metric() {
        let metric = UnitWeightMetric;
        let e = TestEdge { from: 0, to: 1 };
        assert_eq!(metric.weight(&e), 1.0);
    }

    #[test]
    fn test_map_metric() {
        let mut metric = MapWeightMetric::new();
        metric.set(0, 1, 5.0);
        assert_eq!(metric.get(0, 1), Some(5.0));
        assert_eq!(metric.get(1, 0), None);
    }
}
