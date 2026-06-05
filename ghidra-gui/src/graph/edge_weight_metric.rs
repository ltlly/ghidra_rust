//! Edge weight metric trait.
//!
//! Ports `ghidra.graph.GEdgeWeightMetric`.

use std::hash::Hash;

use super::GEdge;

/// A function that computes a numeric weight for an edge.
///
/// Ports `ghidra.graph.GEdgeWeightMetric`.
pub trait GEdgeWeightMetric<V: Eq + Hash + Clone, E: GEdge<V>> {
    /// Compute the weight for the given edge.
    fn weight(&self, edge: &E) -> f64;
}

/// A constant-weight metric (all edges have the same weight).
pub struct ConstantWeightMetric {
    weight: f64,
}

impl ConstantWeightMetric {
    /// Create a metric with the given constant weight.
    pub fn new(weight: f64) -> Self {
        Self { weight }
    }
}

impl<V: Eq + Hash + Clone, E: GEdge<V>> GEdgeWeightMetric<V, E> for ConstantWeightMetric {
    fn weight(&self, _edge: &E) -> f64 {
        self.weight
    }
}

/// A metric based on hop count (all edges have weight 1.0).
pub struct HopCountMetric;

impl<V: Eq + Hash + Clone, E: GEdge<V>> GEdgeWeightMetric<V, E> for HopCountMetric {
    fn weight(&self, _edge: &E) -> f64 {
        1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::DefaultGEdge;

    #[test]
    fn test_constant_weight() {
        let metric = ConstantWeightMetric::new(5.0);
        let edge = DefaultGEdge::new(1, 2);
        assert_eq!(metric.weight(&edge), 5.0);
    }

    #[test]
    fn test_hop_count() {
        let metric = HopCountMetric;
        let edge = DefaultGEdge::new(1, 2);
        assert_eq!(metric.weight(&edge), 1.0);
    }
}
