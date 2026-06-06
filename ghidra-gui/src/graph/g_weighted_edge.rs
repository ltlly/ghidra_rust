//! Port of Ghidra's `ghidra.graph.GWeightedEdge` interface.
//!
//! Extends the basic edge concept with a numeric weight.

use super::g_edge::GEdge;

/// An edge with an associated numeric weight.
///
/// Extends `GEdge<V>` with a `weight()` accessor. Used by weighted-graph
/// algorithms (Dijkstra, minimum spanning tree, etc.).
pub trait GWeightedEdge<V>: GEdge<V> {
    /// Return the weight of this edge.
    fn weight(&self) -> f64;
}

/// A simple weighted edge implementation.
#[derive(Debug, Clone)]
pub struct WeightedEdge<V: Send + Sync + std::fmt::Debug> {
    from: V,
    to: V,
    w: f64,
}

impl<V: Send + Sync + std::fmt::Debug> WeightedEdge<V> {
    /// Create a new weighted edge.
    pub fn new(from: V, to: V, weight: f64) -> Self {
        Self { from, to, w: weight }
    }
}

impl<V: Send + Sync + std::fmt::Debug> GEdge<V> for WeightedEdge<V> {
    fn start(&self) -> &V { &self.from }
    fn end(&self) -> &V { &self.to }
}

impl<V: Send + Sync + std::fmt::Debug> GWeightedEdge<V> for WeightedEdge<V> {
    fn weight(&self) -> f64 { self.w }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weighted_edge() {
        let e = WeightedEdge::new(0usize, 1usize, 3.5);
        assert_eq!(*e.start(), 0);
        assert_eq!(*e.end(), 1);
        assert!((e.weight() - 3.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_weighted_edge_zero() {
        let e = WeightedEdge::new("a", "b", 0.0);
        assert_eq!(e.weight(), 0.0);
    }
}
