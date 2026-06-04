//! Edge weight metric for computing edge weights.
//!
//! Port of `ghidra.graph.GEdgeWeightMetric<E>`.

use super::traits::GWeightedEdge;

/// A function object that computes a weight for a given edge.
///
/// Mirrors `ghidra.graph.GEdgeWeightMetric<E>`.
pub trait GEdgeWeightMetric<E> {
    /// Compute the weight of the given edge.
    fn compute_weight(&self, edge: &E) -> f64;
}

/// The natural weight metric: uses `GWeightedEdge::weight()` if available,
/// or returns 1.0 as a default.
///
/// Mirrors the Java `GEdgeWeightMetric.naturalMetric()`.
pub struct NaturalWeightMetric;

impl<E> GEdgeWeightMetric<E> for NaturalWeightMetric {
    fn compute_weight(&self, _edge: &E) -> f64 {
        // In the Java version, this casts to GWeightedEdge and calls getWeight().
        // In Rust, we cannot downcast trait objects, so the user should provide
        // a typed metric when edges are GWeightedEdge.
        1.0
    }
}

/// A weight metric that always returns a constant weight.
pub struct ConstantWeightMetric {
    weight: f64,
}

impl ConstantWeightMetric {
    /// Create a metric that always returns the given constant weight.
    pub fn new(weight: f64) -> Self {
        Self { weight }
    }
}

impl<E> GEdgeWeightMetric<E> for ConstantWeightMetric {
    fn compute_weight(&self, _edge: &E) -> f64 {
        self.weight
    }
}

/// A weight metric for edges implementing [`GWeightedEdge`].
///
/// Due to Rust's type system, this cannot be implemented as a blanket impl.
/// Users should create a concrete wrapper for their specific edge type.
pub struct WeightedEdgeMetric<F: Fn(&E) -> f64, E> {
    weight_fn: F,
    _phantom: std::marker::PhantomData<E>,
}

impl<F: Fn(&E) -> f64, E> WeightedEdgeMetric<F, E> {
    /// Create a weighted edge metric from a weight extraction function.
    pub fn new(weight_fn: F) -> Self {
        Self {
            weight_fn,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Fn(&E) -> f64, E> GEdgeWeightMetric<E> for WeightedEdgeMetric<F, E> {
    fn compute_weight(&self, edge: &E) -> f64 {
        (self.weight_fn)(edge)
    }
}
