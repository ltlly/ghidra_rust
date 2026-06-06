//! Port of `GEdgeWeightMetric` interface.
/// Trait porting `GEdgeWeightMetric`.
#[allow(dead_code)]
pub trait GEdgeWeightMetric: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
