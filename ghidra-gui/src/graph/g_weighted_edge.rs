//! Port of `GWeightedEdge` interface.
/// Trait porting `GWeightedEdge`.
#[allow(dead_code)]
pub trait GWeightedEdge: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
