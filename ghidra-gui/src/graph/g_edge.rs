//! Port of `GEdge` interface.
/// Trait porting `GEdge`.
#[allow(dead_code)]
pub trait GEdge: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
