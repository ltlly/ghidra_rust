//! Port of `GDirectedGraph` interface.
/// Trait porting `GDirectedGraph`.
#[allow(dead_code)]
pub trait GDirectedGraph: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
