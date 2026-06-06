//! Port of `GImplicitDirectedGraph` interface.
/// Trait porting `GImplicitDirectedGraph`.
#[allow(dead_code)]
pub trait GImplicitDirectedGraph: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
