//! Port of `VisualEdge` interface.
/// Trait porting `VisualEdge`.
#[allow(dead_code)]
pub trait VisualEdge: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
