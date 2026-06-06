//! Port of `VisualGraphVertexActionContext` interface.
/// Trait porting `VisualGraphVertexActionContext`.
#[allow(dead_code)]
pub trait VisualGraphVertexActionContext: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
