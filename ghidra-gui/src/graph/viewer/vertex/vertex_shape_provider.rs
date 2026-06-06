//! Port of `VertexShapeProvider` interface.
/// Trait porting `VertexShapeProvider`.
#[allow(dead_code)]
pub trait VertexShapeProvider: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
