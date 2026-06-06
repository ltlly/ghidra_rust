//! Port of `VertexFocusListener` interface.
/// Trait porting `VertexFocusListener`.
#[allow(dead_code)]
pub trait VertexFocusListener: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
