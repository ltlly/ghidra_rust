//! Port of `VertexClickListener` interface.
/// Trait porting `VertexClickListener`.
#[allow(dead_code)]
pub trait VertexClickListener: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
