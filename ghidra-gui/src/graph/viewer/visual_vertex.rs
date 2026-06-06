//! Port of `VisualVertex` interface.
/// Trait porting `VisualVertex`.
#[allow(dead_code)]
pub trait VisualVertex: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
