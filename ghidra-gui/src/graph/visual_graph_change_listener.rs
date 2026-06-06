//! Port of `VisualGraphChangeListener` interface.
/// Trait porting `VisualGraphChangeListener`.
#[allow(dead_code)]
pub trait VisualGraphChangeListener: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
