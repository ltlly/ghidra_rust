//! Port of `VisualGraphLayout` interface.
/// Trait porting `VisualGraphLayout`.
#[allow(dead_code)]
pub trait VisualGraphLayout: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
