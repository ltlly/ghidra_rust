//! Port of `VisualGraphMousePlugin` interface.
/// Trait porting `VisualGraphMousePlugin`.
#[allow(dead_code)]
pub trait VisualGraphMousePlugin: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
