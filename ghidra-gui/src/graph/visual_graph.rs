//! Port of `VisualGraph` interface.
/// Trait porting `VisualGraph`.
#[allow(dead_code)]
pub trait VisualGraph: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
