//! Port of `VisualGraphActionContext` interface.
/// Trait porting `VisualGraphActionContext`.
#[allow(dead_code)]
pub trait VisualGraphActionContext: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
