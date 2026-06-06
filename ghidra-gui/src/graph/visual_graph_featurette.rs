//! Port of `VisualGraphFeaturette` interface.
/// Trait porting `VisualGraphFeaturette`.
#[allow(dead_code)]
pub trait VisualGraphFeaturette: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
