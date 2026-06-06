//! Port of `VisualGraphContextMarker` interface.
/// Trait porting `VisualGraphContextMarker`.
#[allow(dead_code)]
pub trait VisualGraphContextMarker: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
