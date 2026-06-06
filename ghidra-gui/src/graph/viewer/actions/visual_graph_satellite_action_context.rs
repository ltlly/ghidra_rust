//! Port of `VisualGraphSatelliteActionContext` interface.
/// Trait porting `VisualGraphSatelliteActionContext`.
#[allow(dead_code)]
pub trait VisualGraphSatelliteActionContext: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
