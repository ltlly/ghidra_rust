//! Port of `GraphSatelliteListener` interface.
/// Trait porting `GraphSatelliteListener`.
#[allow(dead_code)]
pub trait GraphSatelliteListener: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
