//! Port of `FindPathsAlgorithm` interface.
/// Trait porting `FindPathsAlgorithm`.
#[allow(dead_code)]
pub trait FindPathsAlgorithm: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
