//! Port of `ScoreCaching` interface.
/// Trait porting `ScoreCaching`.
#[allow(dead_code)]
pub trait ScoreCaching: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
