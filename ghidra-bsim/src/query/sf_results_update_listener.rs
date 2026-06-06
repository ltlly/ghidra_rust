//! Port of `SFResultsUpdateListener` interface.
/// Trait porting `SFResultsUpdateListener`.
#[allow(dead_code)]
pub trait SFResultsUpdateListener: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
