//! Port of `TrackedTaskListener` interface.
/// Trait porting `TrackedTaskListener`.
#[allow(dead_code)]
pub trait TrackedTaskListener: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
