//! Port of `SwingRunnable` interface.
/// Trait porting `SwingRunnable`.
#[allow(dead_code)]
pub trait SwingRunnable: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
