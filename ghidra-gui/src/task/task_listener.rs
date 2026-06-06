//! Port of `TaskListener` interface.
/// Trait porting `TaskListener`.
#[allow(dead_code)]
pub trait TaskListener: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
