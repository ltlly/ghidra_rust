//! Port of `GraphJob` interface.
/// Trait porting `GraphJob`.
#[allow(dead_code)]
pub trait GraphJob: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
