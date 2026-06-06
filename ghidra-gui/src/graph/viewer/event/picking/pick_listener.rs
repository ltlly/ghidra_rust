//! Port of `PickListener` interface.
/// Trait porting `PickListener`.
#[allow(dead_code)]
pub trait PickListener: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
