//! Port of `BSimServerManagerListener` interface.
/// Trait porting `BSimServerManagerListener`.
#[allow(dead_code)]
pub trait BSimServerManagerListener: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
