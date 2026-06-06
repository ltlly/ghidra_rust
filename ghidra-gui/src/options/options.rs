//! Port of `Options` interface.
/// Trait porting `Options`.
#[allow(dead_code)]
pub trait Options: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
