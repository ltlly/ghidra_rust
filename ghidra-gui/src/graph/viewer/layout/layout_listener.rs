//! Port of `LayoutListener` interface.
/// Trait porting `LayoutListener`.
#[allow(dead_code)]
pub trait LayoutListener: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
