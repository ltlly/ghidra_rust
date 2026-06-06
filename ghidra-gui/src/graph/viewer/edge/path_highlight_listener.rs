//! Port of `PathHighlightListener` interface.
/// Trait porting `PathHighlightListener`.
#[allow(dead_code)]
pub trait PathHighlightListener: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
