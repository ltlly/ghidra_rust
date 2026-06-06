//! Port of `ClangHighlightListener` interface.
/// Trait porting `ClangHighlightListener`.
#[allow(dead_code)]
pub trait ClangHighlightListener: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
