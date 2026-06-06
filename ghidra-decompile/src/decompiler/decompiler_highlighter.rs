//! Port of `DecompilerHighlighter` interface.
/// Trait porting `DecompilerHighlighter`.
#[allow(dead_code)]
pub trait DecompilerHighlighter: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
