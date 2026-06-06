//! Port of `DecompilerHighlightService` interface.
/// Trait porting `DecompilerHighlightService`.
#[allow(dead_code)]
pub trait DecompilerHighlightService: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
