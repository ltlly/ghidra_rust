//! Port of `PathHighlighterWorkPauser` interface.
/// Trait porting `PathHighlighterWorkPauser`.
#[allow(dead_code)]
pub trait PathHighlighterWorkPauser: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
