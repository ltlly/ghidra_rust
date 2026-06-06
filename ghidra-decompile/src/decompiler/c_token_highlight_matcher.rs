//! Port of `CTokenHighlightMatcher` interface.
/// Trait porting `CTokenHighlightMatcher`.
#[allow(dead_code)]
pub trait CTokenHighlightMatcher: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
