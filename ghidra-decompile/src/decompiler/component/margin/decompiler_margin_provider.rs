//! Port of `DecompilerMarginProvider` interface.
/// Trait porting `DecompilerMarginProvider`.
#[allow(dead_code)]
pub trait DecompilerMarginProvider: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
