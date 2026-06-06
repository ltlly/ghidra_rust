//! Port of `DecompilerMarginService` interface.
/// Trait porting `DecompilerMarginService`.
#[allow(dead_code)]
pub trait DecompilerMarginService: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
