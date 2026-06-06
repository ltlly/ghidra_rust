//! Port of `DecompilerReducer` interface.
/// Trait porting `DecompilerReducer`.
#[allow(dead_code)]
pub trait DecompilerReducer: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
