//! Port of `DecompilerLocation` interface.
/// Trait porting `DecompilerLocation`.
#[allow(dead_code)]
pub trait DecompilerLocation: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
