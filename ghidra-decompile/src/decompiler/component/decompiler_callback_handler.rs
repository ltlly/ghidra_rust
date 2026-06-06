//! Port of `DecompilerCallbackHandler` interface.
/// Trait porting `DecompilerCallbackHandler`.
#[allow(dead_code)]
pub trait DecompilerCallbackHandler: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
