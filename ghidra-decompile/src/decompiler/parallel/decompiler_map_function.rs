//! Port of `DecompilerMapFunction` interface.
/// Trait porting `DecompilerMapFunction`.
#[allow(dead_code)]
pub trait DecompilerMapFunction: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
