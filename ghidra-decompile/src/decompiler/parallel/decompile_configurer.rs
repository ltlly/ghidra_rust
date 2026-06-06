//! Port of `DecompileConfigurer` interface.
/// Trait porting `DecompileConfigurer`.
#[allow(dead_code)]
pub trait DecompileConfigurer: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
