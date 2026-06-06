//! Port of `OptionsChangeListener` interface.
/// Trait porting `OptionsChangeListener`.
#[allow(dead_code)]
pub trait OptionsChangeListener: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
