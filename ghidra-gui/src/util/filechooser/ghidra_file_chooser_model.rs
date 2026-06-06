//! Port of `GhidraFileChooserModel` interface.
/// Trait porting `GhidraFileChooserModel`.
#[allow(dead_code)]
pub trait GhidraFileChooserModel: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
