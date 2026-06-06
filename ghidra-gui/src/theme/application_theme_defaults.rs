//! Port of `ApplicationThemeDefaults` interface.
/// Trait porting `ApplicationThemeDefaults`.
#[allow(dead_code)]
pub trait ApplicationThemeDefaults: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
