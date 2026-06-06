//! Port of `ThemeListener` interface.
/// Trait porting `ThemeListener`.
#[allow(dead_code)]
pub trait ThemeListener: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
