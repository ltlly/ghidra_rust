//! Port of `ColorProvider` interface.
/// Trait porting `ColorProvider`.
#[allow(dead_code)]
pub trait ColorProvider: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
