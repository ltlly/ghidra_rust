//! Port of `LayoutProviderExtensionPoint` interface.
/// Trait porting `LayoutProviderExtensionPoint`.
#[allow(dead_code)]
pub trait LayoutProviderExtensionPoint: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
