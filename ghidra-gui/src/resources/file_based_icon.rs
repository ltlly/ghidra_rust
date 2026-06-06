//! Port of `FileBasedIcon` interface.
/// Trait porting `FileBasedIcon`.
#[allow(dead_code)]
pub trait FileBasedIcon: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
