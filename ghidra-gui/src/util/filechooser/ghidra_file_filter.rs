//! Port of `GhidraFileFilter` interface.
/// Trait porting `GhidraFileFilter`.
#[allow(dead_code)]
pub trait GhidraFileFilter: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
