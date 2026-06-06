//! Port of `BSimValueEditor` interface.
/// Trait porting `BSimValueEditor`.
#[allow(dead_code)]
pub trait BSimValueEditor: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
