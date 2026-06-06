//! Port of `StatementSupplier` interface.
/// Trait porting `StatementSupplier`.
#[allow(dead_code)]
pub trait StatementSupplier: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
