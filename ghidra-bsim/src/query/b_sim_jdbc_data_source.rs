//! Port of `BSimJDBCDataSource` interface.
/// Trait porting `BSimJDBCDataSource`.
#[allow(dead_code)]
pub trait BSimJDBCDataSource: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
