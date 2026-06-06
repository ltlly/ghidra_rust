//! Port of `BSimSearchService` interface.
/// Trait porting `BSimSearchService`.
#[allow(dead_code)]
pub trait BSimSearchService: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
