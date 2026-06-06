//! Port of `VertexTooltipProvider` interface.
/// Trait porting `VertexTooltipProvider`.
#[allow(dead_code)]
pub trait VertexTooltipProvider: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
