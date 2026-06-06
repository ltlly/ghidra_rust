//! Port of `GGlassPanePainter` interface.
/// Trait porting `GGlassPanePainter`.
#[allow(dead_code)]
pub trait GGlassPanePainter: Send + Sync {
    /// Marker method.
    fn as_any(&self) -> &dyn std::any::Any;
}
