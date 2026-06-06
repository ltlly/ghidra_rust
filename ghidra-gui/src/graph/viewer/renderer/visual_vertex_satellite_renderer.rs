//! Port of `VisualVertexSatelliteRenderer`.
use std::collections::HashMap;
/// Struct porting `VisualVertexSatelliteRenderer`.
#[derive(Debug, Clone)]
pub struct VisualVertexSatelliteRenderer {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualVertexSatelliteRenderer {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualVertexSatelliteRenderer {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_vertex_satellite_renderer_new() { let _ = VisualVertexSatelliteRenderer::new(); }
}
