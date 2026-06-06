//! Port of `VisualGraphEdgeSatelliteRenderer`.
use std::collections::HashMap;
/// Struct porting `VisualGraphEdgeSatelliteRenderer`.
#[derive(Debug, Clone)]
pub struct VisualGraphEdgeSatelliteRenderer {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphEdgeSatelliteRenderer {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphEdgeSatelliteRenderer {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_edge_satellite_renderer_new() { let _ = VisualGraphEdgeSatelliteRenderer::new(); }
}
