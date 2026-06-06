//! Port of `VisualGraphSatelliteGraphMouse`.
use std::collections::HashMap;
/// Struct porting `VisualGraphSatelliteGraphMouse`.
#[derive(Debug, Clone)]
pub struct VisualGraphSatelliteGraphMouse {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphSatelliteGraphMouse {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphSatelliteGraphMouse {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_satellite_graph_mouse_new() { let _ = VisualGraphSatelliteGraphMouse::new(); }
}
