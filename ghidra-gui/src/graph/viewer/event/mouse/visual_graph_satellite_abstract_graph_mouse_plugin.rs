//! Port of `VisualGraphSatelliteAbstractGraphMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphSatelliteAbstractGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphSatelliteAbstractGraphMousePlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphSatelliteAbstractGraphMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphSatelliteAbstractGraphMousePlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_satellite_abstract_graph_mouse_plugin_new() { let _ = VisualGraphSatelliteAbstractGraphMousePlugin::new(); }
}
