//! Port of `VisualGraphSatelliteScalingGraphMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphSatelliteScalingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphSatelliteScalingGraphMousePlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphSatelliteScalingGraphMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphSatelliteScalingGraphMousePlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_satellite_scaling_graph_mouse_plugin_new() { let _ = VisualGraphSatelliteScalingGraphMousePlugin::new(); }
}
