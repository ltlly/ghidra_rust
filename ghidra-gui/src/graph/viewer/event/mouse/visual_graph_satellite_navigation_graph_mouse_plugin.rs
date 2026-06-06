//! Port of `VisualGraphSatelliteNavigationGraphMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphSatelliteNavigationGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphSatelliteNavigationGraphMousePlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphSatelliteNavigationGraphMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphSatelliteNavigationGraphMousePlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_satellite_navigation_graph_mouse_plugin_new() { let _ = VisualGraphSatelliteNavigationGraphMousePlugin::new(); }
}
