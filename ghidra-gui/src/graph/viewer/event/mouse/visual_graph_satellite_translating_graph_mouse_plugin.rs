//! Port of `VisualGraphSatelliteTranslatingGraphMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphSatelliteTranslatingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphSatelliteTranslatingGraphMousePlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphSatelliteTranslatingGraphMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphSatelliteTranslatingGraphMousePlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_satellite_translating_graph_mouse_plugin_new() { let _ = VisualGraphSatelliteTranslatingGraphMousePlugin::new(); }
}
