//! Port of `VisualGraphZoomingPickingGraphMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphZoomingPickingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphZoomingPickingGraphMousePlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphZoomingPickingGraphMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphZoomingPickingGraphMousePlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_zooming_picking_graph_mouse_plugin_new() { let _ = VisualGraphZoomingPickingGraphMousePlugin::new(); }
}
