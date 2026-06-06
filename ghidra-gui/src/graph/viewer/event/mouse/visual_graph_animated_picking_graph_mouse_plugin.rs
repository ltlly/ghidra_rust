//! Port of `VisualGraphAnimatedPickingGraphMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphAnimatedPickingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphAnimatedPickingGraphMousePlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphAnimatedPickingGraphMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphAnimatedPickingGraphMousePlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_animated_picking_graph_mouse_plugin_new() { let _ = VisualGraphAnimatedPickingGraphMousePlugin::new(); }
}
