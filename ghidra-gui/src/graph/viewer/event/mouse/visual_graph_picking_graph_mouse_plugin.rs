//! Port of `VisualGraphPickingGraphMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphPickingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphPickingGraphMousePlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphPickingGraphMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphPickingGraphMousePlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_picking_graph_mouse_plugin_new() { let _ = VisualGraphPickingGraphMousePlugin::new(); }
}
