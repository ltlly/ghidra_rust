//! Port of `VisualGraphScrollWheelPanningPlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphScrollWheelPanningPlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphScrollWheelPanningPlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphScrollWheelPanningPlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphScrollWheelPanningPlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_scroll_wheel_panning_plugin_new() { let _ = VisualGraphScrollWheelPanningPlugin::new(); }
}
