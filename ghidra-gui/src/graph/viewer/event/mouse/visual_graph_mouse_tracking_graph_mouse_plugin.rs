//! Port of `VisualGraphMouseTrackingGraphMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphMouseTrackingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphMouseTrackingGraphMousePlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphMouseTrackingGraphMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphMouseTrackingGraphMousePlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_mouse_tracking_graph_mouse_plugin_new() { let _ = VisualGraphMouseTrackingGraphMousePlugin::new(); }
}
