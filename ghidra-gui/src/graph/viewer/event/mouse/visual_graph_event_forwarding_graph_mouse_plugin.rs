//! Port of `VisualGraphEventForwardingGraphMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphEventForwardingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphEventForwardingGraphMousePlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphEventForwardingGraphMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphEventForwardingGraphMousePlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_event_forwarding_graph_mouse_plugin_new() { let _ = VisualGraphEventForwardingGraphMousePlugin::new(); }
}
