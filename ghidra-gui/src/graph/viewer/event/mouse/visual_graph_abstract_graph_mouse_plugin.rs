//! Port of `VisualGraphAbstractGraphMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphAbstractGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphAbstractGraphMousePlugin {
    /// is_handling_mouse_events.
    pub is_handling_mouse_events: bool,
    /// selected_vertex.
    pub selected_vertex: String,
    /// selected_edge.
    pub selected_edge: String,
}

impl VisualGraphAbstractGraphMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for VisualGraphAbstractGraphMousePlugin {
    fn default() -> Self {
        Self {
            is_handling_mouse_events: false,
            selected_vertex: String::new(),
            selected_edge: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_abstract_graph_mouse_plugin_new() { let _ = VisualGraphAbstractGraphMousePlugin::new(); }
}
