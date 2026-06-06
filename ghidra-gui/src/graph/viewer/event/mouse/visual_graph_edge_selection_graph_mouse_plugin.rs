//! Port of `VisualGraphEdgeSelectionGraphMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphEdgeSelectionGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphEdgeSelectionGraphMousePlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphEdgeSelectionGraphMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphEdgeSelectionGraphMousePlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_edge_selection_graph_mouse_plugin_new() { let _ = VisualGraphEdgeSelectionGraphMousePlugin::new(); }
}
