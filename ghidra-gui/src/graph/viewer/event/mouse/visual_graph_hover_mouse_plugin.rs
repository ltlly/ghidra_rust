//! Port of `VisualGraphHoverMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphHoverMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphHoverMousePlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphHoverMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphHoverMousePlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_hover_mouse_plugin_new() { let _ = VisualGraphHoverMousePlugin::new(); }
}
