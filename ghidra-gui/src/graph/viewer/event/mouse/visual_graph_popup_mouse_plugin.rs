//! Port of `VisualGraphPopupMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphPopupMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphPopupMousePlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphPopupMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphPopupMousePlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_popup_mouse_plugin_new() { let _ = VisualGraphPopupMousePlugin::new(); }
}
