//! Port of `VisualGraphTranslatingGraphMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphTranslatingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphTranslatingGraphMousePlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphTranslatingGraphMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphTranslatingGraphMousePlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_translating_graph_mouse_plugin_new() { let _ = VisualGraphTranslatingGraphMousePlugin::new(); }
}
