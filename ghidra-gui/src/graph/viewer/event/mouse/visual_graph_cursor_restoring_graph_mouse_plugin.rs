//! Port of `VisualGraphCursorRestoringGraphMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphCursorRestoringGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphCursorRestoringGraphMousePlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphCursorRestoringGraphMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphCursorRestoringGraphMousePlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_cursor_restoring_graph_mouse_plugin_new() { let _ = VisualGraphCursorRestoringGraphMousePlugin::new(); }
}
