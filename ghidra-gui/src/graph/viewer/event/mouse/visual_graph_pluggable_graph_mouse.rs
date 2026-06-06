//! Port of `VisualGraphPluggableGraphMouse`.
use std::collections::HashMap;
/// Struct porting `VisualGraphPluggableGraphMouse`.
#[derive(Debug, Clone)]
pub struct VisualGraphPluggableGraphMouse {
    /// mouse_plugins.
    pub mouse_plugins: String,
}

impl VisualGraphPluggableGraphMouse {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for VisualGraphPluggableGraphMouse {
    fn default() -> Self {
        Self {
            mouse_plugins: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_pluggable_graph_mouse_new() { let _ = VisualGraphPluggableGraphMouse::new(); }
}
