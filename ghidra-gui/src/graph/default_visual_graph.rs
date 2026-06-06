//! Port of `DefaultVisualGraph`.
use std::collections::HashMap;
/// Struct porting `DefaultVisualGraph`.
#[derive(Debug, Clone)]
pub struct DefaultVisualGraph {
    /// focused_vertex.
    pub focused_vertex: String,
}

impl DefaultVisualGraph {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for DefaultVisualGraph {
    fn default() -> Self {
        Self {
            focused_vertex: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_default_visual_graph_new() { let _ = DefaultVisualGraph::new(); }
}
