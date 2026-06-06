//! Port of `VisualGraphPathHighlighter`.
use std::collections::HashMap;
/// Struct porting `VisualGraphPathHighlighter`.
#[derive(Debug, Clone)]
pub struct VisualGraphPathHighlighter {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphPathHighlighter {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphPathHighlighter {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_path_highlighter_new() { let _ = VisualGraphPathHighlighter::new(); }
}
