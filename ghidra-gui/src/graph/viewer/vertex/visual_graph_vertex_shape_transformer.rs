//! Port of `VisualGraphVertexShapeTransformer`.
use std::collections::HashMap;
/// Struct porting `VisualGraphVertexShapeTransformer`.
#[derive(Debug, Clone)]
pub struct VisualGraphVertexShapeTransformer {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphVertexShapeTransformer {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphVertexShapeTransformer {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_vertex_shape_transformer_new() { let _ = VisualGraphVertexShapeTransformer::new(); }
}
