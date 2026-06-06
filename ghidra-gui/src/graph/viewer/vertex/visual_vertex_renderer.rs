//! Port of `VisualVertexRenderer`.
use std::collections::HashMap;
/// Struct porting `VisualVertexRenderer`.
#[derive(Debug, Clone)]
pub struct VisualVertexRenderer {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualVertexRenderer {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualVertexRenderer {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_vertex_renderer_new() { let _ = VisualVertexRenderer::new(); }
}
