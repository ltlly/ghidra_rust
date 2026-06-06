//! Port of `AbstractVisualVertexRenderer`.
use std::collections::HashMap;
/// Struct porting `AbstractVisualVertexRenderer`.
#[derive(Debug, Clone)]
pub struct AbstractVisualVertexRenderer {
    _phantom: std::marker::PhantomData<()>,
}
impl AbstractVisualVertexRenderer {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for AbstractVisualVertexRenderer {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_abstract_visual_vertex_renderer_new() { let _ = AbstractVisualVertexRenderer::new(); }
}
