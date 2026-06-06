//! Port of `VisualEdgeArrowRenderingSupport`.
use std::collections::HashMap;
/// Struct porting `VisualEdgeArrowRenderingSupport`.
#[derive(Debug, Clone)]
pub struct VisualEdgeArrowRenderingSupport {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualEdgeArrowRenderingSupport {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualEdgeArrowRenderingSupport {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_edge_arrow_rendering_support_new() { let _ = VisualEdgeArrowRenderingSupport::new(); }
}
