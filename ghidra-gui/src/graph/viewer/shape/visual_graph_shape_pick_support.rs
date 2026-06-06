//! Port of `VisualGraphShapePickSupport`.
use std::collections::HashMap;
/// Struct porting `VisualGraphShapePickSupport`.
#[derive(Debug, Clone)]
pub struct VisualGraphShapePickSupport {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphShapePickSupport {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphShapePickSupport {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_shape_pick_support_new() { let _ = VisualGraphShapePickSupport::new(); }
}
