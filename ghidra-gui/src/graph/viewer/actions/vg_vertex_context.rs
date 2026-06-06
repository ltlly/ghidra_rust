//! Port of `VgVertexContext`.
use std::collections::HashMap;
/// Struct porting `VgVertexContext`.
#[derive(Debug, Clone)]
pub struct VgVertexContext {
    _phantom: std::marker::PhantomData<()>,
}
impl VgVertexContext {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VgVertexContext {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vg_vertex_context_new() { let _ = VgVertexContext::new(); }
}
