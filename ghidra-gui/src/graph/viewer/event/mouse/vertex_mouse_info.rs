//! Port of `VertexMouseInfo`.
use std::collections::HashMap;
/// Struct porting `VertexMouseInfo`.
#[derive(Debug, Clone)]
pub struct VertexMouseInfo {
    _phantom: std::marker::PhantomData<()>,
}
impl VertexMouseInfo {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VertexMouseInfo {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vertex_mouse_info_new() { let _ = VertexMouseInfo::new(); }
}
