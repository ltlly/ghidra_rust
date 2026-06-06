//! Port of `GraphPerspectiveInfo`.
use std::collections::HashMap;
/// Struct porting `GraphPerspectiveInfo`.
#[derive(Debug, Clone)]
pub struct GraphPerspectiveInfo {
    _phantom: std::marker::PhantomData<()>,
}
impl GraphPerspectiveInfo {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for GraphPerspectiveInfo {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_graph_perspective_info_new() { let _ = GraphPerspectiveInfo::new(); }
}
