//! Port of `GraphPath`.
use std::collections::HashMap;
/// Struct porting `GraphPath`.
#[derive(Debug, Clone)]
pub struct GraphPath {
    _phantom: std::marker::PhantomData<()>,
}
impl GraphPath {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for GraphPath {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_graph_path_new() { let _ = GraphPath::new(); }
}
