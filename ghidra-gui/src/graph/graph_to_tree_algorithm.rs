//! Port of `GraphToTreeAlgorithm`.
use std::collections::HashMap;
/// Struct porting `GraphToTreeAlgorithm`.
#[derive(Debug, Clone)]
pub struct GraphToTreeAlgorithm {
    _phantom: std::marker::PhantomData<()>,
}
impl GraphToTreeAlgorithm {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for GraphToTreeAlgorithm {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_graph_to_tree_algorithm_new() { let _ = GraphToTreeAlgorithm::new(); }
}
