//! Port of `JungDirectedGraph`.
use std::collections::HashMap;
/// Struct porting `JungDirectedGraph`.
#[derive(Debug, Clone)]
pub struct JungDirectedGraph {
    _phantom: std::marker::PhantomData<()>,
}
impl JungDirectedGraph {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for JungDirectedGraph {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_jung_directed_graph_new() { let _ = JungDirectedGraph::new(); }
}
