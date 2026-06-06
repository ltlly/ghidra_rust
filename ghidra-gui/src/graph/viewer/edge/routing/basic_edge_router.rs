//! Port of `BasicEdgeRouter`.
use std::collections::HashMap;
/// Struct porting `BasicEdgeRouter`.
#[derive(Debug, Clone)]
pub struct BasicEdgeRouter {
    /// edges.
    pub edges: String,
}

impl BasicEdgeRouter {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for BasicEdgeRouter {
    fn default() -> Self {
        Self {
            edges: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_basic_edge_router_new() { let _ = BasicEdgeRouter::new(); }
}
