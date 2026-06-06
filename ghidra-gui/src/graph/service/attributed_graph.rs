//! Port of `AttributedGraph`.
use std::collections::HashMap;
/// Struct porting `AttributedGraph`.
#[derive(Debug, Clone)]
pub struct AttributedGraph {
    /// weight.
    pub weight: String,
}

impl AttributedGraph {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for AttributedGraph {
    fn default() -> Self {
        Self {
            weight: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_attributed_graph_new() { let _ = AttributedGraph::new(); }
}
