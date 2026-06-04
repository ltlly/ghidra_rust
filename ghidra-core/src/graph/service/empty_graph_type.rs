//! Port of `ghidra.service.graph.EmptyGraphType`.
//!
//! A default graph type used when no specific type is needed.

use super::graph_type::GraphType;

/// An empty graph type used as a default.
///
/// Mirrors `ghidra.service.graph.EmptyGraphType`.
pub struct EmptyGraphType;

impl EmptyGraphType {
    /// Create the empty graph type.
    pub fn create() -> GraphType {
        GraphType::new("EmptyGraphType", "Empty Graph")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_graph_type() {
        let gt = EmptyGraphType::create();
        assert_eq!(gt.id(), "EmptyGraphType");
        assert_eq!(gt.name(), "Empty Graph");
    }
}
