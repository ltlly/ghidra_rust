//! Default empty graph type with no vertex or edge types.
//!
//! Ports `ghidra.service.graph.EmptyGraphType`.

use super::GraphType;

/// Create a default GraphType with no defined vertex or edge types.
///
/// Ports `ghidra.service.graph.EmptyGraphType`.
pub fn empty_graph_type() -> GraphType {
    GraphType::new("Empty Graph Type", "Graph type with no defined vertex or edge types")
}

/// Check if a graph type is an empty graph type (no vertex types defined).
pub fn is_empty_graph_type(gt: &GraphType) -> bool {
    gt.vertex_types.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_graph_type() {
        let gt = empty_graph_type();
        assert_eq!(gt.name, "Empty Graph Type");
        assert!(gt.vertex_types.is_empty());
    }

    #[test]
    fn test_is_empty() {
        let gt = empty_graph_type();
        assert!(is_empty_graph_type(&gt));

        let mut gt2 = GraphType::new("cfg", "CFG");
        gt2.add_vertex_type("basic_block");
        assert!(!is_empty_graph_type(&gt2));
    }
}
