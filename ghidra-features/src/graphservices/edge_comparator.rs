//! Edge comparator for prioritized edge ordering in graph layouts.
//!
//! Ported from Ghidra's `ghidra.graph.visualization.EdgeComparator` Java class.
//!
//! Compares edges based on their type priority as defined in the
//! `GraphDisplayOptions`. Edges with lower priority numbers come first.
//! This is used by layout algorithms to determine edge routing order.

use std::cmp::Ordering;

use super::attributed::AttributedEdge;
use super::display_options::GraphDisplayOptions;

/// Comparator that orders edges by their type priority.
///
/// Priority is determined by [`GraphDisplayOptions::get_edge_priority`].
/// Lower priority numbers come first. Edges with no defined priority
/// are sorted to the end.
///
/// This is the Rust equivalent of Ghidra's `EdgeComparator` class.
#[derive(Debug)]
pub struct EdgeComparator {
    /// Copy of edge priorities for fast lookup.
    priorities: std::collections::HashMap<String, i32>,
}

impl EdgeComparator {
    /// Create a new edge comparator from display options.
    pub fn new(options: &GraphDisplayOptions) -> Self {
        // Pre-collect all known priorities from the options.
        // Since GraphDisplayOptions stores them internally, we build
        // a lookup by testing known edge types.
        let known_types = [
            "fallthrough",
            "conditional_branch",
            "unconditional_branch",
            "branch",
            "call",
            "return",
            "indirect",
            "jump",
            "true_branch",
            "false_branch",
        ];

        let mut priorities = std::collections::HashMap::new();
        for etype in &known_types {
            let p = options.get_edge_priority(etype);
            if p != i32::MAX {
                priorities.insert(etype.to_string(), p);
            }
        }

        Self { priorities }
    }

    /// Get the priority for an edge type.
    ///
    /// Returns `i32::MAX` for unknown edge types (sorted last).
    pub fn get_priority(&self, edge_type: &str) -> i32 {
        self.priorities
            .get(edge_type)
            .copied()
            .unwrap_or(i32::MAX)
    }

    /// Compare two edges by their type priority.
    ///
    /// Returns `Ordering::Less` if `a` has higher priority (lower number)
    /// than `b`. Null edge types sort last.
    pub fn compare(&self, a: &AttributedEdge, b: &AttributedEdge) -> Ordering {
        let pa = match a.edge_type() {
            Some(t) => self.get_priority(t),
            None => i32::MAX,
        };
        let pb = match b.edge_type() {
            Some(t) => self.get_priority(t),
            None => i32::MAX,
        };
        pa.cmp(&pb)
    }

    /// Sort a mutable slice of edges by their type priority.
    pub fn sort_edges(&self, edges: &mut [AttributedEdge]) {
        edges.sort_by(|a, b| self.compare(a, b));
    }
}

/// Compare two edges using a reference to display options (stateless version).
///
/// This is a convenience function for one-off comparisons without
/// pre-building a comparator.
pub fn compare_edges(
    a: &AttributedEdge,
    b: &AttributedEdge,
    options: &GraphDisplayOptions,
) -> Ordering {
    let comparator = EdgeComparator::new(options);
    comparator.compare(a, b)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphservices::attributed::AttributedEdge;
    use crate::graphservices::display_options::cfg_display_options;

    fn edge(id: &str, etype: &str) -> AttributedEdge {
        AttributedEdge::new(id, "A", "B", Some(etype.to_string()))
    }

    #[test]
    fn test_compare_same_type() {
        let opts = cfg_display_options();
        let cmp = EdgeComparator::new(&opts);
        let a = edge("e1", "fallthrough");
        let b = edge("e2", "fallthrough");
        assert_eq!(cmp.compare(&a, &b), Ordering::Equal);
    }

    #[test]
    fn test_compare_different_priorities() {
        let opts = cfg_display_options();
        let cmp = EdgeComparator::new(&opts);
        let ft = edge("e1", "fallthrough");
        let call = edge("e2", "call");
        assert_eq!(cmp.compare(&ft, &call), Ordering::Less);
        assert_eq!(cmp.compare(&call, &ft), Ordering::Greater);
    }

    #[test]
    fn test_null_type_sorts_last() {
        let opts = cfg_display_options();
        let cmp = EdgeComparator::new(&opts);
        let with_type = edge("e1", "fallthrough");
        let no_type = AttributedEdge::new("e2", "A", "B", None);
        assert_eq!(cmp.compare(&with_type, &no_type), Ordering::Less);
    }

    #[test]
    fn test_sort_edges() {
        let opts = cfg_display_options();
        let cmp = EdgeComparator::new(&opts);

        let mut edges = vec![
            edge("e3", "return"),
            edge("e1", "fallthrough"),
            edge("e2", "call"),
            edge("e4", "conditional_branch"),
        ];

        cmp.sort_edges(&mut edges);

        assert_eq!(edges[0].edge_type(), Some("fallthrough"));
        assert_eq!(edges[1].edge_type(), Some("conditional_branch"));
        assert_eq!(edges[2].edge_type(), Some("call"));
        assert_eq!(edges[3].edge_type(), Some("return"));
    }

    #[test]
    fn test_unknown_type_priority() {
        let opts = cfg_display_options();
        let cmp = EdgeComparator::new(&opts);
        assert_eq!(cmp.get_priority("unknown_type"), i32::MAX);
    }

    #[test]
    fn test_convenience_function() {
        let opts = cfg_display_options();
        let a = edge("e1", "fallthrough");
        let b = edge("e2", "call");
        assert_eq!(compare_edges(&a, &b, &opts), Ordering::Less);
    }
}
