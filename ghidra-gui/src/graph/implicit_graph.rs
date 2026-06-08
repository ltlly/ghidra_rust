//! Implicit directed graph: edges are computed on the fly.
//!
//! Ports `ghidra.graph.GImplicitDirectedGraph`.

use std::collections::HashSet;
use std::hash::Hash;


/// A directed graph where edges are derived from a function rather than stored.
///
/// Useful when the graph structure is too large to enumerate eagerly or when
/// edges are computed dynamically (e.g., control-flow edges computed from
/// a block successor function).
pub trait GImplicitDirectedGraph<V: Eq + Hash + Clone> {
    /// Get the successors of a vertex.
    fn successors(&self, v: &V) -> Vec<V>;

    /// Get the predecessors of a vertex.
    fn predecessors(&self, v: &V) -> Vec<V>;

    /// All vertices in the graph (may be expensive).
    fn vertices(&self) -> Vec<V>;

    /// Whether the graph contains the vertex.
    fn contains_vertex(&self, v: &V) -> bool;
}

/// Compute the transitive closure of successors from a start vertex.
pub fn transitive_successors<V, G>(graph: &G, start: &V) -> HashSet<V>
where
    V: Eq + Hash + Clone,
    G: GImplicitDirectedGraph<V>,
{
    let mut visited = HashSet::new();
    let mut stack = vec![start.clone()];
    visited.insert(start.clone());

    while let Some(current) = stack.pop() {
        for succ in graph.successors(&current) {
            if visited.insert(succ.clone()) {
                stack.push(succ);
            }
        }
    }

    visited
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct TestImplicitGraph {
        edges: HashMap<i32, Vec<i32>>,
    }

    impl GImplicitDirectedGraph<i32> for TestImplicitGraph {
        fn successors(&self, v: &i32) -> Vec<i32> {
            self.edges.get(v).cloned().unwrap_or_default()
        }

        fn predecessors(&self, v: &i32) -> Vec<i32> {
            self.edges
                .iter()
                .filter(|(_, succs)| succs.contains(v))
                .map(|(&k, _)| k)
                .collect()
        }

        fn vertices(&self) -> Vec<i32> {
            self.edges.keys().copied().collect()
        }

        fn contains_vertex(&self, v: &i32) -> bool {
            self.edges.contains_key(v)
        }
    }

    #[test]
    fn test_transitive_successors() {
        let graph = TestImplicitGraph {
            edges: vec![(1, vec![2, 3]), (2, vec![4]), (3, vec![4]), (4, vec![])]
                .into_iter()
                .collect(),
        };
        let reachable = transitive_successors(&graph, &1);
        assert!(reachable.contains(&1));
        assert!(reachable.contains(&2));
        assert!(reachable.contains(&3));
        assert!(reachable.contains(&4));
        assert_eq!(reachable.len(), 4);
    }

    #[test]
    fn test_transitive_successors_single() {
        let graph = TestImplicitGraph {
            edges: vec![(1, vec![])].into_iter().collect(),
        };
        let reachable = transitive_successors(&graph, &1);
        assert_eq!(reachable.len(), 1);
    }
}
