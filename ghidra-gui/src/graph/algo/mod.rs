//! Graph algorithms.
//!
//! Ports Ghidra's `ghidra.graph.algo` package, including:
//!
//! - [`TarjanScc`] — Tarjan's strongly-connected-components algorithm
//! - [`DepthFirstSorter`] — DFS-based topological and post-order sorting
//! - [`Dijkstra`] — Dijkstra's single-source shortest-paths algorithm
//! - [`JohnsonCircuits`] — Johnson's algorithm for finding all elementary circuits
//! - [`FindPaths`] — Find all paths between two vertices
//! - [`DominanceAlgorithm`] — Dominator / post-dominator computation
//! - [`GraphToTree`] — Convert a graph into a spanning tree

pub mod dominance;
pub mod dijkstra;
pub mod find_paths;
pub mod johnson;
pub mod tarjan;
pub mod dfs_sorter;
pub mod graph_to_tree;

// New modules ported from Ghidra's graph algo package
pub mod recursive_find_paths;
pub mod sorter_exception;
pub mod status_listener;

pub use dominance::{DominanceAlgorithm, DominatorResult};
pub use dijkstra::Dijkstra;
pub use find_paths::FindPaths;
pub use johnson::JohnsonCircuits;
pub use tarjan::TarjanScc;
pub use dfs_sorter::{DepthFirstSorter, SortOrder};
pub use graph_to_tree::GraphToTree;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DefaultDirectedGraph, DefaultGEdge, GDirectedGraph};

    type E = DefaultGEdge<char>;
    type G = DefaultDirectedGraph<char, E>;

    fn make_cycle_graph() -> G {
        let mut g = G::new();
        g.add_edge(E::new('a', 'b'));
        g.add_edge(E::new('b', 'c'));
        g.add_edge(E::new('c', 'a'));
        g.add_edge(E::new('c', 'd'));
        g
    }

    fn make_dag() -> G {
        // a -> b -> d
        // a -> c -> d
        let mut g = G::new();
        g.add_edge(E::new('a', 'b'));
        g.add_edge(E::new('a', 'c'));
        g.add_edge(E::new('b', 'd'));
        g.add_edge(E::new('c', 'd'));
        g
    }

    #[test]
    fn tarjan_finds_cycle_scc() {
        let g = make_cycle_graph();
        let scc = TarjanScc::compute(&g);
        // {a,b,c} is one SCC; {d} is its own
        let big = scc.iter().find(|s| s.len() > 1).expect("should have non-trivial SCC");
        assert!(big.contains(&'a'));
        assert!(big.contains(&'b'));
        assert!(big.contains(&'c'));
    }

    #[test]
    fn tarjan_dag_all_singletons() {
        let g = make_dag();
        let scc = TarjanScc::compute(&g);
        for component in &scc {
            assert_eq!(component.len(), 1);
        }
    }

    #[test]
    fn dfs_post_order_dag() {
        let g = make_dag();
        let order = DepthFirstSorter::sort_from(&g, SortOrder::PostOrder, &['a']);
        // 'd' must appear before 'b' and 'c', which must appear before 'a'
        let pos = |c: char| order.iter().position(|&x| x == c).unwrap();
        assert!(pos('d') < pos('b'));
        assert!(pos('d') < pos('c'));
        assert!(pos('b') < pos('a'));
        assert!(pos('c') < pos('a'));
    }

    #[test]
    fn dfs_pre_order_dag() {
        let g = make_dag();
        let order = DepthFirstSorter::sort_from(&g, SortOrder::PreOrder, &['a']);
        let pos = |c: char| order.iter().position(|&x| x == c).unwrap();
        assert!(pos('a') < pos('b'));
        assert!(pos('a') < pos('c'));
    }

    #[test]
    fn dijkstra_shortest_path() {
        let mut g = DefaultDirectedGraph::<char, GWeightedEdge<char>>::new();
        use crate::graph::GWeightedEdge;
        g.add_edge(GWeightedEdge::new('a', 'b', 1.0));
        g.add_edge(GWeightedEdge::new('a', 'c', 5.0));
        g.add_edge(GWeightedEdge::new('b', 'c', 2.0));
        g.add_edge(GWeightedEdge::new('c', 'd', 1.0));

        let result = Dijkstra::shortest_paths(&g, &'a');
        assert_eq!(result.distance(&'b'), Some(1.0));
        assert_eq!(result.distance(&'c'), Some(3.0)); // a->b->c
        assert_eq!(result.distance(&'d'), Some(4.0)); // a->b->c->d
    }

    #[test]
    fn find_paths_simple() {
        let g = make_dag();
        let paths = FindPaths::all_paths(&g, &'a', &'d');
        assert_eq!(paths.len(), 2); // a->b->d, a->c->d
    }

    #[test]
    fn graph_to_tree_basic() {
        let g = make_dag();
        let tree = GraphToTree::convert(&g, &'a');
        // Should have 3 edges (a->b, a->c, b->d or c->d -- spanning tree)
        assert_eq!(tree.edge_count(), 3);
        assert_eq!(tree.vertex_count(), 4);
    }

    #[test]
    fn dominance_simple() {
        let g = make_dag();
        let result = DominanceAlgorithm::compute_dominators(&g, &'a');
        // Every node is dominated by 'a'
        for v in &['b', 'c', 'd'] {
            assert!(result.dominators(v).contains(&'a'), "{} should be dominated by a", v);
        }
    }

    #[test]
    fn johnson_no_cycles_in_dag() {
        let g = make_dag();
        let circuits = JohnsonCircuits::find_circuits(&g);
        assert!(circuits.is_empty(), "DAG should have no circuits");
    }

    #[test]
    fn johnson_finds_cycle() {
        let g = make_cycle_graph();
        let circuits = JohnsonCircuits::find_circuits(&g);
        assert!(!circuits.is_empty(), "cycle graph should have circuits");
    }
}
