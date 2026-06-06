//! Integration tests for graph algorithm modules ported from Ghidra.
//!
//! Covers: Dijkstra, Tarjan SCC, Dominance, Johnson Circuits,
//! FindPaths, and GraphToTree algorithms.

use ghidra_gui::graph::{
    DefaultDirectedGraph, DefaultGEdge, GDirectedGraph, GWeightedEdge,
    algo::{
        dijkstra::Dijkstra,
        tarjan::TarjanScc,
        dominance::DominanceAlgorithm,
        johnson::JohnsonCircuits,
        find_paths::FindPaths,
        graph_to_tree::GraphToTree,
    },
};

// ============================================================================
// Helpers
// ============================================================================

type IEdge = DefaultGEdge<i32>;
type IGraph = DefaultDirectedGraph<i32, IEdge>;
type WEdge = GWeightedEdge<i32>;
type WGraph = DefaultDirectedGraph<i32, WEdge>;

fn make_diamond() -> IGraph {
    //   1 -> 2
    //   1 -> 3
    //   2 -> 4
    //   3 -> 4
    let mut g = IGraph::new();
    g.add_edge(IEdge::new(1, 2));
    g.add_edge(IEdge::new(1, 3));
    g.add_edge(IEdge::new(2, 4));
    g.add_edge(IEdge::new(3, 4));
    g
}

fn make_cycle() -> IGraph {
    // 1 -> 2 -> 3 -> 1
    let mut g = IGraph::new();
    g.add_edge(IEdge::new(1, 2));
    g.add_edge(IEdge::new(2, 3));
    g.add_edge(IEdge::new(3, 1));
    g
}

fn make_chain() -> IGraph {
    // 1 -> 2 -> 3 -> 4
    let mut g = IGraph::new();
    g.add_edge(IEdge::new(1, 2));
    g.add_edge(IEdge::new(2, 3));
    g.add_edge(IEdge::new(3, 4));
    g
}

fn make_weighted_graph() -> WGraph {
    //   1 --(1.0)--> 2 --(2.0)--> 4
    //   1 --(4.0)--> 3 --(1.0)--> 4
    //   2 --(1.0)--> 3
    let mut g = WGraph::new();
    g.add_edge(WEdge::new(1, 2, 1.0));
    g.add_edge(WEdge::new(1, 3, 4.0));
    g.add_edge(WEdge::new(2, 3, 1.0));
    g.add_edge(WEdge::new(2, 4, 2.0));
    g.add_edge(WEdge::new(3, 4, 1.0));
    g
}

// ============================================================================
// Dijkstra tests
// ============================================================================

#[test]
fn test_dijkstra_source_distance_is_zero() {
    let g = make_weighted_graph();
    let result = Dijkstra::shortest_paths(&g, &1);
    assert_eq!(result.distance(&1), Some(0.0));
}

#[test]
fn test_dijkstra_shortest_path_simple() {
    let g = make_weighted_graph();
    let result = Dijkstra::shortest_paths(&g, &1);
    // 1->2->4 = 1+2 = 3.0 (same cost as 1->2->3->4 = 1+1+1 = 3.0)
    // Dijkstra picks 1->2->4 as shortest (fewer hops).
    assert_eq!(result.distance(&4), Some(3.0));
    let path = result.path_to(&4).unwrap();
    assert_eq!(path, vec![1, 2, 4]);
}

#[test]
fn test_dijkstra_direct_edge() {
    let g = make_weighted_graph();
    let result = Dijkstra::shortest_paths(&g, &1);
    assert_eq!(result.distance(&2), Some(1.0));
    let path = result.path_to(&2).unwrap();
    assert_eq!(path, vec![1, 2]);
}

#[test]
fn test_dijkstra_unreachable_vertex() {
    let mut g = WGraph::new();
    g.add_edge(WEdge::new(1, 2, 1.0));
    g.add_vertex(99); // disconnected
    let result = Dijkstra::shortest_paths(&g, &1);
    assert_eq!(result.distance(&99), None);
    assert!(result.path_to(&99).is_none());
}

#[test]
fn test_dijkstra_single_vertex() {
    let mut g = WGraph::new();
    g.add_vertex(42);
    let result = Dijkstra::shortest_paths(&g, &42);
    assert_eq!(result.distance(&42), Some(0.0));
    assert_eq!(result.path_to(&42), Some(vec![42]));
}

#[test]
fn test_dijkstra_result_clone() {
    let g = make_weighted_graph();
    let result = Dijkstra::shortest_paths(&g, &1);
    let cloned = result.clone();
    assert_eq!(cloned.distance(&4), result.distance(&4));
}

// ============================================================================
// Tarjan SCC tests
// ============================================================================

#[test]
fn test_tarjan_single_cycle() {
    let g = make_cycle();
    let sccs = TarjanScc::compute(&g);
    assert_eq!(sccs.len(), 1);
    let scc = &sccs[0];
    assert!(scc.contains(&1));
    assert!(scc.contains(&2));
    assert!(scc.contains(&3));
}

#[test]
fn test_tarjan_chain_gives_singletons() {
    let g = make_chain();
    let sccs = TarjanScc::compute(&g);
    assert_eq!(sccs.len(), 4);
    for scc in &sccs {
        assert_eq!(scc.len(), 1);
    }
}

#[test]
fn test_tarjan_diamond() {
    let g = make_diamond();
    let sccs = TarjanScc::compute(&g);
    // Diamond is a DAG, so all SCCs are singletons.
    assert_eq!(sccs.len(), 4);
}

#[test]
fn test_tarjan_two_cycles() {
    // 1->2->3->1  and  4->5->4
    let mut g = IGraph::new();
    g.add_edge(IEdge::new(1, 2));
    g.add_edge(IEdge::new(2, 3));
    g.add_edge(IEdge::new(3, 1));
    g.add_edge(IEdge::new(4, 5));
    g.add_edge(IEdge::new(5, 4));
    let sccs = TarjanScc::compute(&g);
    assert_eq!(sccs.len(), 2);
    let sizes: Vec<usize> = sccs.iter().map(|s| s.len()).collect();
    assert!(sizes.contains(&3));
    assert!(sizes.contains(&2));
}

#[test]
fn test_tarjan_single_vertex() {
    let mut g = IGraph::new();
    g.add_vertex(1);
    let sccs = TarjanScc::compute(&g);
    assert_eq!(sccs.len(), 1);
    assert!(sccs[0].contains(&1));
}

// ============================================================================
// Dominance tests
// ============================================================================

#[test]
fn test_dominance_entry_dominates_all() {
    let g = make_chain();
    let result = DominanceAlgorithm::compute_dominators(&g, &1);
    // In a chain 1->2->3->4, 1 dominates all.
    for v in [1, 2, 3, 4] {
        assert!(result.dominates(&1, &v), "entry should dominate {}", v);
    }
}

#[test]
fn test_dominance_entry_idom_none() {
    let g = make_chain();
    let result = DominanceAlgorithm::compute_dominators(&g, &1);
    assert!(result.immediate_dominator(&1).is_none());
}

#[test]
fn test_dominance_chain_idom() {
    let g = make_chain();
    let result = DominanceAlgorithm::compute_dominators(&g, &1);
    assert_eq!(result.immediate_dominator(&2), Some(&1));
    assert_eq!(result.immediate_dominator(&3), Some(&2));
    assert_eq!(result.immediate_dominator(&4), Some(&3));
}

#[test]
fn test_dominance_diamond_idom() {
    let g = make_diamond();
    let result = DominanceAlgorithm::compute_dominators(&g, &1);
    // In diamond 1->{2,3}->4, 1 is the immediate dominator of 2,3,4.
    assert_eq!(result.immediate_dominator(&2), Some(&1));
    assert_eq!(result.immediate_dominator(&3), Some(&1));
    assert_eq!(result.immediate_dominator(&4), Some(&1));
}

#[test]
fn test_dominance_diamond_dominates() {
    let g = make_diamond();
    let result = DominanceAlgorithm::compute_dominators(&g, &1);
    assert!(result.dominates(&1, &4));
    // 2 does NOT dominate 4 (path 1->3->4 avoids 2).
    assert!(!result.dominates(&2, &4));
}

#[test]
fn test_post_dominance_chain() {
    let g = make_chain();
    let result = DominanceAlgorithm::compute_post_dominators(&g, &4);
    // 4 post-dominates all in a chain.
    for v in [1, 2, 3, 4] {
        assert!(result.dominates(&4, &v), "exit should post-dominate {}", v);
    }
}

// ============================================================================
// Johnson Circuits tests
// ============================================================================

#[test]
fn test_johnson_no_cycles_in_dag() {
    let g = make_diamond();
    let circuits = JohnsonCircuits::find_circuits(&g);
    assert!(circuits.is_empty());
}

#[test]
fn test_johnson_single_cycle() {
    let g = make_cycle();
    let circuits = JohnsonCircuits::find_circuits(&g);
    assert_eq!(circuits.len(), 1);
    // Cycle should contain all 3 vertices.
    let cycle = &circuits[0];
    assert_eq!(cycle.len(), 4); // includes start repeated at end
    assert_eq!(cycle[0], cycle[cycle.len() - 1]);
}

#[test]
fn test_johnson_two_simple_cycles() {
    // 1->2->1  and  3->4->5->3
    let mut g = IGraph::new();
    g.add_edge(IEdge::new(1, 2));
    g.add_edge(IEdge::new(2, 1));
    g.add_edge(IEdge::new(3, 4));
    g.add_edge(IEdge::new(4, 5));
    g.add_edge(IEdge::new(5, 3));
    let circuits = JohnsonCircuits::find_circuits(&g);
    assert_eq!(circuits.len(), 2);
}

#[test]
fn test_johnson_empty_graph() {
    let g = IGraph::new();
    let circuits = JohnsonCircuits::find_circuits(&g);
    assert!(circuits.is_empty());
}

// ============================================================================
// FindPaths tests
// ============================================================================

#[test]
fn test_find_paths_all_paths_diamond() {
    let g = make_diamond();
    let paths = FindPaths::all_paths(&g, &1, &4);
    // Two paths: 1->2->4 and 1->3->4
    assert_eq!(paths.len(), 2);
}

#[test]
fn test_find_paths_single_path_chain() {
    let g = make_chain();
    let paths = FindPaths::all_paths(&g, &1, &4);
    assert_eq!(paths.len(), 1);
}

#[test]
fn test_find_paths_no_path() {
    let mut g = IGraph::new();
    g.add_edge(IEdge::new(1, 2));
    g.add_edge(IEdge::new(3, 4));
    let paths = FindPaths::all_paths(&g, &1, &4);
    assert!(paths.is_empty());
}

#[test]
fn test_find_paths_same_start_end() {
    let g = make_chain();
    let path = FindPaths::shortest_path(&g, &1, &1);
    assert!(path.is_some());
    assert!(path.unwrap().is_empty());
}

#[test]
fn test_find_paths_shortest_path_chain() {
    let g = make_chain();
    let path = FindPaths::shortest_path(&g, &1, &4);
    assert!(path.is_some());
    let p = path.unwrap();
    assert_eq!(p.len(), 3);
}

#[test]
fn test_find_paths_is_reachable() {
    let g = make_diamond();
    assert!(FindPaths::is_reachable(&g, &1, &4));
    assert!(!FindPaths::is_reachable(&g, &4, &1));
}

#[test]
fn test_find_paths_shortest_path_none_for_unreachable() {
    let mut g = IGraph::new();
    g.add_edge(IEdge::new(1, 2));
    g.add_vertex(99);
    assert!(FindPaths::shortest_path(&g, &1, &99).is_none());
}

// ============================================================================
// GraphToTree tests
// ============================================================================

#[test]
fn test_graph_to_tree_simple_chain() {
    let g = make_chain();
    let tree = GraphToTree::convert(&g, &1);
    assert_eq!(tree.vertex_count(), 4);
    assert_eq!(tree.edge_count(), 3);
    // Should be a tree.
    assert!(GraphToTree::is_tree(&tree, &1));
}

#[test]
fn test_graph_to_tree_diamond() {
    let g = make_diamond();
    let tree = GraphToTree::convert(&g, &1);
    // BFS from 1: 1->2, 1->3, then 2->4 (not 3->4 because 4 already visited)
    assert_eq!(tree.vertex_count(), 4);
    assert_eq!(tree.edge_count(), 3);
    assert!(GraphToTree::is_tree(&tree, &1));
}

#[test]
fn test_graph_to_tree_disconnected() {
    let mut g = IGraph::new();
    g.add_edge(IEdge::new(1, 2));
    g.add_edge(IEdge::new(3, 4));
    let tree = GraphToTree::convert(&g, &1);
    // Only reachable vertices included.
    assert_eq!(tree.vertex_count(), 2);
    assert!(tree.contains_vertex(&1));
    assert!(tree.contains_vertex(&2));
    assert!(!tree.contains_vertex(&3));
}

#[test]
fn test_graph_to_tree_single_vertex() {
    let mut g = IGraph::new();
    g.add_vertex(42);
    let tree = GraphToTree::convert(&g, &42);
    assert_eq!(tree.vertex_count(), 1);
    assert_eq!(tree.edge_count(), 0);
}

#[test]
fn test_graph_to_tree_edges() {
    let g = make_chain();
    let edges = GraphToTree::tree_edges(&g, &1);
    assert_eq!(edges.len(), 3);
}

#[test]
fn test_graph_to_tree_is_tree_true_for_tree() {
    let mut g = IGraph::new();
    g.add_edge(IEdge::new(1, 2));
    g.add_edge(IEdge::new(1, 3));
    g.add_edge(IEdge::new(2, 4));
    assert!(GraphToTree::is_tree(&g, &1));
}

#[test]
fn test_graph_to_tree_is_tree_false_for_diamond() {
    let g = make_diamond();
    // Node 4 has in-degree 2, so not a tree.
    assert!(!GraphToTree::is_tree(&g, &1));
}
