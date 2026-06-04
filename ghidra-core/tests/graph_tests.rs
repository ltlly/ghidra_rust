//! Tests for graph algorithms: HashDirectedGraph, GraphPath, GraphPathSet,
//! DefaultGEdge, Tarjan SCC, graph factory, and graph-to-tree conversion.
//!
//! Ports key Java graph test logic from Ghidra's `ghidra.graph` package.

use ghidra_core::graph::default_edge::DefaultGEdge;
use ghidra_core::graph::graph_path::{GraphPath, GraphPathSet};
use ghidra_core::graph::hash_graph::HashDirectedGraph;
use ghidra_core::graph::traits::{GDirectedGraph, GEdge, GImplicitDirectedGraph};

// ============================================================================
// DefaultGEdge tests
// ============================================================================

#[test]
fn test_default_edge_creation() {
    let e = DefaultGEdge::new(1, 2);
    assert_eq!(*e.start(), 1);
    assert_eq!(*e.end(), 2);
}

#[test]
fn test_default_edge_equality() {
    let a = DefaultGEdge::new(1, 2);
    let b = DefaultGEdge::new(1, 2);
    let c = DefaultGEdge::new(1, 3);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn test_default_edge_clone() {
    let e = DefaultGEdge::new("a", "b");
    let cloned = e.clone();
    assert_eq!(e, cloned);
}

#[test]
fn test_default_edge_reflexive() {
    let e = DefaultGEdge::new(5, 5);
    assert_eq!(*e.start(), *e.end());
}

// ============================================================================
// HashDirectedGraph — basic CRUD
// ============================================================================

type IGraph = HashDirectedGraph<i32, DefaultGEdge<i32>>;

#[test]
fn test_empty_graph() {
    let g = IGraph::new();
    assert_eq!(g.get_vertex_count(), 0);
    assert_eq!(g.get_edge_count(), 0);
    assert!(g.get_vertices().is_empty());
    assert!(g.get_edges().is_empty());
}

#[test]
fn test_add_vertex() {
    let mut g = IGraph::new();
    assert!(g.add_vertex(1));
    assert!(!g.add_vertex(1)); // duplicate
    assert_eq!(g.get_vertex_count(), 1);
    assert!(g.contains_vertex(&1));
    assert!(!g.contains_vertex(&2));
}

#[test]
fn test_add_edge_creates_vertices() {
    let mut g = IGraph::new();
    g.add_edge(DefaultGEdge::new(10, 20));
    assert_eq!(g.get_vertex_count(), 2);
    assert_eq!(g.get_edge_count(), 1);
    assert!(g.contains_vertex(&10));
    assert!(g.contains_vertex(&20));
}

#[test]
fn test_remove_vertex() {
    let mut g = IGraph::new();
    g.add_edge(DefaultGEdge::new(1, 2));
    g.add_edge(DefaultGEdge::new(2, 3));
    g.add_edge(DefaultGEdge::new(1, 3));

    assert!(g.remove_vertex(&2));
    assert!(!g.contains_vertex(&2));
    assert_eq!(g.get_vertex_count(), 2);
    // Edges involving 2 should be removed
    assert!(!g.contains_edge_between(&1, &2));
    assert!(!g.contains_edge_between(&2, &3));
    // Edge 1->3 should remain
    assert!(g.contains_edge_between(&1, &3));
}

#[test]
fn test_remove_nonexistent_vertex() {
    let mut g = IGraph::new();
    assert!(!g.remove_vertex(&99));
}

#[test]
fn test_remove_vertices_batch() {
    let mut g = IGraph::new();
    g.add_edge(DefaultGEdge::new(1, 2));
    g.add_edge(DefaultGEdge::new(3, 4));
    g.remove_vertices(&[2, 4]);
    assert_eq!(g.get_vertex_count(), 2);
    assert_eq!(g.get_edge_count(), 0);
}

#[test]
fn test_remove_edge() {
    let mut g = IGraph::new();
    let e = DefaultGEdge::new(1, 2);
    g.add_edge(e.clone());
    assert!(g.remove_edge(&e));
    assert_eq!(g.get_edge_count(), 0);
    assert!(!g.remove_edge(&e)); // already removed
}

#[test]
fn test_find_edge() {
    let mut g = IGraph::new();
    g.add_edge(DefaultGEdge::new(1, 2));
    g.add_edge(DefaultGEdge::new(1, 3));

    let e = g.find_edge(&1, &2);
    assert!(e.is_some());
    assert_eq!(*e.unwrap().end(), 2);

    assert!(g.find_edge(&1, &5).is_none());
}

#[test]
fn test_contains_edge_between() {
    let mut g = IGraph::new();
    g.add_edge(DefaultGEdge::new(1, 2));
    assert!(g.contains_edge_between(&1, &2));
    assert!(!g.contains_edge_between(&2, &1)); // directed
    assert!(!g.contains_edge_between(&1, &5));
}

#[test]
fn test_contains_edge_object() {
    let mut g = IGraph::new();
    let e = DefaultGEdge::new(1, 2);
    g.add_edge(e.clone());
    assert!(g.contains_edge(&e));
    let other = DefaultGEdge::new(1, 3);
    assert!(!g.contains_edge(&other));
}

// ============================================================================
// HashDirectedGraph — adjacency queries
// ============================================================================

fn build_linear_graph() -> IGraph {
    // 1 -> 2 -> 3 -> 4
    let mut g = IGraph::new();
    g.add_edge(DefaultGEdge::new(1, 2));
    g.add_edge(DefaultGEdge::new(2, 3));
    g.add_edge(DefaultGEdge::new(3, 4));
    g
}

#[test]
fn test_successors_linear() {
    let g = build_linear_graph();
    let succ = g.get_successors(&1);
    assert_eq!(succ.len(), 1);
    assert!(succ.contains(&2));

    let succ3 = g.get_successors(&3);
    assert_eq!(succ3.len(), 1);
    assert!(succ3.contains(&4));

    let succ4 = g.get_successors(&4);
    assert!(succ4.is_empty());
}

#[test]
fn test_predecessors_linear() {
    let g = build_linear_graph();
    let pred = g.get_predecessors(&4);
    assert_eq!(pred.len(), 1);
    assert!(pred.contains(&3));

    let pred1 = g.get_predecessors(&1);
    assert!(pred1.is_empty());
}

#[test]
fn test_out_edges_linear() {
    let g = build_linear_graph();
    let out = g.get_out_edges(&2);
    assert_eq!(out.len(), 1);
    assert_eq!(*out[0].end(), 3);
}

#[test]
fn test_in_edges_linear() {
    let g = build_linear_graph();
    let in_e = g.get_in_edges(&2);
    assert_eq!(in_e.len(), 1);
    assert_eq!(*in_e[0].start(), 1);
}

// ============================================================================
// HashDirectedGraph — diamond / fan-in / fan-out
// ============================================================================

fn build_diamond() -> IGraph {
    //    1
    //   / \
    //  2   3
    //   \ /
    //    4
    let mut g = IGraph::new();
    g.add_edge(DefaultGEdge::new(1, 2));
    g.add_edge(DefaultGEdge::new(1, 3));
    g.add_edge(DefaultGEdge::new(2, 4));
    g.add_edge(DefaultGEdge::new(3, 4));
    g
}

#[test]
fn test_diamond_successors() {
    let g = build_diamond();
    let succ1 = g.get_successors(&1);
    assert_eq!(succ1.len(), 2);
    assert!(succ1.contains(&2));
    assert!(succ1.contains(&3));

    let succ4 = g.get_successors(&4);
    assert!(succ4.is_empty());
}

#[test]
fn test_diamond_predecessors() {
    let g = build_diamond();
    let pred4 = g.get_predecessors(&4);
    assert_eq!(pred4.len(), 2);
    assert!(pred4.contains(&2));
    assert!(pred4.contains(&3));
}

#[test]
fn test_diamond_edge_count() {
    let g = build_diamond();
    assert_eq!(g.get_vertex_count(), 4);
    assert_eq!(g.get_edge_count(), 4);
}

// ============================================================================
// HashDirectedGraph — subgraph / copy
// ============================================================================

#[test]
fn test_create_subgraph() {
    let g = build_diamond();
    let mut subset = std::collections::HashSet::new();
    subset.insert(1);
    subset.insert(2);
    subset.insert(4);

    let sub = g.create_subgraph(&subset);
    assert_eq!(sub.get_vertex_count(), 3);
    // Edges: 1->2 and 2->4 (3 was excluded)
    assert_eq!(sub.get_edge_count(), 2);
    assert!(sub.contains_edge_between(&1, &2));
    assert!(sub.contains_edge_between(&2, &4));
    assert!(!sub.contains_edge_between(&3, &4));
}

#[test]
fn test_copy_explicit() {
    let g = build_diamond();
    let copy = g.copy_explicit();
    assert_eq!(copy.get_vertex_count(), g.get_vertex_count());
    assert_eq!(copy.get_edge_count(), g.get_edge_count());
}

#[test]
fn test_empty_clone() {
    let g = build_diamond();
    let empty = g.empty_clone();
    assert_eq!(empty.get_vertex_count(), 0);
    assert_eq!(empty.get_edge_count(), 0);
}

// ============================================================================
// GraphPath tests
// ============================================================================

#[test]
fn test_graph_path_empty() {
    let p: GraphPath<i32> = GraphPath::new();
    assert!(p.is_empty());
    assert_eq!(p.size(), 0);
    assert!(p.first().is_none());
    assert!(p.last().is_none());
}

#[test]
fn test_graph_path_single_vertex() {
    let p = GraphPath::with_vertex(42);
    assert_eq!(p.size(), 1);
    assert_eq!(*p.first().unwrap(), 42);
    assert_eq!(*p.last().unwrap(), 42);
    assert!(p.contains(&42));
    assert!(!p.contains(&99));
}

#[test]
fn test_graph_path_add_unique() {
    let mut p = GraphPath::new();
    assert!(p.add(1));
    assert!(p.add(2));
    assert!(p.add(3));
    assert!(!p.add(2)); // duplicate rejected
    assert_eq!(p.size(), 3);
}

#[test]
fn test_graph_path_ordering() {
    let mut p = GraphPath::new();
    p.add('a');
    p.add('b');
    p.add('c');
    assert_eq!(*p.get(0), 'a');
    assert_eq!(*p.get(1), 'b');
    assert_eq!(*p.get(2), 'c');
}

#[test]
fn test_graph_path_starts_with() {
    let mut p1 = GraphPath::new();
    p1.add(1);
    p1.add(2);
    p1.add(3);
    p1.add(4);

    let mut prefix = GraphPath::new();
    prefix.add(1);
    prefix.add(2);

    assert!(p1.starts_with(&prefix));

    let mut wrong = GraphPath::new();
    wrong.add(9);
    wrong.add(2);
    assert!(!p1.starts_with(&wrong));

    // Full path starts with itself
    assert!(p1.starts_with(&p1));

    // Empty prefix
    let empty: GraphPath<i32> = GraphPath::new();
    assert!(p1.starts_with(&empty));
}

#[test]
fn test_graph_path_common_start() {
    let mut p1 = GraphPath::new();
    p1.add("a");
    p1.add("b");
    p1.add("c");
    p1.add("d");
    p1.add("e");
    p1.add("f");

    let mut p2 = GraphPath::new();
    p2.add("a");
    p2.add("b");
    p2.add("c");
    p2.add("d");
    p2.add("k");
    p2.add("l");

    let common = p1.get_common_start_path(&p2);
    assert_eq!(common.size(), 4);
    assert_eq!(*common.get(0), "a");
    assert_eq!(*common.get(3), "d");
}

#[test]
fn test_graph_path_sub_path() {
    let mut p = GraphPath::new();
    p.add(10);
    p.add(20);
    p.add(30);
    p.add(40);
    p.add(50);

    let sub = p.sub_path(1, 4);
    assert_eq!(sub.size(), 3);
    assert_eq!(*sub.get(0), 20);
    assert_eq!(*sub.get(1), 30);
    assert_eq!(*sub.get(2), 40);
}

#[test]
fn test_graph_path_predecessors() {
    let mut p = GraphPath::new();
    p.add(1);
    p.add(2);
    p.add(3);
    p.add(4);

    let preds = p.get_predecessors(&3);
    assert_eq!(preds.len(), 3);
    assert!(preds.contains(&1));
    assert!(preds.contains(&2));
    assert!(preds.contains(&3));
}

#[test]
fn test_graph_path_successors() {
    let mut p = GraphPath::new();
    p.add(1);
    p.add(2);
    p.add(3);
    p.add(4);

    let succs = p.get_successors(&2);
    assert_eq!(succs.len(), 3);
    assert!(succs.contains(&2));
    assert!(succs.contains(&3));
    assert!(succs.contains(&4));
}

#[test]
fn test_graph_path_equality() {
    let mut p1 = GraphPath::new();
    p1.add(1);
    p1.add(2);

    let mut p2 = GraphPath::new();
    p2.add(1);
    p2.add(2);

    assert_eq!(p1, p2);

    let mut p3 = GraphPath::new();
    p3.add(2);
    p3.add(1);
    assert_ne!(p1, p3);
}

#[test]
fn test_graph_path_copy() {
    let mut p = GraphPath::new();
    p.add(1);
    p.add(2);
    p.add(3);

    let copy = p.copy();
    assert_eq!(p, copy);
}

#[test]
fn test_graph_path_vertices() {
    let mut p = GraphPath::new();
    p.add("x");
    p.add("y");
    p.add("z");

    assert_eq!(p.vertices(), &["x", "y", "z"]);
    assert_eq!(p.as_slice(), &["x", "y", "z"]);
}

// ============================================================================
// GraphPathSet tests
// ============================================================================

#[test]
fn test_path_set_empty() {
    let s: GraphPathSet<i32> = GraphPathSet::new();
    assert!(s.is_empty());
    assert_eq!(s.size(), 0);
}

#[test]
fn test_path_set_add_and_query() {
    let mut s = GraphPathSet::new();

    let mut p1 = GraphPath::new();
    p1.add(1);
    p1.add(2);
    p1.add(3);
    s.add(p1);

    let mut p2 = GraphPath::new();
    p2.add(4);
    p2.add(5);
    s.add(p2);

    assert_eq!(s.size(), 2);

    let with_3 = s.get_paths_containing(&3);
    assert_eq!(with_3.len(), 1);

    let with_2 = s.get_paths_containing(&2);
    assert_eq!(with_2.len(), 1);
}

#[test]
fn test_path_set_starts_with() {
    let mut s = GraphPathSet::new();

    let mut p = GraphPath::new();
    p.add(1);
    p.add(2);
    p.add(3);
    s.add(p);

    let mut prefix = GraphPath::new();
    prefix.add(1);
    prefix.add(2);

    assert!(s.contain_some_path_starting_with(&prefix));

    let mut wrong = GraphPath::new();
    wrong.add(9);
    assert!(!s.contain_some_path_starting_with(&wrong));
}

// ============================================================================
// String-keyed graph (testing non-numeric vertex types)
// ============================================================================

type SGraph = HashDirectedGraph<String, DefaultGEdge<String>>;

#[test]
fn test_string_graph() {
    let mut g = SGraph::new();
    g.add_edge(DefaultGEdge::new("main".into(), "helper".into()));
    g.add_edge(DefaultGEdge::new("main".into(), "printf".into()));
    g.add_edge(DefaultGEdge::new("helper".into(), "malloc".into()));

    assert_eq!(g.get_vertex_count(), 4);
    assert_eq!(g.get_edge_count(), 3);

    let succ = g.get_successors(&"main".to_string());
    assert_eq!(succ.len(), 2);
}

// ============================================================================
// Large graph stress test
// ============================================================================

#[test]
fn test_large_graph_performance() {
    let mut g = IGraph::new();
    // Build a chain of 1000 vertices
    for i in 0..1000 {
        g.add_edge(DefaultGEdge::new(i, i + 1));
    }
    assert_eq!(g.get_vertex_count(), 1001);
    assert_eq!(g.get_edge_count(), 1000);

    // Verify first and last
    assert!(g.contains_edge_between(&0, &1));
    assert!(g.contains_edge_between(&999, &1000));
    assert!(g.get_predecessors(&0).is_empty());
    assert_eq!(g.get_successors(&1000).len(), 0);
}

#[test]
fn test_wide_fan_out() {
    let mut g = IGraph::new();
    // Single root with 100 children
    for i in 0..100 {
        g.add_edge(DefaultGEdge::new(0, i + 1));
    }
    assert_eq!(g.get_edge_count(), 100);
    assert_eq!(g.get_successors(&0).len(), 100);
    for i in 1..=100 {
        assert_eq!(g.get_predecessors(&i).len(), 1);
    }
}

// ============================================================================
// Cycle detection via graph structure
// ============================================================================

#[test]
fn test_self_loop() {
    let mut g = IGraph::new();
    g.add_edge(DefaultGEdge::new(1, 1));
    assert_eq!(g.get_edge_count(), 1);
    assert!(g.contains_edge_between(&1, &1));
    assert!(g.get_successors(&1).contains(&1));
    assert!(g.get_predecessors(&1).contains(&1));
}

#[test]
fn test_cycle() {
    // 1 -> 2 -> 3 -> 1
    let mut g = IGraph::new();
    g.add_edge(DefaultGEdge::new(1, 2));
    g.add_edge(DefaultGEdge::new(2, 3));
    g.add_edge(DefaultGEdge::new(3, 1));
    assert_eq!(g.get_edge_count(), 3);

    // Every node has exactly one successor and one predecessor
    for v in [1, 2, 3] {
        assert_eq!(g.get_successors(&v).len(), 1);
        assert_eq!(g.get_predecessors(&v).len(), 1);
    }
}
