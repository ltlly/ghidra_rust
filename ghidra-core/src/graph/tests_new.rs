//! Tests for the generic graph framework ported from Ghidra's Java code.

#[cfg(test)]
mod tests {
    use crate::graph::default_edge::DefaultGEdge;
    use crate::graph::traits::{GDirectedGraph, GEdge, GImplicitDirectedGraph};
    use crate::graph::hash_graph::HashDirectedGraph;
    use crate::graph::graph_path::{GraphPath, GraphPathSet};
    use crate::graph::factory::{get_sources, get_sinks, is_self_contained, GraphFactory};
    use crate::graph::graph_to_tree::{to_tree, to_tree_default};
    use crate::graph::edge_weight::{ConstantWeightMetric, GEdgeWeightMetric};
    use crate::graph::algo::graph_navigator::GraphNavigator;
    use crate::graph::algo::depth_first_sorter::DepthFirstSorter;
    use crate::graph::algo::find_paths::{find_paths_iterative, find_paths_recursive};
    use crate::graph::algo::tarjan_scc::tarjan_scc;
    use crate::graph::algo::chk_dominance::{ChkDominanceAlgorithm, ChkPostDominanceAlgorithm};
    use crate::graph::algo::dijkstra::DijkstraShortestPaths;
    use crate::graph::algo::johnson_circuits::find_circuits;

    type E = DefaultGEdge<i32>;
    type G = HashDirectedGraph<i32, E>;

    fn edge(a: i32, b: i32) -> E {
        DefaultGEdge::new(a, b)
    }

    // ------------------------------------------------------------------
    // DefaultGEdge tests
    // ------------------------------------------------------------------

    #[test]
    fn test_default_edge() {
        let e = edge(1, 2);
        assert_eq!(*e.start(), 1);
        assert_eq!(*e.end(), 2);
    }

    #[test]
    fn test_edge_equality() {
        let e1 = edge(1, 2);
        let e2 = edge(1, 2);
        let e3 = edge(1, 3);
        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }

    // ------------------------------------------------------------------
    // HashDirectedGraph tests
    // ------------------------------------------------------------------

    #[test]
    fn test_hash_graph_create() {
        let g: G = HashDirectedGraph::new();
        assert!(g.is_empty());
        assert_eq!(g.get_vertex_count(), 0);
        assert_eq!(g.get_edge_count(), 0);
    }

    #[test]
    fn test_hash_graph_add_vertex() {
        let mut g: G = HashDirectedGraph::new();
        assert!(g.add_vertex(1));
        assert!(!g.add_vertex(1)); // duplicate
        assert_eq!(g.get_vertex_count(), 1);
    }

    #[test]
    fn test_hash_graph_add_edge() {
        let mut g: G = HashDirectedGraph::new();
        g.add_vertex(1);
        g.add_vertex(2);
        g.add_edge(edge(1, 2));
        assert_eq!(g.get_edge_count(), 1);
        assert!(g.contains_edge_between(&1, &2));
        assert!(!g.contains_edge_between(&2, &1));
    }

    #[test]
    fn test_hash_graph_add_edge_creates_vertices() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        assert_eq!(g.get_vertex_count(), 2);
        assert!(g.contains_vertex(&1));
        assert!(g.contains_vertex(&2));
    }

    #[test]
    fn test_hash_graph_remove_vertex() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(2, 3));
        g.remove_vertex(&2);
        assert_eq!(g.get_vertex_count(), 2);
        assert_eq!(g.get_edge_count(), 0); // both edges removed
    }

    #[test]
    fn test_hash_graph_find_edge() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        let e = g.find_edge(&1, &2);
        assert!(e.is_some());
        assert_eq!(*e.unwrap().end(), 2);
        assert!(g.find_edge(&2, &1).is_none());
    }

    #[test]
    fn test_hash_graph_successors_predecessors() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(1, 3));
        g.add_edge(edge(2, 3));

        let succs = g.get_successors(&1);
        assert_eq!(succs.len(), 2);
        assert!(succs.contains(&2));
        assert!(succs.contains(&3));

        let preds = g.get_predecessors(&3);
        assert_eq!(preds.len(), 2);
        assert!(preds.contains(&1));
        assert!(preds.contains(&2));
    }

    #[test]
    fn test_hash_graph_in_edges_out_edges() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(3, 2));

        let in_edges = g.get_in_edges(&2);
        assert_eq!(in_edges.len(), 2);

        let out_edges = g.get_out_edges(&1);
        assert_eq!(out_edges.len(), 1);
        assert_eq!(*out_edges[0].end(), 2);
    }

    #[test]
    fn test_hash_graph_copy_explicit() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(2, 3));

        let copy = g.copy_explicit();
        assert_eq!(copy.get_vertex_count(), 3);
        assert_eq!(copy.get_edge_count(), 2);
    }

    // ------------------------------------------------------------------
    // GraphFactory tests
    // ------------------------------------------------------------------

    #[test]
    fn test_graph_factory() {
        let g: G = GraphFactory::create_directed_graph();
        assert!(g.is_empty());
    }

    // ------------------------------------------------------------------
    // get_sources / get_sinks tests
    // ------------------------------------------------------------------

    #[test]
    fn test_get_sources() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(2, 3));

        let sources = get_sources(&g);
        assert_eq!(sources.len(), 1);
        assert!(sources.contains(&1));
    }

    #[test]
    fn test_get_sinks() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(2, 3));

        let sinks = get_sinks(&g);
        assert_eq!(sinks.len(), 1);
        assert!(sinks.contains(&3));
    }

    #[test]
    fn test_is_self_contained() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        assert!(is_self_contained(&g));
    }

    // ------------------------------------------------------------------
    // GraphPath tests
    // ------------------------------------------------------------------

    #[test]
    fn test_graph_path_basic() {
        let mut p = GraphPath::new();
        assert!(p.is_empty());
        p.add(1);
        p.add(2);
        p.add(3);
        assert_eq!(p.size(), 3);
        assert!(p.contains(&2));
        assert!(!p.contains(&4));
    }

    #[test]
    fn test_graph_path_no_duplicates() {
        let mut p = GraphPath::new();
        assert!(p.add(1));
        assert!(!p.add(1));
        assert_eq!(p.size(), 1);
    }

    #[test]
    fn test_graph_path_starts_with() {
        let mut p1 = GraphPath::new();
        p1.add(1);
        p1.add(2);
        p1.add(3);
        p1.add(4);

        let mut p2 = GraphPath::new();
        p2.add(1);
        p2.add(2);

        assert!(p1.starts_with(&p2));
        assert!(!p2.starts_with(&p1));
    }

    #[test]
    fn test_graph_path_common_start() {
        let mut p1 = GraphPath::new();
        for v in [1, 2, 3, 4, 5, 6] { p1.add(v); }

        let mut p2 = GraphPath::new();
        for v in [1, 2, 3, 4, 7, 8] { p2.add(v); }

        let common = p1.get_common_start_path(&p2);
        assert_eq!(common.size(), 4);
        assert_eq!(*common.get(3), 4);
    }

    #[test]
    fn test_graph_path_sub_path() {
        let mut p = GraphPath::new();
        for v in [1, 2, 3, 4, 5] { p.add(v); }
        let sub = p.sub_path(1, 4);
        assert_eq!(sub.size(), 3);
        assert_eq!(*sub.get(0), 2);
        assert_eq!(*sub.get(2), 4);
    }

    #[test]
    fn test_graph_path_predecessors_successors() {
        let mut p = GraphPath::new();
        for v in [1, 2, 3, 4, 5] { p.add(v); }

        let preds = p.get_predecessors(&3);
        assert!(preds.contains(&1));
        assert!(preds.contains(&2));
        assert!(preds.contains(&3));
        assert!(!preds.contains(&4));

        let succs = p.get_successors(&3);
        assert!(succs.contains(&3));
        assert!(succs.contains(&4));
        assert!(succs.contains(&5));
        assert!(!succs.contains(&1));
    }

    // ------------------------------------------------------------------
    // GraphPathSet tests
    // ------------------------------------------------------------------

    #[test]
    fn test_graph_path_set() {
        let mut ps = GraphPathSet::new();
        let mut p1 = GraphPath::new();
        p1.add(1); p1.add(2); p1.add(3);
        let mut p2 = GraphPath::new();
        p2.add(1); p2.add(4); p2.add(5);

        ps.add(p1);
        ps.add(p2);
        assert_eq!(ps.size(), 2);

        let containing_1 = ps.get_paths_containing(&1);
        assert_eq!(containing_1.len(), 2);

        let containing_4 = ps.get_paths_containing(&4);
        assert_eq!(containing_4.len(), 1);
    }

    #[test]
    fn test_graph_path_set_starts_with() {
        let mut ps = GraphPathSet::new();
        let mut p = GraphPath::new();
        p.add(1); p.add(2); p.add(3);
        ps.add(p);

        let mut prefix = GraphPath::new();
        prefix.add(1); prefix.add(2);
        assert!(ps.contain_some_path_starting_with(&prefix));

        let mut not_prefix = GraphPath::new();
        not_prefix.add(2); not_prefix.add(3);
        assert!(!ps.contain_some_path_starting_with(&not_prefix));
    }

    // ------------------------------------------------------------------
    // GraphNavigator tests
    // ------------------------------------------------------------------

    #[test]
    fn test_graph_navigator_top_down() {
        let nav = GraphNavigator::top_down();
        assert!(nav.is_top_down());

        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(2, 3));

        let sources = nav.get_sources(&g);
        assert!(sources.contains(&1));

        let sinks = nav.get_sinks(&g);
        assert!(sinks.contains(&3));

        let succs = nav.get_successors(&g, &1);
        assert!(succs.contains(&2));
    }

    #[test]
    fn test_graph_navigator_bottom_up() {
        let nav = GraphNavigator::bottom_up();
        assert!(!nav.is_top_down());

        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(2, 3));

        // For bottom-up, "sources" are the sinks of the original graph
        let sources = nav.get_sources(&g);
        assert!(sources.contains(&3));

        // "successors" in bottom-up = predecessors in original
        let succs = nav.get_successors(&g, &3);
        assert!(succs.contains(&2));
    }

    // ------------------------------------------------------------------
    // DepthFirstSorter tests
    // ------------------------------------------------------------------

    #[test]
    fn test_depth_first_sorter_post_order() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(1, 3));
        g.add_edge(edge(2, 4));
        g.add_edge(edge(3, 4));

        let po = DepthFirstSorter::post_order(&g);
        assert_eq!(po.len(), 4);
        // 1 should be last in post-order (it's the source)
        assert_eq!(*po.last().unwrap(), 1);
    }

    #[test]
    fn test_depth_first_sorter_pre_order() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(1, 3));
        g.add_edge(edge(2, 4));

        let pre = DepthFirstSorter::pre_order(&g);
        assert_eq!(pre.len(), 4);
        // 1 should be first in pre-order
        assert_eq!(pre[0], 1);
    }

    // ------------------------------------------------------------------
    // Graph-to-tree tests
    // ------------------------------------------------------------------

    #[test]
    fn test_to_tree_simple() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(1, 3));
        g.add_edge(edge(2, 4));
        g.add_edge(edge(3, 4));

        let tree = to_tree_default(&g, &1);
        assert_eq!(tree.get_vertex_count(), 4);
        // Tree should have exactly 3 edges (n-1 for a tree)
        assert_eq!(tree.get_edge_count(), 3);
    }

    #[test]
    fn test_to_tree_removes_back_edges() {
        // Graph with cycle: 1 -> 2 -> 3 -> 2
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(2, 3));
        g.add_edge(edge(3, 2)); // back edge

        let tree = to_tree_default(&g, &1);
        // Should have 3 vertices, 2 edges (tree)
        assert_eq!(tree.get_vertex_count(), 3);
        assert_eq!(tree.get_edge_count(), 2);
    }

    // ------------------------------------------------------------------
    // Find paths tests
    // ------------------------------------------------------------------

    #[test]
    fn test_find_paths_iterative() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(1, 3));
        g.add_edge(edge(2, 4));
        g.add_edge(edge(3, 4));

        let paths = find_paths_iterative(&g, &1, &4);
        assert_eq!(paths.len(), 2);
        // Both paths should start with 1 and end with 4
        for p in &paths {
            assert_eq!(p[0], 1);
            assert_eq!(*p.last().unwrap(), 4);
        }
    }

    #[test]
    fn test_find_paths_recursive() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(1, 3));
        g.add_edge(edge(2, 4));
        g.add_edge(edge(3, 4));

        let paths = find_paths_recursive(&g, &1, &4);
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn test_find_paths_no_path() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(3, 4));

        let paths = find_paths_iterative(&g, &1, &4);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_find_paths_single_path() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(2, 3));

        let paths = find_paths_iterative(&g, &1, &3);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vec![1, 2, 3]);
    }

    // ------------------------------------------------------------------
    // Johnson's circuits tests
    // ------------------------------------------------------------------

    #[test]
    fn test_johnson_circuits_simple_cycle() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(0, 1));
        g.add_edge(edge(1, 2));
        g.add_edge(edge(2, 0));

        let circuits = find_circuits(&g, false);
        // With unique=false, the algorithm finds the same cycle from
        // different starting vertices (this matches the Java behavior).
        assert!(!circuits.is_empty());
        for c in &circuits {
            assert_eq!(c.len(), 4); // 0, 1, 2, 0 (or rotation)
        }
    }

    #[test]
    fn test_johnson_circuits_no_cycles() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(0, 1));
        g.add_edge(edge(1, 2));

        let circuits = find_circuits(&g, false);
        assert!(circuits.is_empty());
    }

    // ------------------------------------------------------------------
    // Dijkstra tests
    // ------------------------------------------------------------------

    #[test]
    fn test_dijkstra_simple() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(2, 3));
        g.add_edge(edge(1, 3));

        struct UnitMetric;
        impl GEdgeWeightMetric<E> for UnitMetric {
            fn compute_weight(&self, _edge: &E) -> f64 { 1.0 }
        }

        let mut dijkstra = DijkstraShortestPaths::new_unbounded();
        let dists = dijkstra.get_distances_from_source(&g, &1, &UnitMetric);

        assert_eq!(dists.get(&1), Some(&0.0));
        assert_eq!(dists.get(&2), Some(&1.0));
        assert_eq!(dists.get(&3), Some(&1.0)); // Direct edge 1->3
    }

    #[test]
    fn test_dijkstra_weighted() {
        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(1, 2));
        g.add_edge(edge(2, 3));
        g.add_edge(edge(1, 3));

        // Weight by edge: 1->2 = 1, 2->3 = 1, 1->3 = 5
        struct TestMetric;
        impl GEdgeWeightMetric<E> for TestMetric {
            fn compute_weight(&self, edge: &E) -> f64 {
                match (edge.start(), edge.end()) {
                    (1, 3) => 5.0,
                    _ => 1.0,
                }
            }
        }

        let mut dijkstra = DijkstraShortestPaths::new_unbounded();
        let dists = dijkstra.get_distances_from_source(&g, &1, &TestMetric);

        assert_eq!(dists.get(&1), Some(&0.0));
        assert_eq!(dists.get(&2), Some(&1.0));
        assert_eq!(dists.get(&3), Some(&2.0)); // via 1->2->3 (2 < 5)
    }

    // ------------------------------------------------------------------
    // CHK Dominance tests (generic graph)
    // ------------------------------------------------------------------

    #[test]
    fn test_chk_dominance_generic() {
        // 0 -> 1 -> 3, 0 -> 2 -> 3
        let mut g: G = HashDirectedGraph::new();
        g.add_vertex(0);
        g.add_vertex(1);
        g.add_vertex(2);
        g.add_vertex(3);
        g.add_edge(edge(0, 1));
        g.add_edge(edge(0, 2));
        g.add_edge(edge(1, 3));
        g.add_edge(edge(2, 3));

        let dom = ChkDominanceAlgorithm::compute(&g);
        assert_eq!(dom.get_root(), &0);
        assert_eq!(dom.get_immediate_dominator(&3), Some(&0));
    }

    #[test]
    fn test_chk_post_dominance() {
        // 0 -> 1 -> 3, 0 -> 2 -> 3
        let mut g: G = HashDirectedGraph::new();
        g.add_vertex(0);
        g.add_vertex(1);
        g.add_vertex(2);
        g.add_vertex(3);
        g.add_edge(edge(0, 1));
        g.add_edge(edge(0, 2));
        g.add_edge(edge(1, 3));
        g.add_edge(edge(2, 3));

        let pdom = ChkPostDominanceAlgorithm::compute(&g);
        // 3 post-dominates everything (single exit)
        assert!(pdom.get_post_dominators(&0).contains(&3));
    }

    // ------------------------------------------------------------------
    // Integration tests
    // ------------------------------------------------------------------

    #[test]
    fn test_full_pipeline() {
        // Build a graph representing a simple function:
        // entry -> if_header -> then_block -> merge
        //                   \-> else_block -/
        //                    -> loop_header -> loop_body (back to header)
        //                                 \-> exit

        let mut g: G = HashDirectedGraph::new();
        g.add_edge(edge(0, 1)); // entry -> if_header
        g.add_edge(edge(1, 2)); // if_header -> then_block
        g.add_edge(edge(1, 3)); // if_header -> else_block
        g.add_edge(edge(1, 4)); // if_header -> loop_header
        g.add_edge(edge(2, 5)); // then_block -> merge
        g.add_edge(edge(3, 5)); // else_block -> merge
        g.add_edge(edge(4, 6)); // loop_header -> loop_body
        g.add_edge(edge(6, 4)); // loop_body -> loop_header (back edge)
        g.add_edge(edge(4, 7)); // loop_header -> exit

        // Test various analyses
        let sources = get_sources(&g);
        assert!(sources.contains(&0));

        let sinks = get_sinks(&g);
        assert!(sinks.contains(&5));
        assert!(sinks.contains(&7));

        assert!(is_self_contained(&g));

        // Find all paths from entry to merge
        let paths = find_paths_iterative(&g, &0, &5);
        assert!(!paths.is_empty());

        // SCC: loop_header and loop_body form one SCC
        let sccs = tarjan_scc(&g);
        let has_cycle_scc = sccs.iter().any(|scc| scc.len() > 1);
        assert!(has_cycle_scc);

        // Dominance
        let dom = ChkDominanceAlgorithm::compute(&g);
        assert_eq!(dom.get_root(), &0);
    }
}
