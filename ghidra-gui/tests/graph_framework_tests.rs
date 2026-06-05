//! Tests for the Graph framework ported from Ghidra's Java Framework/Graph package.
//!
//! Covers: GDirectedGraph, GEdge, GraphPath, edge weight metrics,
//! graph algorithms, MutableGDirectedGraphWrapper, GImplicitDirectedGraph,
//! service layer types, and visual graph types.

use ghidra_gui::graph::{
    DefaultDirectedGraph, DefaultGEdge, GDirectedGraph, GEdge, GWeightedEdge, GraphPath,
    g_vertex, edge_weight_metric,
    algo, job, mutable_wrapper, implicit_graph,
    service, viewer,
    filtering_visual_graph, grouping_visual_graph,
};

// ============================================================================
// GEdge trait and DefaultGEdge
// ============================================================================

#[test]
fn test_g_edge_trait() {
    let edge = DefaultGEdge::new(10, 20);
    assert_eq!(*edge.start(), 10);
    assert_eq!(*edge.end(), 20);
}

#[test]
fn test_g_edge_display() {
    let edge = DefaultGEdge::new("a", "b");
    assert_eq!(format!("{}", edge), "a -> b");
}

#[test]
fn test_g_edge_equality() {
    let e1 = DefaultGEdge::new(1, 2);
    let e2 = DefaultGEdge::new(1, 2);
    let e3 = DefaultGEdge::new(2, 1);
    assert_eq!(e1, e2);
    assert_ne!(e1, e3);
}

#[test]
fn test_g_weighted_edge() {
    let edge = GWeightedEdge::new(1, 2, 3.5);
    assert_eq!(*edge.start(), 1);
    assert_eq!(*edge.end(), 2);
    assert_eq!(edge.weight(), 3.5);
}

// ============================================================================
// GDirectedGraph trait and DefaultDirectedGraph
// ============================================================================

type TestEdge = DefaultGEdge<i32>;
type TestGraph = DefaultDirectedGraph<i32, TestEdge>;

#[test]
fn test_graph_add_and_query_vertices() {
    let mut g = TestGraph::new();
    assert!(g.add_vertex(1));
    assert!(g.add_vertex(2));
    assert!(!g.add_vertex(1));
    assert_eq!(g.vertex_count(), 2);
}

#[test]
fn test_graph_add_and_query_edges() {
    let mut g = TestGraph::new();
    g.add_edge(TestEdge::new(1, 2));
    g.add_edge(TestEdge::new(2, 3));
    assert_eq!(g.edge_count(), 2);
    assert_eq!(g.vertex_count(), 3);
    assert!(g.contains_edge_between(&1, &2));
    assert!(!g.contains_edge_between(&2, &1));
}

#[test]
fn test_graph_find_edge() {
    let mut g = TestGraph::new();
    g.add_edge(TestEdge::new(10, 20));
    let e = g.find_edge(&10, &20).unwrap();
    assert_eq!(*e.start(), 10);
    assert_eq!(*e.end(), 20);
    assert!(g.find_edge(&20, &10).is_none());
}

#[test]
fn test_graph_in_edges_out_edges() {
    let mut g = TestGraph::new();
    g.add_edge(TestEdge::new(1, 2));
    g.add_edge(TestEdge::new(3, 2));
    g.add_edge(TestEdge::new(2, 4));
    assert_eq!(g.in_edges(&2).len(), 2);
    assert_eq!(g.out_edges(&2).len(), 1);
    assert_eq!(g.in_degree(&2), 2);
    assert_eq!(g.out_degree(&2), 1);
}

#[test]
fn test_graph_predecessors_successors() {
    let mut g = TestGraph::new();
    g.add_edge(TestEdge::new(1, 2));
    g.add_edge(TestEdge::new(3, 2));
    g.add_edge(TestEdge::new(2, 4));
    let mut preds = g.predecessors(&2);
    preds.sort();
    assert_eq!(preds, vec![1, 3]);
    let succs = g.successors(&2);
    assert_eq!(succs, vec![4]);
}

#[test]
fn test_graph_remove_vertex_removes_edges() {
    let mut g = TestGraph::new();
    g.add_edge(TestEdge::new(1, 2));
    g.add_edge(TestEdge::new(2, 3));
    g.add_edge(TestEdge::new(3, 4));
    g.remove_vertex(&2);
    assert_eq!(g.vertex_count(), 3);
    assert_eq!(g.edge_count(), 1);
    assert!(g.contains_edge_between(&3, &4));
}

#[test]
fn test_graph_remove_edge() {
    let mut g = TestGraph::new();
    g.add_edge(TestEdge::new(1, 2));
    g.add_edge(TestEdge::new(2, 3));
    assert!(g.remove_edge(&TestEdge::new(1, 2)));
    assert_eq!(g.edge_count(), 1);
    assert!(!g.contains_edge_between(&1, &2));
}

#[test]
fn test_graph_copy_and_empty_copy() {
    let mut g = TestGraph::new();
    g.add_edge(TestEdge::new(1, 2));
    let copy = g.copy();
    assert_eq!(copy.edge_count(), 1);
    let empty = g.empty_copy();
    assert!(empty.is_empty());
}

#[test]
fn test_graph_batch_remove() {
    let mut g = TestGraph::new();
    g.add_edge(TestEdge::new(1, 2));
    g.add_edge(TestEdge::new(3, 4));
    g.remove_vertices(vec![2, 3]);
    assert_eq!(g.vertex_count(), 2);
    assert_eq!(g.edge_count(), 0);
}

// ============================================================================
// GraphPath
// ============================================================================

#[test]
fn test_graph_path_basics() {
    let mut path = GraphPath::<i32, TestEdge>::new();
    assert!(path.is_empty());
    path.add(TestEdge::new(1, 2));
    path.add(TestEdge::new(2, 3));
    assert_eq!(path.len(), 2);
    assert_eq!(path.start_vertex(), Some(&1));
    assert_eq!(path.end_vertex(), Some(&3));
}

#[test]
fn test_graph_path_from_edges() {
    let path = GraphPath::from_edges(vec![
        TestEdge::new(1, 2),
        TestEdge::new(2, 3),
    ]);
    assert_eq!(path.len(), 2);
}

// ============================================================================
// Edge weight metrics
// ============================================================================

#[test]
fn test_constant_weight_metric() {
    use edge_weight_metric::{ConstantWeightMetric, GEdgeWeightMetric, HopCountMetric};
    let metric = ConstantWeightMetric::new(5.0);
    let edge = DefaultGEdge::new(1, 2);
    assert_eq!(metric.weight(&edge), 5.0);

    let hop = HopCountMetric;
    assert_eq!(hop.weight(&edge), 1.0);
}

// ============================================================================
// GImplicitDirectedGraph
// ============================================================================

#[test]
fn test_implicit_graph_transitive_successors() {
    use std::collections::HashMap;
    struct TestImplicitGraph {
        edges: HashMap<i32, Vec<i32>>,
    }
    impl implicit_graph::GImplicitDirectedGraph<i32> for TestImplicitGraph {
        fn successors(&self, v: &i32) -> Vec<i32> {
            self.edges.get(v).cloned().unwrap_or_default()
        }
        fn predecessors(&self, v: &i32) -> Vec<i32> {
            self.edges.iter()
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

    let graph = TestImplicitGraph {
        edges: vec![(1, vec![2, 3]), (2, vec![4]), (3, vec![4]), (4, vec![])]
            .into_iter().collect(),
    };
    let reachable = implicit_graph::transitive_successors(&graph, &1);
    assert!(reachable.contains(&1));
    assert!(reachable.contains(&2));
    assert!(reachable.contains(&3));
    assert!(reachable.contains(&4));
    assert_eq!(reachable.len(), 4);
}

// ============================================================================
// MutableGDirectedGraphWrapper
// ============================================================================

#[test]
fn test_mutable_wrapper_preserves_delegate() {
    let mut g = TestGraph::new();
    g.add_edge(TestEdge::new(1, 2));
    g.add_edge(TestEdge::new(2, 3));
    let wrapper = mutable_wrapper::MutableGDirectedGraphWrapper::from_graph(&g);
    assert_eq!(wrapper.vertices().len(), 3);
    assert_eq!(wrapper.edges().len(), 2);
}

#[test]
fn test_mutable_wrapper_add_vertex() {
    let mut g = TestGraph::new();
    g.add_edge(TestEdge::new(1, 2));
    let mut wrapper = mutable_wrapper::MutableGDirectedGraphWrapper::from_graph(&g);
    wrapper.add_vertex(10);
    assert_eq!(wrapper.vertices().len(), 3);
    assert!(wrapper.contains_vertex(&10));
}

#[test]
fn test_mutable_wrapper_dummy_vertex() {
    let g = TestGraph::new();
    let mut wrapper = mutable_wrapper::MutableGDirectedGraphWrapper::from_graph(&g);
    let dv = wrapper.add_dummy_vertex("root");
    assert_eq!(dv.name, "root");
    assert_eq!(wrapper.dummy_vertex_count(), 1);
}

// ============================================================================
// Graph algorithms (sample checks)
// ============================================================================

#[test]
fn test_tarjan_scc() {
    use algo::tarjan::TarjanScc;
    let mut g = TestGraph::new();
    g.add_edge(TestEdge::new(1, 2));
    g.add_edge(TestEdge::new(2, 3));
    g.add_edge(TestEdge::new(3, 1));
    g.add_edge(TestEdge::new(3, 4));

    let scc = TarjanScc::compute(&g);
    assert!(scc.len() >= 2); // {1,2,3} and {4}
}

#[test]
fn test_dfs_sorter() {
    use algo::dfs_sorter::{DepthFirstSorter, SortOrder};
    let mut g = TestGraph::new();
    g.add_edge(TestEdge::new(1, 2));
    g.add_edge(TestEdge::new(2, 3));

    let sorted = DepthFirstSorter::sort_from(&g, SortOrder::PreOrder, &[1]);
    assert!(!sorted.is_empty());
}

// ============================================================================
// Service layer types
// ============================================================================

#[test]
fn test_attributed_graph() {
    use service::{AttributedGraph, AttributedVertex, AttributedEdge};
    let mut g = AttributedGraph::new("test", "cfg");
    g.add_vertex(AttributedVertex::new("a", "A"));
    g.add_vertex(AttributedVertex::new("b", "B"));
    g.add_edge(AttributedEdge::new("ab", "a", "b"));
    assert_eq!(g.vertex_count(), 2);
    assert_eq!(g.edge_count(), 1);
    assert_eq!(g.successors("a"), vec!["b"]);
}

#[test]
fn test_vertex_shape() {
    use service::VertexShape;
    assert_eq!(VertexShape::default(), VertexShape::Rectangle);
    assert_eq!(VertexShape::from_name("Ellipse"), Some(VertexShape::Ellipse));
    assert_eq!(VertexShape::ALL.len(), 10);
}

#[test]
fn test_graph_display_options_builder() {
    use service::{GraphDisplayOptionsBuilder, GraphLabelPosition};
    let opts = GraphDisplayOptionsBuilder::new("cfg")
        .default_vertex_color("#FFE0E0")
        .label_position(GraphLabelPosition::North)
        .show_edge_labels(true)
        .build();
    assert_eq!(opts.default_vertex_color, "#FFE0E0");
    assert!(opts.show_edge_labels);
}

// ============================================================================
// Graph jobs (sample checks)
// ============================================================================

#[test]
fn test_graph_job_runner() {
    use job::GraphJobRunner;
    let runner = GraphJobRunner::new();
    assert_eq!(runner.pending_count(), 0);
}

#[test]
fn test_easing_function() {
    use job::EasingFunction;
    let linear = EasingFunction::Linear;
    assert_eq!(linear.apply(0.0), 0.0);
    assert_eq!(linear.apply(1.0), 1.0);
    assert!((linear.apply(0.5) - 0.5).abs() < 1e-6);

    let ease_in = EasingFunction::EaseIn;
    assert!((ease_in.apply(0.5) - 0.25).abs() < 1e-6);
}

#[test]
fn test_animator_job() {
    use job::AbstractAnimatorJob;
    let mut anim = AbstractAnimatorJob::new(1000);
    assert!(!anim.is_finished());
    anim.start();
    assert!(anim.is_running());
    anim.tick(500);
    assert!((anim.raw_progress() - 0.5).abs() < 1e-3);
    anim.tick(500);
    assert!(anim.is_finished());
}

#[test]
fn test_edge_hover_animator() {
    use job::EdgeHoverAnimator;
    let mut hover = EdgeHoverAnimator::new();
    assert!(!hover.is_active());
    hover.start_hover();
    hover.tick(100);
    assert!(hover.is_active());
}

#[test]
fn test_twinkle_vertex_animator() {
    use job::TwinkleVertexAnimator;
    let mut twinkle = TwinkleVertexAnimator::new("v1", 3, 100);
    assert!(!twinkle.is_finished());
    twinkle.tick(350);
    assert!(twinkle.is_finished());
}

// ============================================================================
// Viewer types
// ============================================================================

#[test]
fn test_viewer_visual_vertex() {
    use viewer::VisualVertex;
    let v = VisualVertex::new("v1", "Vertex 1");
    assert_eq!(v.id, "v1");
    assert_eq!(v.label, "Vertex 1");
    assert!(!v.selected);
}

#[test]
fn test_viewer_visual_edge() {
    use viewer::VisualEdge;
    let e = VisualEdge::new("e1", "v1", "v2");
    assert_eq!(e.id, "e1");
    assert_eq!(e.from_id, "v1");
    assert_eq!(e.to_id, "v2");
}

#[test]
fn test_viewer_point2d() {
    use viewer::Point2D;
    let p = Point2D { x: 10.0, y: 20.0 };
    assert_eq!(p.x, 10.0);
    assert_eq!(p.y, 20.0);
}

#[test]
fn test_viewer_visual_graph() {
    use viewer::{VisualGraph, VisualVertex, VisualEdge};
    let mut g = VisualGraph::new();
    g.add_vertex(VisualVertex::new("a", "A"));
    g.add_vertex(VisualVertex::new("b", "B"));
    g.add_edge(VisualEdge::new("ab", "a", "b"));
    assert_eq!(g.vertex_count(), 2);
    assert!(g.vertex("a").is_some());
}

// ============================================================================
// Filtering and grouping types
// ============================================================================

#[test]
fn test_filtering_graph_empty() {
    use filtering_visual_graph::FilteringGraph;
    let g = FilteringGraph::<i32, TestEdge>::empty();
    assert_eq!(g.visible_vertices().len(), 0);
}

#[test]
fn test_filtering_graph_hide_show() {
    use filtering_visual_graph::FilteringGraph;
    let mut inner = TestGraph::new();
    inner.add_edge(TestEdge::new(1, 2));
    inner.add_edge(TestEdge::new(2, 3));
    let mut g = FilteringGraph::new(inner);

    assert_eq!(g.visible_vertices().len(), 3);

    g.hide_vertex(2);
    assert!(g.is_vertex_hidden(&2));
    assert_eq!(g.visible_vertices().len(), 2);

    g.show_vertex(&2);
    assert!(!g.is_vertex_hidden(&2));
    assert_eq!(g.visible_vertices().len(), 3);
}

#[test]
fn test_grouping_graph_empty() {
    use grouping_visual_graph::GroupingGraph;
    let g = GroupingGraph::<i32, TestEdge>::empty();
    assert_eq!(g.group_count(), 0);
}

#[test]
fn test_vertex_group() {
    use grouping_visual_graph::VertexGroup;
    let mut group = VertexGroup::new(1, "group1");
    group.add_member(2);
    group.add_member(3);
    assert_eq!(group.member_count(), 2);
    assert!(group.contains(&2));
}
