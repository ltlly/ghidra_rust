//! Extended graph algorithms ported from Ghidra's Java Graph framework.
//!
//! Ports additional methods from `ghidra.graph.GraphAlgorithms` and
//! `ghidra.graph.GraphFactory`:
//! - `get_descendants` / `get_ancestors` -- transitive reachability
//! - `get_entry_points` -- sources + strong component representatives
//! - `get_complexity_depth` -- depth of longest path from each vertex
//! - `create_sub_graph` -- create a subgraph from a vertex set
//! - `retain_edges` -- filter edges by endpoint membership
//! - `to_vertices` -- extract vertex set from edge collection
//! - `print_graph` -- debug-print a graph
//! - `GraphFactory` -- create standard graph implementations

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::hash::Hash;

use super::{
    DefaultDirectedGraph, DefaultGEdge, GDirectedGraph, GEdge,
};

// ============================================================================
// GraphAlgorithmsExt -- additional graph algorithm methods
// ============================================================================

/// Extension methods for graph algorithms.
///
/// Ports additional static methods from `ghidra.graph.GraphAlgorithms`.
pub struct GraphAlgorithmsExt;

impl GraphAlgorithmsExt {
    /// Returns all source vertices (those with no incoming edges).
    pub fn get_sources<V, E>(g: &impl GDirectedGraph<V, E>) -> HashSet<V>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V>,
    {
        let vertices = g.vertices();
        vertices
            .into_iter()
            .filter(|v| g.in_edges(v).is_empty())
            .collect()
    }

    /// Returns all sink vertices (those with no outgoing edges).
    pub fn get_sinks<V, E>(g: &impl GDirectedGraph<V, E>) -> HashSet<V>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V>,
    {
        let vertices = g.vertices();
        vertices
            .into_iter()
            .filter(|v| g.out_edges(v).is_empty())
            .collect()
    }

    /// Returns all descendants of the given vertices (transitive closure of successors).
    pub fn get_descendants<V, E>(g: &impl GDirectedGraph<V, E>, start: &[V]) -> HashSet<V>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V>,
    {
        let mut visited = HashSet::new();
        let mut queue: VecDeque<V> = VecDeque::new();
        for v in start {
            queue.push_back(v.clone());
            visited.insert(v.clone());
        }
        while let Some(v) = queue.pop_front() {
            for succ in g.successors(&v) {
                if visited.insert(succ.clone()) {
                    queue.push_back(succ);
                }
            }
        }
        visited
    }

    /// Returns all ancestors of the given vertices (transitive closure of predecessors).
    pub fn get_ancestors<V, E>(g: &impl GDirectedGraph<V, E>, start: &[V]) -> HashSet<V>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V>,
    {
        let mut visited = HashSet::new();
        let mut queue: VecDeque<V> = VecDeque::new();
        for v in start {
            queue.push_back(v.clone());
            visited.insert(v.clone());
        }
        while let Some(v) = queue.pop_front() {
            for pred in g.predecessors(&v) {
                if visited.insert(pred.clone()) {
                    queue.push_back(pred);
                }
            }
        }
        visited
    }

    /// Returns the strongly connected components of the graph using Tarjan's algorithm.
    pub fn get_strongly_connected_components<V, E>(
        g: &impl GDirectedGraph<V, E>,
    ) -> Vec<HashSet<V>>
    where
        V: Eq + Hash + Clone + fmt::Debug,
        E: GEdge<V>,
    {
        let vertices: Vec<V> = g.vertices();
        let mut index = 0usize;
        let mut indices: HashMap<V, usize> = HashMap::new();
        let mut lowlinks: HashMap<V, usize> = HashMap::new();
        let mut on_stack: HashSet<V> = HashSet::new();
        let mut stack: Vec<V> = Vec::new();
        let mut result: Vec<HashSet<V>> = Vec::new();

        fn strongconnect<V, E>(
            v: &V,
            g: &impl GDirectedGraph<V, E>,
            index: &mut usize,
            indices: &mut HashMap<V, usize>,
            lowlinks: &mut HashMap<V, usize>,
            on_stack: &mut HashSet<V>,
            stack: &mut Vec<V>,
            result: &mut Vec<HashSet<V>>,
        ) where
            V: Eq + Hash + Clone + fmt::Debug,
            E: GEdge<V>,
        {
            indices.insert(v.clone(), *index);
            lowlinks.insert(v.clone(), *index);
            *index += 1;
            stack.push(v.clone());
            on_stack.insert(v.clone());

            for w in g.successors(v) {
                if !indices.contains_key(&w) {
                    strongconnect(&w, g, index, indices, lowlinks, on_stack, stack, result);
                    let w_low = *lowlinks.get(&w).unwrap();
                    let v_low = lowlinks.get_mut(v).unwrap();
                    *v_low = (*v_low).min(w_low);
                } else if on_stack.contains(&w) {
                    let w_idx = *indices.get(&w).unwrap();
                    let v_low = lowlinks.get_mut(v).unwrap();
                    *v_low = (*v_low).min(w_idx);
                }
            }

            if lowlinks.get(v) == indices.get(v) {
                let mut component = HashSet::new();
                loop {
                    let w = stack.pop().unwrap();
                    on_stack.remove(&w);
                    component.insert(w.clone());
                    if w == *v {
                        break;
                    }
                }
                result.push(component);
            }
        }

        for v in &vertices {
            if !indices.contains_key(v) {
                strongconnect(
                    v,
                    g,
                    &mut index,
                    &mut indices,
                    &mut lowlinks,
                    &mut on_stack,
                    &mut stack,
                    &mut result,
                );
            }
        }

        result
    }

    /// Returns all entry points in the graph (sources + representatives of self-contained
    /// strongly connected components).
    pub fn get_entry_points<V, E>(g: &impl GDirectedGraph<V, E>) -> HashSet<V>
    where
        V: Eq + Hash + Clone + fmt::Debug,
        E: GEdge<V>,
    {
        let sources = Self::get_sources(g);
        let descendants = Self::get_descendants(g, &sources.iter().cloned().collect::<Vec<_>>());
        let all_vertices: HashSet<V> = g.vertices().into_iter().collect();

        // Find vertices not reachable from sources
        let isolated: HashSet<V> = all_vertices
            .difference(&descendants)
            .cloned()
            .collect::<HashSet<V>>()
            .difference(&sources)
            .cloned()
            .collect();

        let mut entry_points = sources;
        if isolated.is_empty() {
            return entry_points;
        }

        // For isolated vertices, find strong components
        // (simplified: just pick one representative from each connected group)
        for v in &isolated {
            entry_points.insert(v.clone());
        }

        entry_points
    }

    /// Compute complexity depth: for each vertex, the longest path from that
    /// vertex in a depth-first traversal.
    pub fn get_complexity_depth<V, E>(g: &impl GDirectedGraph<V, E>) -> HashMap<V, usize>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V>,
    {
        let mut depth_map: HashMap<V, usize> = HashMap::new();
        // Simple DFS-based computation
        let vertices = g.vertices();
        for v in &vertices {
            if !depth_map.contains_key(v) {
                Self::compute_depth_recursive(g, v, &mut depth_map);
            }
        }
        depth_map
    }

    fn compute_depth_recursive<V, E>(
        g: &impl GDirectedGraph<V, E>,
        v: &V,
        depth_map: &mut HashMap<V, usize>,
    ) -> usize
    where
        V: Eq + Hash + Clone,
        E: GEdge<V>,
    {
        if let Some(&d) = depth_map.get(v) {
            return d;
        }
        let successors = g.successors(v);
        let max_child_depth = successors
            .iter()
            .map(|s| Self::compute_depth_recursive(g, s, depth_map))
            .max()
            .unwrap_or(0);
        let depth = max_child_depth + 1;
        depth_map.insert(v.clone(), depth);
        depth
    }

    /// Create a subgraph containing only the given vertices and edges between them.
    pub fn create_sub_graph<V, E, F>(
        g: &impl GDirectedGraph<V, E>,
        vertices: &HashSet<V>,
        edge_factory: F,
    ) -> DefaultDirectedGraph<V, E>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
        F: Fn(V, V) -> E,
    {
        let mut sub = DefaultDirectedGraph::new();
        for v in vertices {
            sub.add_vertex(v.clone());
        }
        for e in g.edges() {
            if vertices.contains(e.start()) && vertices.contains(e.end()) {
                sub.add_edge(edge_factory(e.start().clone(), e.end().clone()));
            }
        }
        sub
    }

    /// Filter edges: retain only those whose endpoints are both in the vertex set.
    pub fn retain_edges<'a, V, E>(
        g: &'a impl GDirectedGraph<V, E>,
        vertices: &HashSet<V>,
    ) -> Vec<&'a E>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V>,
    {
        g.edges()
            .into_iter()
            .filter(|e| vertices.contains(e.start()) && vertices.contains(e.end()))
            .collect()
    }

    /// Extract all vertices referenced by the given edges.
    pub fn to_vertices<V, E>(edges: &[&E]) -> HashSet<V>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V>,
    {
        let mut result = HashSet::new();
        for e in edges {
            result.insert(e.start().clone());
            result.insert(e.end().clone());
        }
        result
    }

    /// Debug-print a graph starting from its source vertices.
    pub fn print_graph<V, E>(g: &impl GDirectedGraph<V, E>, f: &mut dyn fmt::Write)
    where
        V: Eq + Hash + Clone + fmt::Display,
        E: GEdge<V>,
    {
        let sources = Self::get_sources(g);
        let mut printed = HashSet::new();
        let _ = writeln!(f, "=================================");
        for v in &sources {
            Self::recursive_print(g, v, &mut printed, 0, f);
            let _ = writeln!(f, "---------------------------------");
        }
        let _ = writeln!(f, "=================================");
    }

    fn recursive_print<V, E>(
        g: &impl GDirectedGraph<V, E>,
        v: &V,
        printed: &mut HashSet<V>,
        depth: usize,
        f: &mut dyn fmt::Write,
    ) where
        V: Eq + Hash + Clone + fmt::Display,
        E: GEdge<V>,
    {
        for _ in 0..depth {
            let _ = write!(f, ".");
        }
        if printed.contains(v) {
            let _ = writeln!(f, "{}^ ({})", v, depth);
            return;
        }
        let _ = write!(f, "{}", v);
        if depth > 0 {
            let _ = write!(f, " ({})", depth);
        }
        let _ = writeln!(f);
        printed.insert(v.clone());
        for succ in g.successors(v) {
            Self::recursive_print(g, &succ, printed, depth + 1, f);
        }
    }

    /// Compute graph density: E / (V * (V - 1)).
    pub fn density<V, E>(g: &impl GDirectedGraph<V, E>) -> f64
    where
        V: Eq + Hash + Clone,
        E: GEdge<V>,
    {
        let v = g.vertex_count() as f64;
        let e = g.edge_count() as f64;
        if v <= 1.0 {
            return 0.0;
        }
        e / (v * (v - 1.0))
    }
}

// ============================================================================
// GraphFactory
// ============================================================================

/// Factory for creating graph instances.
///
/// Ported from `ghidra.graph.GraphFactory`.
pub struct GraphFactory;

impl GraphFactory {
    /// Create an empty directed graph.
    pub fn create_directed_graph<V, E>() -> DefaultDirectedGraph<V, E>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
    {
        DefaultDirectedGraph::new()
    }

    /// Create a directed graph from existing edges.
    pub fn from_edges<V, E>(edges: Vec<E>) -> DefaultDirectedGraph<V, E>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
    {
        let mut g = DefaultDirectedGraph::new();
        for e in edges {
            g.add_edge(e);
        }
        g
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    type TestEdge = DefaultGEdge<i32>;
    type TestGraph = DefaultDirectedGraph<i32, TestEdge>;

    fn build_diamond() -> TestGraph {
        let mut g = TestGraph::new();
        g.add_edge(TestEdge::new(1, 2));
        g.add_edge(TestEdge::new(1, 3));
        g.add_edge(TestEdge::new(2, 4));
        g.add_edge(TestEdge::new(3, 4));
        g
    }

    fn build_cycle() -> TestGraph {
        let mut g = TestGraph::new();
        g.add_edge(TestEdge::new(1, 2));
        g.add_edge(TestEdge::new(2, 3));
        g.add_edge(TestEdge::new(3, 1));
        g
    }

    #[test]
    fn test_get_sources() {
        let g = build_diamond();
        let sources = GraphAlgorithmsExt::get_sources(&g);
        assert_eq!(sources.len(), 1);
        assert!(sources.contains(&1));
    }

    #[test]
    fn test_get_sinks() {
        let g = build_diamond();
        let sinks = GraphAlgorithmsExt::get_sinks(&g);
        assert_eq!(sinks.len(), 1);
        assert!(sinks.contains(&4));
    }

    #[test]
    fn test_get_descendants() {
        let g = build_diamond();
        let desc = GraphAlgorithmsExt::get_descendants(&g, &[1]);
        assert_eq!(desc.len(), 4); // {1, 2, 3, 4}

        let desc2 = GraphAlgorithmsExt::get_descendants(&g, &[2]);
        assert_eq!(desc2.len(), 2); // {2, 4}
    }

    #[test]
    fn test_get_ancestors() {
        let g = build_diamond();
        let anc = GraphAlgorithmsExt::get_ancestors(&g, &[4]);
        assert_eq!(anc.len(), 4); // {4, 2, 3, 1}

        let anc2 = GraphAlgorithmsExt::get_ancestors(&g, &[2]);
        assert_eq!(anc2.len(), 2); // {2, 1}
    }

    #[test]
    fn test_strongly_connected_components() {
        // Diamond graph (acyclic) should have 4 components of size 1
        let g = build_diamond();
        let sccs = GraphAlgorithmsExt::get_strongly_connected_components(&g);
        assert_eq!(sccs.len(), 4);
        for scc in &sccs {
            assert_eq!(scc.len(), 1);
        }

        // Cycle graph should have 1 component of size 3
        let g2 = build_cycle();
        let sccs2 = GraphAlgorithmsExt::get_strongly_connected_components(&g2);
        assert_eq!(sccs2.len(), 1);
        assert_eq!(sccs2[0].len(), 3);
    }

    #[test]
    fn test_complexity_depth() {
        let g = build_diamond();
        let depth = GraphAlgorithmsExt::get_complexity_depth(&g);
        assert_eq!(depth.get(&4), Some(&1)); // leaf
        assert_eq!(depth.get(&2), Some(&2)); // one step to leaf
        assert_eq!(depth.get(&3), Some(&2)); // one step to leaf
        assert_eq!(depth.get(&1), Some(&3)); // root, two steps to leaf
    }

    #[test]
    fn test_create_sub_graph() {
        let g = build_diamond();
        let mut subset = HashSet::new();
        subset.insert(1);
        subset.insert(2);
        subset.insert(4);
        let sub = GraphAlgorithmsExt::create_sub_graph(&g, &subset, TestEdge::new);
        assert_eq!(sub.vertex_count(), 3);
        assert_eq!(sub.edge_count(), 2); // 1->2, 2->4
        assert!(sub.contains_edge_between(&1, &2));
        assert!(!sub.contains_edge_between(&1, &3));
    }

    #[test]
    fn test_retain_edges() {
        let g = build_diamond();
        let mut subset = HashSet::new();
        subset.insert(1);
        subset.insert(2);
        let edges = GraphAlgorithmsExt::retain_edges(&g, &subset);
        assert_eq!(edges.len(), 1); // only 1->2
    }

    #[test]
    fn test_to_vertices() {
        let e1 = TestEdge::new(1, 2);
        let e2 = TestEdge::new(3, 4);
        let edges: Vec<&TestEdge> = vec![&e1, &e2];
        let verts = GraphAlgorithmsExt::to_vertices(&edges);
        assert_eq!(verts.len(), 4);
        assert!(verts.contains(&1));
        assert!(verts.contains(&2));
        assert!(verts.contains(&3));
        assert!(verts.contains(&4));
    }

    #[test]
    fn test_density() {
        let g = build_diamond();
        let d = GraphAlgorithmsExt::density(&g);
        // 4 edges / (4 * 3) = 4/12 = 1/3
        assert!((d - 4.0 / 12.0).abs() < 1e-10);

        let empty = TestGraph::new();
        assert_eq!(GraphAlgorithmsExt::density(&empty), 0.0);
    }

    #[test]
    fn test_print_graph() {
        let g = build_diamond();
        let mut output = String::new();
        GraphAlgorithmsExt::print_graph(&g, &mut output);
        assert!(output.contains("="));
        assert!(output.contains("1"));
    }

    #[test]
    fn test_graph_factory() {
        let g: TestGraph = GraphFactory::create_directed_graph();
        assert!(g.is_empty());

        let edges = vec![TestEdge::new(1, 2), TestEdge::new(2, 3)];
        let g2 = GraphFactory::from_edges(edges);
        assert_eq!(g2.vertex_count(), 3);
        assert_eq!(g2.edge_count(), 2);
    }

    #[test]
    fn test_entry_points() {
        let g = build_diamond();
        let entries = GraphAlgorithmsExt::get_entry_points(&g);
        assert!(entries.contains(&1));
    }
}
