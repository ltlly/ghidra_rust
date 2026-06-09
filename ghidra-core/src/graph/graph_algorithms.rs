//! Graph algorithm utilities.
//!
//! Port of `ghidra.graph.GraphAlgorithms` static methods:
//! - Source/sink detection
//! - Reachability (ancestors/descendants)
//! - Entry points
//! - Graph density
//! - Edge extraction and vertex projection
//! - Neighbors and incident edges
//! - Topological ordering helpers
//! - Graph equivalence checking
//! - Self-loop detection

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;

use super::traits::{GDirectedGraph, GEdge};

/// Returns all source vertices (those with no incoming edges).
pub fn get_sources<V, E>(g: &dyn GDirectedGraph<V, E>) -> HashSet<V>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let mut sources = HashSet::new();
    for v in g.get_vertices() {
        if g.get_in_edges(&v).is_empty() {
            sources.insert(v);
        }
    }
    sources
}

/// Returns all sink vertices (those with no outgoing edges).
pub fn get_sinks<V, E>(g: &dyn GDirectedGraph<V, E>) -> HashSet<V>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let mut sinks = HashSet::new();
    for v in g.get_vertices() {
        if g.get_out_edges(&v).is_empty() {
            sinks.insert(v);
        }
    }
    sinks
}

/// Returns all descendants of the given starting vertices.
///
/// A descendant is any vertex reachable by following out-edges from the
/// starting set, excluding the starting vertices themselves.
pub fn get_descendants<V, E>(g: &dyn GDirectedGraph<V, E>, starts: &[V]) -> HashSet<V>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let starts_set: HashSet<V> = starts.iter().cloned().collect();
    let mut visited = HashSet::new();
    let mut stack: Vec<V> = starts.to_vec();
    while let Some(v) = stack.pop() {
        if !visited.insert(v.clone()) {
            continue;
        }
        for succ in g.get_successors(&v) {
            if !visited.contains(&succ) {
                stack.push(succ);
            }
        }
    }
    // Remove the starting vertices from the result
    for s in &starts_set {
        visited.remove(s);
    }
    visited
}

/// Returns all ancestors of the given starting vertices.
///
/// An ancestor is any vertex reachable by following in-edges backwards
/// from the starting set, excluding the starting vertices themselves.
pub fn get_ancestors<V, E>(g: &dyn GDirectedGraph<V, E>, starts: &[V]) -> HashSet<V>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let starts_set: HashSet<V> = starts.iter().cloned().collect();
    let mut visited = HashSet::new();
    let mut stack: Vec<V> = starts.to_vec();
    while let Some(v) = stack.pop() {
        if !visited.insert(v.clone()) {
            continue;
        }
        for pred in g.get_predecessors(&v) {
            if !visited.contains(&pred) {
                stack.push(pred);
            }
        }
    }
    // Remove the starting vertices from the result
    for s in &starts_set {
        visited.remove(s);
    }
    visited
}

/// Returns all entry points in the graph.
///
/// Entry points are source vertices that are not descendants of any
/// other source vertex.
pub fn get_entry_points<V, E>(g: &dyn GDirectedGraph<V, E>) -> HashSet<V>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let sources = get_sources(g);
    let source_vec: Vec<V> = sources.iter().cloned().collect();
    let descendants = get_descendants(g, &source_vec);
    let all_vertices = g.get_vertices();
    let mut isolated = all_vertices.clone();
    for s in &sources {
        isolated.remove(s);
    }
    for d in &descendants {
        isolated.remove(d);
    }
    let mut result = sources;
    for v in isolated {
        if g.get_in_edges(&v).is_empty() {
            result.insert(v);
        }
    }
    result
}

/// Compute the density of the graph.
///
/// Density = E / (V * (V - 1)) for directed graphs.
pub fn density<V, E>(g: &dyn GDirectedGraph<V, E>) -> f64
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let v = g.get_vertex_count() as f64;
    let e = g.get_edge_count() as f64;
    if v <= 1.0 {
        return 0.0;
    }
    e / (v * (v - 1.0))
}

/// Extract the set of unique vertices from a collection of edges.
pub fn to_vertices<V, E>(edges: &[E]) -> HashSet<V>
where
    V: Clone + Debug + Eq + Hash,
    E: GEdge<V>,
{
    let mut vertices = HashSet::new();
    for e in edges {
        vertices.insert(e.start().clone());
        vertices.insert(e.end().clone());
    }
    vertices
}

/// Get edges from the given vertices.
///
/// If `outgoing` is true, returns out-edges; otherwise returns in-edges.
pub fn get_edges_from<V, E>(
    g: &dyn GDirectedGraph<V, E>,
    vertices: &[V],
    outgoing: bool,
) -> Vec<E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let mut result = Vec::new();
    for v in vertices {
        let edges = if outgoing {
            g.get_out_edges(v)
        } else {
            g.get_in_edges(v)
        };
        result.extend(edges);
    }
    result
}

/// Get the neighbors of the given vertices.
///
/// Returns all vertices that are either predecessors or successors of
/// any vertex in the input set.
pub fn get_neighbors<V, E>(g: &dyn GDirectedGraph<V, E>, vertices: &[V]) -> HashSet<V>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let mut result = HashSet::new();
    for v in vertices {
        result.extend(g.get_predecessors(v));
        result.extend(g.get_successors(v));
    }
    // Remove the input vertices themselves
    for v in vertices {
        result.remove(v);
    }
    result
}

/// Get all incident edges (in + out) for the given vertices.
pub fn get_incident_edges<V, E>(g: &dyn GDirectedGraph<V, E>, vertices: &[V]) -> Vec<E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let mut result = Vec::new();
    for v in vertices {
        result.extend(g.get_in_edges(v));
        result.extend(g.get_out_edges(v));
    }
    result
}

/// Check whether the graph contains any self-loops (edges from a vertex to itself).
pub fn has_self_loops<V, E>(g: &dyn GDirectedGraph<V, E>) -> bool
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    for e in g.get_edges() {
        if e.start() == e.end() {
            return true;
        }
    }
    false
}

/// Return all self-loop edges in the graph.
pub fn get_self_loops<V, E>(g: &dyn GDirectedGraph<V, E>) -> Vec<E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    g.get_edges()
        .into_iter()
        .filter(|e| e.start() == e.end())
        .collect()
}

/// Compute BFS distances from a set of start vertices.
///
/// Returns a map from vertex to distance (unreachable vertices are absent).
pub fn bfs_distances<V, E>(
    g: &dyn GDirectedGraph<V, E>,
    starts: &[V],
) -> HashMap<V, usize>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let mut distances = HashMap::new();
    let mut queue = VecDeque::new();

    for v in starts {
        distances.insert(v.clone(), 0);
        queue.push_back(v.clone());
    }

    while let Some(current) = queue.pop_front() {
        let current_dist = distances[&current];
        for succ in g.get_successors(&current) {
            if !distances.contains_key(&succ) {
                distances.insert(succ.clone(), current_dist + 1);
                queue.push_back(succ);
            }
        }
    }

    distances
}

/// Check whether two graphs are structurally equivalent (same vertices and edges).
pub fn graphs_equal<V, E>(a: &dyn GDirectedGraph<V, E>, b: &dyn GDirectedGraph<V, E>) -> bool
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let a_verts = a.get_vertices();
    let b_verts = b.get_vertices();
    if a_verts != b_verts {
        return false;
    }
    let a_edges = a.get_edges();
    let b_edges = b.get_edges();
    if a_edges.len() != b_edges.len() {
        return false;
    }
    // Check every edge in a exists in b
    for e in &a_edges {
        if !b.contains_edge(e) {
            return false;
        }
    }
    true
}

/// Compute the transitive closure of the graph from a set of start vertices.
///
/// Returns all vertices reachable from any start vertex (including the starts).
pub fn transitive_closure<V, E>(
    g: &dyn GDirectedGraph<V, E>,
    starts: &[V],
) -> HashSet<V>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let mut visited = HashSet::new();
    let mut stack: Vec<V> = starts.to_vec();
    for v in starts {
        visited.insert(v.clone());
    }
    while let Some(v) = stack.pop() {
        for succ in g.get_successors(&v) {
            if visited.insert(succ.clone()) {
                stack.push(succ);
            }
        }
    }
    visited
}

/// Compute the reverse transitive closure (all vertices that can reach
/// any of the target vertices).
pub fn reverse_transitive_closure<V, E>(
    g: &dyn GDirectedGraph<V, E>,
    targets: &[V],
) -> HashSet<V>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let mut visited = HashSet::new();
    let mut stack: Vec<V> = targets.to_vec();
    for v in targets {
        visited.insert(v.clone());
    }
    while let Some(v) = stack.pop() {
        for pred in g.get_predecessors(&v) {
            if visited.insert(pred.clone()) {
                stack.push(pred);
            }
        }
    }
    visited
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::default_edge::DefaultGEdge;
    use crate::graph::hash_graph::HashDirectedGraph;

    fn make_chain_graph() -> HashDirectedGraph<i32, DefaultGEdge<i32>> {
        let mut g = HashDirectedGraph::new();
        for v in 0..5 {
            g.add_vertex(v);
        }
        g.add_edge(DefaultGEdge::new(0, 1));
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(2, 3));
        g.add_edge(DefaultGEdge::new(3, 4));
        g
    }

    fn make_diamond_graph() -> HashDirectedGraph<i32, DefaultGEdge<i32>> {
        let mut g = HashDirectedGraph::new();
        for v in [0, 1, 2, 3] {
            g.add_vertex(v);
        }
        g.add_edge(DefaultGEdge::new(0, 1));
        g.add_edge(DefaultGEdge::new(0, 2));
        g.add_edge(DefaultGEdge::new(1, 3));
        g.add_edge(DefaultGEdge::new(2, 3));
        g
    }

    #[test]
    fn test_sources() {
        let g = make_chain_graph();
        let sources = get_sources(&g);
        assert_eq!(sources.len(), 1);
        assert!(sources.contains(&0));
    }

    #[test]
    fn test_sinks() {
        let g = make_chain_graph();
        let sinks = get_sinks(&g);
        assert_eq!(sinks.len(), 1);
        assert!(sinks.contains(&4));
    }

    #[test]
    fn test_descendants() {
        let g = make_diamond_graph();
        let desc = get_descendants(&g, &[0]);
        assert_eq!(desc.len(), 3);
        assert!(desc.contains(&1));
        assert!(desc.contains(&2));
        assert!(desc.contains(&3));
    }

    #[test]
    fn test_ancestors() {
        let g = make_diamond_graph();
        let anc = get_ancestors(&g, &[3]);
        assert_eq!(anc.len(), 3);
        assert!(anc.contains(&0));
        assert!(anc.contains(&1));
        assert!(anc.contains(&2));
    }

    #[test]
    fn test_density() {
        let g = make_chain_graph();
        let d = density(&g);
        assert!((d - 0.2).abs() < 1e-10);
    }

    #[test]
    fn test_density_single_vertex() {
        let mut g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(1);
        assert_eq!(density(&g), 0.0);
    }

    #[test]
    fn test_to_vertices() {
        let edges = vec![DefaultGEdge::new(1, 2), DefaultGEdge::new(2, 3)];
        let verts = to_vertices(&edges);
        assert_eq!(verts.len(), 3);
    }

    #[test]
    fn test_entry_points() {
        let g = make_diamond_graph();
        let ep = get_entry_points(&g);
        assert!(ep.contains(&0));
    }

    #[test]
    fn test_get_edges_from_outgoing() {
        let g = make_diamond_graph();
        let out_edges = get_edges_from(&g, &[0], true);
        assert_eq!(out_edges.len(), 2);
    }

    #[test]
    fn test_get_edges_from_incoming() {
        let g = make_diamond_graph();
        let in_edges = get_edges_from(&g, &[3], false);
        assert_eq!(in_edges.len(), 2);
    }

    #[test]
    fn test_empty_graph() {
        let g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        assert!(get_sources(&g).is_empty());
        assert!(get_sinks(&g).is_empty());
        assert_eq!(density(&g), 0.0);
    }

    #[test]
    fn test_get_neighbors() {
        let g = make_diamond_graph();
        let neighbors = get_neighbors(&g, &[1]);
        assert!(neighbors.contains(&0));
        assert!(neighbors.contains(&3));
        assert_eq!(neighbors.len(), 2);
    }

    #[test]
    fn test_get_incident_edges() {
        let g = make_diamond_graph();
        let incident = get_incident_edges(&g, &[0]);
        assert_eq!(incident.len(), 2); // 0->1, 0->2
    }

    #[test]
    fn test_has_self_loops_false() {
        let g = make_chain_graph();
        assert!(!has_self_loops(&g));
    }

    #[test]
    fn test_has_self_loops_true() {
        let mut g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(1);
        g.add_edge(DefaultGEdge::new(1, 1));
        assert!(has_self_loops(&g));
    }

    #[test]
    fn test_get_self_loops() {
        let mut g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(1);
        g.add_vertex(2);
        g.add_edge(DefaultGEdge::new(1, 1));
        g.add_edge(DefaultGEdge::new(1, 2));
        let loops = get_self_loops(&g);
        assert_eq!(loops.len(), 1);
    }

    #[test]
    fn test_bfs_distances() {
        let g = make_diamond_graph();
        let dists = bfs_distances(&g, &[0]);
        assert_eq!(dists.get(&0), Some(&0));
        assert_eq!(dists.get(&1), Some(&1));
        assert_eq!(dists.get(&2), Some(&1));
        assert_eq!(dists.get(&3), Some(&2));
    }

    #[test]
    fn test_graphs_equal() {
        let a = make_chain_graph();
        let b = make_chain_graph();
        assert!(graphs_equal(&a, &b));
    }

    #[test]
    fn test_graphs_not_equal() {
        let a = make_chain_graph();
        let mut b = make_chain_graph();
        b.add_edge(DefaultGEdge::new(4, 0));
        assert!(!graphs_equal(&a, &b));
    }

    #[test]
    fn test_transitive_closure() {
        let g = make_chain_graph();
        let tc = transitive_closure(&g, &[0]);
        assert_eq!(tc.len(), 5); // all reachable from 0
    }

    #[test]
    fn test_reverse_transitive_closure() {
        let g = make_chain_graph();
        let rtc = reverse_transitive_closure(&g, &[4]);
        assert_eq!(rtc.len(), 5); // all can reach 4
    }
}
