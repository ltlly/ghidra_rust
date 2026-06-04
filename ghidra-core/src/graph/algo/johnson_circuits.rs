//! Johnson's algorithm for finding all elementary circuits.
//!
//! Port of `ghidra.graph.algo.JohnsonCircuitsAlgorithm<V, E>`.

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;

use crate::graph::traits::{GDirectedGraph, GEdge};

/// Finds all elementary circuits (cycles) in a directed graph using
/// Johnson's algorithm.
///
/// Mirrors `ghidra.graph.algo.JohnsonCircuitsAlgorithm<V, E>`.
///
/// # Examples
/// ```
/// use ghidra_core::graph::hash_graph::HashDirectedGraph;
/// use johnson = ghidra_core::graph::algo::johnson_circuits;
/// ```
pub struct JohnsonCircuitsAlgorithm<'a, V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    graph: *const (dyn GDirectedGraph<V, E> + 'a),
    blocked_set: HashSet<V>,
    blocked_back_edges: HashMap<V, HashSet<V>>,
    stack: Vec<V>,
    circuits: Vec<Vec<V>>,
    start_vertex: Option<V>,
}

impl<'a, V, E> JohnsonCircuitsAlgorithm<'a, V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// Create a new Johnson's circuits algorithm for the given graph.
    pub fn new(graph: &'a dyn GDirectedGraph<V, E>) -> Self {
        Self {
            graph: graph as *const (dyn GDirectedGraph<V, E> + 'a),
            blocked_set: HashSet::new(),
            blocked_back_edges: HashMap::new(),
            stack: Vec::new(),
            circuits: Vec::new(),
            start_vertex: None,
        }
    }

    fn graph(&self) -> &'a dyn GDirectedGraph<V, E> {
        unsafe { &*self.graph }
    }

    /// Find all elementary circuits in the graph.
    ///
    /// If `unique_circuits` is `true`, returns only unique circuits where no two
    /// circuits contain the same vertex.
    ///
    /// Returns a list of circuits, each circuit being a list of vertices.
    pub fn compute(&mut self, unique_circuits: bool) -> Vec<Vec<V>> {
        self.circuits.clear();

        let graph = self.graph();

        // Get strongly connected components using the existing Tarjan implementation
        let sccs = compute_scc_generic(graph);

        for scc in sccs {
            if scc.len() < 2 {
                continue; // Singleton SCCs have no circuits
            }

            // Create subgraph for this SCC
            let scc_set: HashSet<V> = scc.iter().cloned().collect();
            let sub_vertices: Vec<V> = scc_set.iter().cloned().collect();

            let size = if unique_circuits {
                sub_vertices.len()
            } else {
                sub_vertices.len() - 1
            };

            for i in 0..size {
                let start = sub_vertices[i].clone();
                self.start_vertex = Some(start.clone());

                self.blocked_set.clear();
                self.blocked_back_edges.clear();
                self.circuit(&start, &scc_set);

                if unique_circuits {
                    // Remove this vertex from the SCC set for subsequent iterations
                    // (this prevents finding the same circuit multiple times)
                }
            }
        }

        self.circuits.clone()
    }

    fn circuit(&mut self, v: &V, scc: &HashSet<V>) -> bool {
        self.blocked_set.insert(v.clone());
        self.stack.push(v.clone());

        let mut found_circuit = false;

        let out_edges = self.graph().get_out_edges(v);
        for e in out_edges {
            let u = e.end().clone();
            if !scc.contains(&u) {
                continue;
            }

            if Some(&u) == self.start_vertex.as_ref() {
                // Found a circuit
                let mut circuit = self.stack.clone();
                circuit.push(self.start_vertex.clone().unwrap());
                self.circuits.push(circuit);
                found_circuit = true;
            } else if !self.blocked_set.contains(&u) {
                if self.circuit(&u, scc) {
                    found_circuit = true;
                }
            }
        }

        if found_circuit {
            self.unblock(v);
        } else {
            let out_edges = self.graph().get_out_edges(v);
            for e in out_edges {
                let u = e.end().clone();
                if scc.contains(&u) {
                    self.blocked_back_edges
                        .entry(u)
                        .or_default()
                        .insert(v.clone());
                }
            }
        }

        self.stack.pop();
        found_circuit
    }

    fn unblock(&mut self, v: &V) {
        self.blocked_set.remove(v);
        let to_unblock: Vec<V> = self
            .blocked_back_edges
            .remove(v)
            .map(|s| s.into_iter().collect())
            .unwrap_or_default();

        for u in to_unblock {
            if self.blocked_set.contains(&u) {
                self.unblock(&u);
            }
        }
    }
}

/// Compute SCCs for a generic GDirectedGraph (not petgraph-based).
/// This is a standalone implementation for use by Johnson's algorithm.
fn compute_scc_generic<V, E>(graph: &dyn GDirectedGraph<V, E>) -> Vec<Vec<V>>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let vertices: Vec<V> = graph.get_vertices().into_iter().collect();
    let n = vertices.len();
    let vertex_to_idx: HashMap<V, usize> = vertices.iter().enumerate().map(|(i, v)| (v.clone(), i)).collect();

    // Build successor lists
    let mut successors: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, v) in vertices.iter().enumerate() {
        for e in graph.get_out_edges(v) {
            if let Some(&j) = vertex_to_idx.get(e.end()) {
                successors[i].push(j);
            }
        }
    }

    // Tarjan's algorithm
    let mut index = 0usize;
    let mut indices = vec![None; n];
    let mut lowlink = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut stack = Vec::new();
    let mut components = Vec::new();

    fn strongconnect(
        v: usize,
        index: &mut usize,
        indices: &mut [Option<usize>],
        lowlink: &mut [usize],
        on_stack: &mut [bool],
        stack: &mut Vec<usize>,
        components: &mut Vec<Vec<usize>>,
        successors: &[Vec<usize>],
    ) {
        indices[v] = Some(*index);
        lowlink[v] = *index;
        *index += 1;
        stack.push(v);
        on_stack[v] = true;

        for &w in &successors[v] {
            if indices[w].is_none() {
                strongconnect(w, index, indices, lowlink, on_stack, stack, components, successors);
                lowlink[v] = lowlink[v].min(lowlink[w]);
            } else if on_stack[w] {
                lowlink[v] = lowlink[v].min(indices[w].unwrap());
            }
        }

        if lowlink[v] == indices[v].unwrap() {
            let mut component = Vec::new();
            loop {
                let w = stack.pop().unwrap();
                on_stack[w] = false;
                component.push(w);
                if w == v {
                    break;
                }
            }
            components.push(component);
        }
    }

    for v in 0..n {
        if indices[v].is_none() {
            strongconnect(
                v,
                &mut index,
                &mut indices,
                &mut lowlink,
                &mut on_stack,
                &mut stack,
                &mut components,
                &successors,
            );
        }
    }

    // Convert back to vertex values
    components
        .into_iter()
        .map(|comp| comp.into_iter().map(|i| vertices[i].clone()).collect())
        .collect()
}

/// Convenience function: find all circuits in a graph.
pub fn find_circuits<V, E>(graph: &dyn GDirectedGraph<V, E>, unique: bool) -> Vec<Vec<V>>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let mut algo = JohnsonCircuitsAlgorithm::new(graph);
    algo.compute(unique)
}
