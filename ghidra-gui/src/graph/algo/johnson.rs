//! Johnson's algorithm for finding all elementary circuits.
//!
//! Ports `ghidra.graph.algo.JohnsonCircuitsAlgorithm`.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use crate::graph::{GDirectedGraph, GEdge};

/// Johnson's circuit-finding algorithm.
///
/// Finds all elementary circuits (simple cycles) in a directed graph.
pub struct JohnsonCircuits;

impl JohnsonCircuits {
    /// Find all elementary circuits in the graph.
    ///
    /// Each circuit is returned as a `Vec` of vertices in cycle order.
    pub fn find_circuits<V, E, G>(graph: &G) -> Vec<Vec<V>>
    where
        V: Eq + Hash + Clone + Ord,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        let mut all_circuits = Vec::new();
        let mut blocked: HashSet<V> = HashSet::new();
        let mut b: HashMap<V, HashSet<V>> = HashMap::new();
        let mut stack: Vec<V> = Vec::new();

        // Get sorted vertices for deterministic ordering.
        let mut vertices = graph.vertices();
        vertices.sort();

        let mut s_index = 0;
        while s_index < vertices.len() {
            let s = &vertices[s_index];

            // Build the subgraph SCC from s onwards.
            let subgraph_vertices: Vec<V> = vertices[s_index..].to_vec();
            blocked.clear();
            b.clear();

            Self::circuit(
                s.clone(),
                s,
                graph,
                &subgraph_vertices,
                &mut blocked,
                &mut b,
                &mut stack,
                &mut all_circuits,
            );

            // Remove s from further consideration.
            s_index += 1;
        }

        all_circuits
    }

    fn circuit<V, E, G>(
        v: V,
        s: &V,
        graph: &G,
        allowed: &[V],
        blocked: &mut HashSet<V>,
        b: &mut HashMap<V, HashSet<V>>,
        stack: &mut Vec<V>,
        circuits: &mut Vec<Vec<V>>,
    ) -> bool
    where
        V: Eq + Hash + Clone + Ord,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        let allowed_set: HashSet<&V> = allowed.iter().collect();
        let mut found_circuit = false;

        stack.push(v.clone());
        blocked.insert(v.clone());

        // Collect neighbours in allowed subgraph.
        let neighbours: Vec<V> = graph
            .out_edges(&v)
            .into_iter()
            .map(|e| e.end().clone())
            .filter(|w| allowed_set.contains(w))
            .collect();

        for w in &neighbours {
            if w == s {
                // Found a circuit.
                let mut circuit = stack.clone();
                circuit.push(s.clone());
                circuits.push(circuit);
                found_circuit = true;
            } else if !blocked.contains(w) {
                if Self::circuit(w.clone(), s, graph, allowed, blocked, b, stack, circuits) {
                    found_circuit = true;
                }
            }
        }

        if found_circuit {
            Self::unblock(&v, blocked, b);
        } else {
            for w in &neighbours {
                b.entry(w.clone())
                    .or_default()
                    .insert(v.clone());
            }
        }

        stack.pop();
        found_circuit
    }

    fn unblock<V: Eq + Hash + Clone>(v: &V, blocked: &mut HashSet<V>, b: &mut HashMap<V, HashSet<V>>) {
        blocked.remove(v);
        if let Some(blockers) = b.remove(v) {
            for w in blockers {
                if blocked.contains(&w) {
                    Self::unblock(&w, blocked, b);
                }
            }
        }
    }
}
