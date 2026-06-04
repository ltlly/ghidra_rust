//! Dijkstra's shortest-paths algorithm.
//!
//! Ports `ghidra.graph.algo.DijkstraShortestPathsAlgorithm`.

use std::collections::{BinaryHeap, HashMap};
use std::cmp::Ordering;
use std::hash::Hash;

use crate::graph::{GDirectedGraph, GEdge, GWeightedEdge};

/// Result of Dijkstra's algorithm from a single source.
#[derive(Debug, Clone)]
pub struct DijkstraResult<V: Eq + Hash + Clone> {
    /// Shortest distance from the source to each reachable vertex.
    pub distances: HashMap<V, f64>,
    /// Predecessor edge for reconstructing shortest paths.
    pub predecessors: HashMap<V, V>,
}

impl<V: Eq + Hash + Clone> DijkstraResult<V> {
    /// Shortest distance to `v`, or `None` if unreachable.
    pub fn distance(&self, v: &V) -> Option<f64> {
        self.distances.get(v).copied()
    }

    /// Reconstruct the shortest path from the source to `target`.
    pub fn path_to(&self, target: &V) -> Option<Vec<V>> {
        if !self.distances.contains_key(target) {
            return None;
        }
        let mut path = vec![target.clone()];
        let mut current = target;
        while let Some(pred) = self.predecessors.get(current) {
            path.push(pred.clone());
            current = pred;
        }
        path.reverse();
        Some(path)
    }
}

/// Dijkstra's single-source shortest-paths algorithm on a weighted directed graph.
pub struct Dijkstra;

impl Dijkstra {
    /// Compute shortest paths from `source` to all reachable vertices.
    ///
    /// Edge weights must be non-negative.
    pub fn shortest_paths<V, G>(graph: &G, source: &V) -> DijkstraResult<V>
    where
        V: Eq + Hash + Clone,
        G: GDirectedGraph<V, GWeightedEdge<V>>,
    {
        let mut distances: HashMap<V, f64> = HashMap::new();
        let mut predecessors: HashMap<V, V> = HashMap::new();
        let mut heap = BinaryHeap::new();

        distances.insert(source.clone(), 0.0);
        heap.push(State {
            cost: 0.0,
            vertex: source.clone(),
        });

        while let Some(State { cost, vertex }) = heap.pop() {
            // Skip if we already found a better path.
            if let Some(&best) = distances.get(&vertex) {
                if cost > best {
                    continue;
                }
            }

            for edge in graph.out_edges(&vertex) {
                let next_cost = cost + edge.weight();
                let next_vertex = edge.end().clone();

                let is_better = distances
                    .get(&next_vertex)
                    .map_or(true, |&current| next_cost < current);

                if is_better {
                    distances.insert(next_vertex.clone(), next_cost);
                    predecessors.insert(next_vertex.clone(), vertex.clone());
                    heap.push(State {
                        cost: next_cost,
                        vertex: next_vertex,
                    });
                }
            }
        }

        DijkstraResult {
            distances,
            predecessors,
        }
    }
}

#[derive(Debug)]
struct State<V> {
    cost: f64,
    vertex: V,
}

impl<V: Eq> PartialEq for State<V> {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost && self.vertex == other.vertex
    }
}

impl<V: Eq> Eq for State<V> {}

impl<V: Eq> PartialOrd for State<V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<V: Eq> Ord for State<V> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Min-heap: reverse the comparison.
        other
            .cost
            .partial_cmp(&self.cost)
            .unwrap_or(Ordering::Equal)
    }
}
