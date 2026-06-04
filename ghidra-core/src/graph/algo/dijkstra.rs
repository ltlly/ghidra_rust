//! Dijkstra's shortest-path algorithm.
//!
//! Port of `ghidra.graph.algo.DijkstraShortestPathsAlgorithm<V, E>`.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;

use crate::graph::edge_weight::GEdgeWeightMetric;
use crate::graph::traits::{GEdge, GImplicitDirectedGraph};

/// Dijkstra's single-source shortest-path algorithm.
///
/// Computes the shortest paths from given source vertices to all reachable
/// destinations. Caches results per source so repeated queries from the same
/// source are cheap.
///
/// Returns all tied shortest paths (not just one arbitrary choice).
///
/// Mirrors `ghidra.graph.algo.DijkstraShortestPathsAlgorithm<V, E>`.
pub struct DijkstraShortestPaths<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    max_distance: f64,
    /// Cached one-source-to-all results.
    sources: HashMap<V, OneSourceToAll<V, E>>,
}

struct OneSourceToAll<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    visited_distance: HashMap<V, f64>,
    best_ins: HashMap<V, Vec<E>>,
}

impl<V, E> DijkstraShortestPaths<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// Create a new Dijkstra algorithm.
    pub fn new(max_distance: f64) -> Self {
        Self {
            max_distance,
            sources: HashMap::new(),
        }
    }

    /// Create with infinite max distance.
    pub fn new_unbounded() -> Self {
        Self::new(f64::INFINITY)
    }

    /// Compute the shortest distances from source to all reachable vertices.
    pub fn get_distances_from_source<M: GEdgeWeightMetric<E>>(
        &mut self,
        graph: &dyn GImplicitDirectedGraph<V, E>,
        source: &V,
        metric: &M,
    ) -> &HashMap<V, f64> {
        if !self.sources.contains_key(source) {
            self.compute_from_source(graph, source.clone(), metric);
        }
        &self.sources.get(source).unwrap().visited_distance
    }

    /// Compute all shortest paths from `src` to `dst`.
    pub fn compute_optimal_paths<M: GEdgeWeightMetric<E>>(
        &mut self,
        graph: &dyn GImplicitDirectedGraph<V, E>,
        src: &V,
        dst: &V,
        metric: &M,
    ) -> Vec<VecDeque<E>> {
        if !self.sources.contains_key(src) {
            self.compute_from_source(graph, src.clone(), metric);
        }
        self.sources
            .get(src)
            .unwrap()
            .compute_optimal_paths_to(dst)
            .into()
    }

    fn compute_from_source<M: GEdgeWeightMetric<E>>(
        &mut self,
        graph: &dyn GImplicitDirectedGraph<V, E>,
        source: V,
        metric: &M,
    ) {
        let mut visited_distance: HashMap<V, f64> = HashMap::new();
        let mut best_ins: HashMap<V, Vec<E>> = HashMap::new();

        let mut queue: BTreeMap<OrderedFloat, Vec<V>> = BTreeMap::new();
        let mut queue_distances: HashMap<V, f64> = HashMap::new();

        queue_distances.insert(source.clone(), 0.0);
        queue
            .entry(OrderedFloat(0.0))
            .or_default()
            .push(source.clone());

        while let Some((&dist_key, vertices)) = queue.iter_mut().next() {
            let dist = dist_key.0;
            let v = if let Some(v) = vertices.pop() {
                v
            } else {
                queue.remove(&dist_key);
                continue;
            };
            if vertices.is_empty() {
                queue.remove(&dist_key);
            }

            if visited_distance.contains_key(&v) {
                continue;
            }

            visited_distance.insert(v.clone(), dist);

            for e in graph.get_out_edges(&v) {
                let dest = e.end().clone();
                let edge_weight = metric.compute_weight(&e);
                let new_dist = dist + edge_weight;

                if new_dist > self.max_distance {
                    continue;
                }

                if !visited_distance.contains_key(&dest) {
                    let current_best = queue_distances.get(&dest).copied();

                    match current_best {
                        None => {
                            queue_distances.insert(dest.clone(), new_dist);
                            queue
                                .entry(OrderedFloat(new_dist))
                                .or_default()
                                .push(dest.clone());
                            best_ins.insert(dest, vec![e]);
                        }
                        Some(cur) if new_dist < cur => {
                            queue_distances.insert(dest.clone(), new_dist);
                            best_ins.insert(dest.clone(), vec![e]);
                            queue
                                .entry(OrderedFloat(new_dist))
                                .or_default()
                                .push(dest);
                        }
                        Some(cur) if (new_dist - cur).abs() < f64::EPSILON => {
                            best_ins.entry(dest).or_default().push(e);
                        }
                        _ => {}
                    }
                }
            }
        }

        self.sources.insert(
            source,
            OneSourceToAll {
                visited_distance,
                best_ins,
            },
        );
    }
}

impl<V, E> OneSourceToAll<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    fn compute_optimal_paths_to(&self, dst: &V) -> VecDeque<VecDeque<E>> {
        let mut paths = VecDeque::new();
        if self.visited_distance.contains_key(dst) {
            self.add_paths_to(&mut paths, dst, &mut VecDeque::new());
        }
        paths
    }

    fn add_paths_to(
        &self,
        paths: &mut VecDeque<VecDeque<E>>,
        prev: &V,
        so_far: &mut VecDeque<E>,
    ) {
        if !self.best_ins.contains_key(prev) {
            paths.push_back(so_far.clone());
            return;
        }

        if let Some(edges) = self.best_ins.get(prev) {
            for e in edges {
                let next_prev = e.start().clone();
                so_far.push_front(e.clone());
                self.add_paths_to(paths, &next_prev, so_far);
                so_far.pop_front();
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct OrderedFloat(f64);

impl PartialEq for OrderedFloat {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for OrderedFloat {}

impl PartialOrd for OrderedFloat {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderedFloat {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .partial_cmp(&other.0)
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}

impl Hash for OrderedFloat {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}
