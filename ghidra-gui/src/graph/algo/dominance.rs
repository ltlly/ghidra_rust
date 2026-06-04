//! Dominator and post-dominator computation.
//!
//! Ports `ghidra.graph.algo.AbstractDominanceAlgorithm`,
//! `ChkDominanceAlgorithm`, and `ChkPostDominanceAlgorithm`.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use crate::graph::{GDirectedGraph, GEdge};

/// Result of a dominator / post-dominator computation.
#[derive(Debug, Clone)]
pub struct DominatorResult<V: Eq + Hash + Clone> {
    /// For each vertex, the set of dominators.
    dominators: HashMap<V, HashSet<V>>,
    /// The immediate dominator for each vertex (None for the entry node).
    idom: HashMap<V, Option<V>>,
}

impl<V: Eq + Hash + Clone> DominatorResult<V> {
    /// The dominators of vertex `v`.  Returns an empty set if `v` is unknown.
    pub fn dominators(&self, v: &V) -> &HashSet<V> {
        self.dominators.get(v).unwrap_or_else(|| {
            // Return a leaked empty set. This is safe because we never mutate
            // the returned reference, and empty sets are zero-sized allocations.
            static EMPTY: std::sync::OnceLock<HashSet<u8>> = std::sync::OnceLock::new();
            let _ = EMPTY.set(HashSet::new());
            unsafe { std::mem::transmute::<&HashSet<u8>, &HashSet<V>>(EMPTY.get().unwrap()) }
        })
    }

    /// The immediate dominator of vertex `v` (None for the entry node).
    pub fn immediate_dominator(&self, v: &V) -> Option<&V> {
        self.idom.get(v).and_then(|opt| opt.as_ref())
    }

    /// Whether `a` dominates `b`.
    pub fn dominates(&self, a: &V, b: &V) -> bool {
        self.dominators(b).contains(a)
    }
}

/// Dominance algorithm.
pub struct DominanceAlgorithm;

impl DominanceAlgorithm {
    /// Compute the dominator tree for all vertices reachable from `entry`.
    ///
    /// Uses the iterative data-flow algorithm (the "CHK" algorithm).
    pub fn compute_dominators<V, E, G>(graph: &G, entry: &V) -> DominatorResult<V>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        let all_vertices: HashSet<V> = graph.vertices().into_iter().collect();
        let mut dominators: HashMap<V, HashSet<V>> = HashMap::new();

        // Initialize: entry dominates itself; all others dominated by everything.
        for v in &all_vertices {
            if v == entry {
                dominators.insert(v.clone(), HashSet::from([v.clone()]));
            } else {
                dominators.insert(v.clone(), all_vertices.clone());
            }
        }

        // Iterate until fixed point.
        let mut changed = true;
        while changed {
            changed = false;
            for v in &all_vertices {
                if v == entry {
                    continue;
                }

                let preds = graph.predecessors(v);
                if preds.is_empty() {
                    continue;
                }

                // Intersect dominators of all predecessors.
                let mut new_dom = dominators[&preds[0]].clone();
                for pred in &preds[1..] {
                    new_dom = new_dom
                        .intersection(&dominators[pred])
                        .cloned()
                        .collect();
                }
                new_dom.insert(v.clone());

                if new_dom != dominators[v] {
                    dominators.insert(v.clone(), new_dom);
                    changed = true;
                }
            }
        }

        // Compute immediate dominators.
        let mut idom: HashMap<V, Option<V>> = HashMap::new();
        for v in &all_vertices {
            if v == entry {
                idom.insert(v.clone(), None);
                continue;
            }
            let doms = &dominators[v];
            // Immediate dominator: the strict dominator of v that is not
            // dominated by any other strict dominator of v.
            let strict_doms: Vec<&V> = doms.iter().filter(|d| *d != v).collect();
            let imm = strict_doms.iter().find(|&&candidate| {
                strict_doms.iter().all(|&other| {
                    other == candidate || !dominators[other].contains(candidate)
                })
            });
            idom.insert(v.clone(), imm.map(|&c| c.clone()));
        }

        DominatorResult { dominators, idom }
    }

    /// Compute post-dominators by reversing the graph direction.
    ///
    /// A node `a` post-dominates `b` if every path from `b` to the exit
    /// passes through `a`.
    pub fn compute_post_dominators<V, E, G>(graph: &G, exit: &V) -> DominatorResult<V>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        // For post-dominance, we treat predecessors as successors and
        // vice versa. We do this by building a reversed graph.
        let mut reversed = crate::graph::DefaultDirectedGraph::new();
        for v in graph.vertices() {
            reversed.add_vertex(v);
        }
        for e in graph.edges() {
            reversed.add_edge(crate::graph::DefaultGEdge::new(
                e.end().clone(),
                e.start().clone(),
            ));
        }
        Self::compute_dominators(&reversed, exit)
    }
}
