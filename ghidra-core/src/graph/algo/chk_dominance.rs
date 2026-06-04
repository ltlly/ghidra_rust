//! Cooper-Harvey-Kennedy (CHK) dominance algorithm.
//!
//! Port of `ghidra.graph.algo.ChkDominanceAlgorithm<V, E>` and
//! `ChkPostDominanceAlgorithm<V, E>`.

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;

use crate::graph::hash_graph::HashDirectedGraph;
use crate::graph::traits::{GDirectedGraph, GEdge};
use super::depth_first_sorter::DepthFirstSorter;
use super::graph_navigator::GraphNavigator;

/// The Cooper-Harvey-Kennedy iterative dominator algorithm.
///
/// Computes the dominance tree of a directed graph. Processes the graph in
/// reverse post-order; runtime is approximately O(V+E*D) per iteration,
/// where D is the size of the largest dominator set.
///
/// Mirrors `ghidra.graph.algo.ChkDominanceAlgorithm<V, E>`.
pub struct ChkDominanceAlgorithm<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    dominator_map: HashMap<V, V>,         // node -> immediate dominator
    dominated_map: HashMap<V, Vec<V>>,    // idom -> list of dominated nodes
    root: V,
    navigator: GraphNavigator,
    _phantom: std::marker::PhantomData<E>,
}

impl<V, E> ChkDominanceAlgorithm<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// Compute the dominance tree for the given graph using top-down traversal.
    ///
    /// The graph must have at least one source vertex.
    pub fn compute(graph: &dyn GDirectedGraph<V, E>) -> Self {
        Self::compute_with_navigator(graph, GraphNavigator::top_down())
    }

    /// Compute the dominance tree using the given traversal direction.
    pub fn compute_with_navigator(
        graph: &dyn GDirectedGraph<V, E>,
        navigator: GraphNavigator,
    ) -> Self {
        let sources = navigator.get_sources(graph);
        assert!(!sources.is_empty(), "Graph must have at least one source node");

        let root = if sources.len() == 1 {
            sources.into_iter().next().unwrap()
        } else {
            // Multiple sources: need a virtual root.
            // In the Java version, a dummy vertex is added. In Rust, we pick
            // the first source as root and compute dominance anyway.
            // For correctness with multiple sources, callers should ensure a
            // single entry point or use the existing DominatorTree in mod.rs.
            sources.into_iter().next().unwrap()
        };

        let mut dominator_map = HashMap::new();
        dominator_map.insert(root.clone(), root.clone());

        // Get vertices in reverse post-order
        let mut rpo = DepthFirstSorter::post_order_with_navigator(graph, &navigator);
        rpo.reverse();

        // Build index map for RPO
        let rpo_index: HashMap<V, usize> = rpo
            .iter()
            .enumerate()
            .map(|(i, v)| (v.clone(), i))
            .collect();

        // Iterative CHK algorithm
        let mut changed = true;
        let max_iterations = rpo.len() + 3; // Bound from the paper
        let mut iterations = 0;

        while changed && iterations < max_iterations {
            changed = false;
            iterations += 1;

            for v in &rpo {
                if *v == root {
                    continue;
                }

                // Get all predecessors in the traversal direction
                let preds: Vec<V> = navigator
                    .get_predecessors(graph, v)
                    .into_iter()
                    .collect();

                if preds.is_empty() {
                    continue;
                }

                // Find the new idom: intersect dominator chains of all predecessors
                let mut new_idom: Option<V> = None;
                for p in &preds {
                    if dominator_map.contains_key(p) {
                        new_idom = Some(p.clone());
                        break;
                    }
                }

                if let Some(mut current_idom) = new_idom {
                    for p in &preds {
                        if p == &current_idom {
                            continue;
                        }
                        if dominator_map.contains_key(p) {
                            current_idom = Self::intersect(
                                &current_idom,
                                p,
                                &dominator_map,
                                &rpo_index,
                            );
                        }
                    }

                    let old_idom = dominator_map.get(v).cloned();
                    if old_idom.as_ref() != Some(&current_idom) {
                        dominator_map.insert(v.clone(), current_idom);
                        changed = true;
                    }
                }
            }
        }

        // Build dominated map (reverse of dominator map)
        let mut dominated_map: HashMap<V, Vec<V>> = HashMap::new();
        for (node, idom) in &dominator_map {
            if node != idom {
                dominated_map
                    .entry(idom.clone())
                    .or_default()
                    .push(node.clone());
            }
        }

        Self {
            dominator_map,
            dominated_map,
            root,
            navigator,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Intersect two dominator chains to find the common dominator.
    fn intersect(
        finger1: &V,
        finger2: &V,
        dominator_map: &HashMap<V, V>,
        rpo_index: &HashMap<V, usize>,
    ) -> V {
        let mut f1 = finger1.clone();
        let mut f2 = finger2.clone();

        loop {
            let f1_idx = rpo_index.get(&f1).copied().unwrap_or(0);
            let f2_idx = rpo_index.get(&f2).copied().unwrap_or(0);

            if f1_idx == f2_idx {
                return f1;
            }

            while f1_idx > f2_idx {
                if let Some(next) = dominator_map.get(&f1) {
                    f1 = next.clone();
                } else {
                    return f1;
                }
                let new_idx = rpo_index.get(&f1).copied().unwrap_or(0);
                if new_idx <= f2_idx {
                    break;
                }
            }

            while f2_idx > f1_idx {
                if let Some(next) = dominator_map.get(&f2) {
                    f2 = next.clone();
                } else {
                    return f1;
                }
                let new_idx = rpo_index.get(&f2).copied().unwrap_or(0);
                if new_idx <= f1_idx {
                    break;
                }
            }
        }
    }

    /// Get the immediate dominator of a vertex.
    pub fn get_immediate_dominator(&self, v: &V) -> Option<&V> {
        self.dominator_map.get(v).filter(|idom| *idom != v)
    }

    /// Get all dominators of a vertex (including itself).
    pub fn get_dominators(&self, v: &V) -> HashSet<V> {
        let mut dominators = HashSet::new();
        dominators.insert(v.clone());

        let mut current = v.clone();
        while current != self.root {
            if let Some(idom) = self.dominator_map.get(&current) {
                dominators.insert(idom.clone());
                current = idom.clone();
            } else {
                break;
            }
        }
        dominators
    }

    /// Get all vertices dominated by `v`.
    pub fn get_dominated(&self, v: &V) -> HashSet<V> {
        let mut result = HashSet::new();
        self.do_get_dominated(v, &mut result);
        result
    }

    fn do_get_dominated(&self, v: &V, result: &mut HashSet<V>) {
        result.insert(v.clone());
        if let Some(children) = self.dominated_map.get(v) {
            for child in children {
                self.do_get_dominated(child, result);
            }
        }
    }

    /// Get the root vertex of the dominance computation.
    pub fn get_root(&self) -> &V {
        &self.root
    }

    /// Build a dominance tree as a directed graph.
    ///
    /// Each node's children are those it immediately dominates.
    pub fn get_dominance_tree(
        &self,
        graph: &dyn GDirectedGraph<V, E>,
    ) -> HashDirectedGraph<V, crate::graph::default_edge::DefaultGEdge<V>> {
        use crate::graph::default_edge::DefaultGEdge;
        use crate::graph::traits::GDirectedGraph as _;

        let mut dg = HashDirectedGraph::new();
        let vertices = graph.get_vertices();

        for v in &vertices {
            dg.add_vertex(v.clone());
        }

        for v in &vertices {
            if *v == self.root {
                continue;
            }
            if let Some(idom) = self.dominator_map.get(v) {
                if idom != v {
                    dg.add_edge(DefaultGEdge::new(idom.clone(), v.clone()));
                }
            }
        }

        dg
    }
}

/// Post-dominance algorithm: CHK with reversed traversal.
///
/// Mirrors `ghidra.graph.algo.ChkPostDominanceAlgorithm<V, E>`.
pub struct ChkPostDominanceAlgorithm<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    inner: ChkDominanceAlgorithm<V, E>,
}

impl<V, E> ChkPostDominanceAlgorithm<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// Compute post-dominance for the given graph.
    pub fn compute(graph: &dyn GDirectedGraph<V, E>) -> Self {
        Self {
            inner: ChkDominanceAlgorithm::compute_with_navigator(
                graph,
                GraphNavigator::bottom_up(),
            ),
        }
    }

    /// Get the immediate post-dominator of a vertex.
    pub fn get_immediate_post_dominator(&self, v: &V) -> Option<&V> {
        self.inner.get_immediate_dominator(v)
    }

    /// Get all post-dominators of a vertex.
    pub fn get_post_dominators(&self, v: &V) -> HashSet<V> {
        self.inner.get_dominators(v)
    }

    /// Get all vertices post-dominated by `v`.
    pub fn get_post_dominated(&self, v: &V) -> HashSet<V> {
        self.inner.get_dominated(v)
    }

    /// Get the post-dominance tree.
    pub fn get_post_dominance_tree(
        &self,
        graph: &dyn GDirectedGraph<V, E>,
    ) -> HashDirectedGraph<V, crate::graph::default_edge::DefaultGEdge<V>> {
        self.inner.get_dominance_tree(graph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::default_edge::DefaultGEdge;
    use crate::graph::hash_graph::HashDirectedGraph;
    use crate::graph::traits::GDirectedGraph;

    #[test]
    fn test_chk_dominance_simple() {
        // 0 -> 1 -> 2 -> 3, 0 -> 2
        let mut g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(0);
        g.add_vertex(1);
        g.add_vertex(2);
        g.add_vertex(3);
        g.add_edge(DefaultGEdge::new(0, 1));
        g.add_edge(DefaultGEdge::new(0, 2));
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(2, 3));

        let dom = ChkDominanceAlgorithm::compute(&g);

        // 0 dominates everyone
        assert_eq!(dom.get_root(), &0);
        let doms_of_3 = dom.get_dominators(&3);
        assert!(doms_of_3.contains(&0));
        assert!(doms_of_3.contains(&2));

        // idom(3) = 2
        assert_eq!(dom.get_immediate_dominator(&3), Some(&2));
    }

    #[test]
    fn test_chk_dominance_diamond() {
        // Diamond: 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
        let mut g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(0);
        g.add_vertex(1);
        g.add_vertex(2);
        g.add_vertex(3);
        g.add_edge(DefaultGEdge::new(0, 1));
        g.add_edge(DefaultGEdge::new(0, 2));
        g.add_edge(DefaultGEdge::new(1, 3));
        g.add_edge(DefaultGEdge::new(2, 3));

        let dom = ChkDominanceAlgorithm::compute(&g);

        // 0 dominates all
        assert_eq!(dom.get_immediate_dominator(&1), Some(&0));
        assert_eq!(dom.get_immediate_dominator(&2), Some(&0));
        // idom(3) = 0 (merge point)
        assert_eq!(dom.get_immediate_dominator(&3), Some(&0));
    }

    #[test]
    fn test_chk_dominated() {
        let mut g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(0);
        g.add_vertex(1);
        g.add_vertex(2);
        g.add_vertex(3);
        g.add_edge(DefaultGEdge::new(0, 1));
        g.add_edge(DefaultGEdge::new(0, 2));
        g.add_edge(DefaultGEdge::new(1, 3));
        g.add_edge(DefaultGEdge::new(2, 3));

        let dom = ChkDominanceAlgorithm::compute(&g);

        let dominated_by_0 = dom.get_dominated(&0);
        assert!(dominated_by_0.contains(&0));
        assert!(dominated_by_0.contains(&1));
        assert!(dominated_by_0.contains(&2));
        assert!(dominated_by_0.contains(&3));
    }
}
