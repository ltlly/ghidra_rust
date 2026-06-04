//! Depth-first graph sorting.
//!
//! Port of `ghidra.graph.algo.DepthFirstSorter<V, E>`.

use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

use crate::graph::traits::{GDirectedGraph, GEdge};

use super::graph_navigator::GraphNavigator;

/// Sorts vertices of a directed graph using depth-first traversal.
///
/// Provides both pre-order (vertices as first encountered) and post-order
/// (vertices as last visited) traversals.
///
/// Mirrors `ghidra.graph.algo.DepthFirstSorter<V, E>`.
pub struct DepthFirstSorter;

impl DepthFirstSorter {
    /// Return vertices in post-order (children before parents) using
    /// top-down traversal.
    ///
    /// Mirrors `DepthFirstSorter.postOrder(g)`.
    pub fn post_order<V, E>(graph: &dyn GDirectedGraph<V, E>) -> Vec<V>
    where
        V: Clone + Debug + Eq + Hash + 'static,
        E: GEdge<V> + 'static,
    {
        Self::post_order_with_navigator(graph, &GraphNavigator::top_down())
    }

    /// Return vertices in post-order using the given navigator direction.
    ///
    /// Mirrors `DepthFirstSorter.postOrder(g, navigator)`.
    pub fn post_order_with_navigator<V, E>(
        graph: &dyn GDirectedGraph<V, E>,
        navigator: &GraphNavigator,
    ) -> Vec<V>
    where
        V: Clone + Debug + Eq + Hash + 'static,
        E: GEdge<V> + 'static,
    {
        let seeds = navigator.get_sources(graph);
        let mut visited = LinkedOrderSet::new();

        for seed in seeds {
            Self::post_order_visit(graph, navigator, seed, &mut visited);
        }

        visited.into_list()
    }

    /// Return vertices in pre-order (parents before children) using
    /// top-down traversal.
    ///
    /// Mirrors `DepthFirstSorter.preOrder(g)`.
    pub fn pre_order<V, E>(graph: &dyn GDirectedGraph<V, E>) -> Vec<V>
    where
        V: Clone + Debug + Eq + Hash + 'static,
        E: GEdge<V> + 'static,
    {
        Self::pre_order_with_navigator(graph, &GraphNavigator::top_down())
    }

    /// Return vertices in pre-order using the given navigator direction.
    ///
    /// Mirrors `DepthFirstSorter.preOrder(g, navigator)`.
    pub fn pre_order_with_navigator<V, E>(
        graph: &dyn GDirectedGraph<V, E>,
        navigator: &GraphNavigator,
    ) -> Vec<V>
    where
        V: Clone + Debug + Eq + Hash + 'static,
        E: GEdge<V> + 'static,
    {
        let seeds = navigator.get_sources(graph);
        let mut visited = LinkedOrderSet::new();

        for seed in seeds {
            Self::pre_order_visit(graph, navigator, seed, &mut visited);
        }

        visited.into_list()
    }

    fn post_order_visit<V, E>(
        graph: &dyn GDirectedGraph<V, E>,
        navigator: &GraphNavigator,
        v: V,
        visited: &mut LinkedOrderSet<V>,
    ) where
        V: Clone + Debug + Eq + Hash + 'static,
        E: GEdge<V> + 'static,
    {
        if visited.contains(&v) {
            return;
        }

        let successors = navigator.get_successors(graph, &v);
        visited.insert(v.clone());

        for child in successors {
            Self::post_order_visit(graph, navigator, child, visited);
        }

        // Move to end (post-order: visited last = appears last)
        visited.move_to_end(&v);
    }

    fn pre_order_visit<V, E>(
        graph: &dyn GDirectedGraph<V, E>,
        navigator: &GraphNavigator,
        v: V,
        visited: &mut LinkedOrderSet<V>,
    ) where
        V: Clone + Debug + Eq + Hash + 'static,
        E: GEdge<V> + 'static,
    {
        if visited.contains(&v) {
            return;
        }

        let successors = navigator.get_successors(graph, &v);
        visited.insert(v);

        for child in successors {
            Self::pre_order_visit(graph, navigator, child, visited);
        }
    }
}

/// A simple ordered set that maintains insertion order (like Java's LinkedHashSet).
struct LinkedOrderSet<V: Eq + Hash + Clone> {
    set: HashSet<V>,
    list: Vec<V>,
}

impl<V: Eq + Hash + Clone> LinkedOrderSet<V> {
    fn new() -> Self {
        Self {
            set: HashSet::new(),
            list: Vec::new(),
        }
    }

    fn contains(&self, v: &V) -> bool {
        self.set.contains(v)
    }

    fn insert(&mut self, v: V) {
        if self.set.insert(v.clone()) {
            self.list.push(v);
        }
    }

    fn move_to_end(&mut self, v: &V) {
        if let Some(pos) = self.list.iter().position(|x| x == v) {
            let item = self.list.remove(pos);
            self.list.push(item);
        }
    }

    fn into_list(self) -> Vec<V> {
        self.list
    }
}
