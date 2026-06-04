//! Tarjan's strongly-connected components algorithm for generic graphs.
//!
//! Port of `ghidra.graph.algo.TarjanStronglyConnectedAlgorthm<V, E>`.

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;

use crate::graph::traits::{GDirectedGraph, GEdge};

/// Tarjan's algorithm for finding strongly-connected components in a
/// directed graph.
///
/// This is a standalone implementation that works with the generic
/// [`GDirectedGraph`] trait (unlike the `petgraph`-based implementation in
/// the main graph module).
///
/// Mirrors `ghidra.graph.algo.TarjanStronglyConnectedAlgorthm<V, E>`.
pub struct TarjanSCC<'a, V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    graph: *const (dyn GDirectedGraph<V, E> + 'a),
    vertex_infos: HashMap<V, VertexInfo>,
    stack: Vec<V>,
    on_stack: HashSet<V>,
    components: Vec<HashSet<V>>,
    next_index: usize,
}

#[derive(Debug)]
struct VertexInfo {
    index: usize,
    low_link: usize,
}

impl<'a, V, E> TarjanSCC<'a, V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// Create a new Tarjan SCC algorithm and immediately compute the
    /// components.
    pub fn new(graph: &'a dyn GDirectedGraph<V, E>) -> Self {
        let mut scc = Self {
            graph: graph as *const (dyn GDirectedGraph<V, E> + 'a),
            vertex_infos: HashMap::new(),
            stack: Vec::new(),
            on_stack: HashSet::new(),
            components: Vec::new(),
            next_index: 0,
        };
        scc.compute();
        scc
    }

    fn graph(&self) -> &'a dyn GDirectedGraph<V, E> {
        unsafe { &*self.graph }
    }

    fn compute(&mut self) {
        let vertices: Vec<V> = self.graph().get_vertices().into_iter().collect();
        for v in vertices {
            if !self.vertex_infos.contains_key(&v) {
                self.strong_connect(&v);
            }
        }
    }

    fn strong_connect(&mut self, v: &V) -> usize {
        let idx = self.next_index;
        self.next_index += 1;

        self.vertex_infos.insert(v.clone(), VertexInfo {
            index: idx,
            low_link: idx,
        });
        self.push(v);

        let out_edges = self.graph().get_out_edges(v);
        for e in out_edges {
            let w = e.end().clone();
            if !self.vertex_infos.contains_key(&w) {
                let w_low = self.strong_connect(&w);
                let v_low = &mut self.vertex_infos.get_mut(v).unwrap().low_link;
                *v_low = (*v_low).min(w_low);
            } else if self.on_stack.contains(&w) {
                let w_index = self.vertex_infos[&w].index;
                let v_low = &mut self.vertex_infos.get_mut(v).unwrap().low_link;
                *v_low = (*v_low).min(w_index);
            }
        }

        let v_info = &self.vertex_infos[v];
        if v_info.low_link == v_info.index {
            let mut component = HashSet::new();
            component.insert(v.clone());
            loop {
                let w = self.pop();
                if w == *v {
                    break;
                }
                component.insert(w);
            }
            self.components.push(component);
        }

        self.vertex_infos[v].low_link
    }

    fn push(&mut self, v: &V) {
        self.stack.push(v.clone());
        self.on_stack.insert(v.clone());
    }

    fn pop(&mut self) -> V {
        let v = self.stack.pop().unwrap();
        self.on_stack.remove(&v);
        v
    }

    /// Get the computed strongly-connected components.
    pub fn get_connected_components(&self) -> &[HashSet<V>] {
        &self.components
    }

    /// Consume self and return the connected components.
    pub fn into_components(self) -> Vec<HashSet<V>> {
        self.components
    }
}

/// Convenience function: compute strongly-connected components of a generic
/// directed graph.
pub fn tarjan_scc<V, E>(graph: &dyn GDirectedGraph<V, E>) -> Vec<HashSet<V>>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let scc = TarjanSCC::new(graph);
    scc.into_components()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::default_edge::DefaultGEdge;
    use crate::graph::hash_graph::HashDirectedGraph;
    use crate::graph::traits::GDirectedGraph;

    #[test]
    fn test_tarjan_scc_simple() {
        // 0 -> 1 -> 2 -> 0 (single SCC)
        let mut g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(0);
        g.add_vertex(1);
        g.add_vertex(2);
        g.add_edge(DefaultGEdge::new(0, 1));
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(2, 0));

        let sccs = tarjan_scc(&g);
        assert_eq!(sccs.len(), 1);
        assert_eq!(sccs[0].len(), 3);
    }

    #[test]
    fn test_tarjan_scc_two_components() {
        // 0 -> 1 -> 0, 2 -> 3 -> 2
        let mut g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(0);
        g.add_vertex(1);
        g.add_vertex(2);
        g.add_vertex(3);
        g.add_edge(DefaultGEdge::new(0, 1));
        g.add_edge(DefaultGEdge::new(1, 0));
        g.add_edge(DefaultGEdge::new(2, 3));
        g.add_edge(DefaultGEdge::new(3, 2));

        let sccs = tarjan_scc(&g);
        assert_eq!(sccs.len(), 2);
        for scc in &sccs {
            assert_eq!(scc.len(), 2);
        }
    }

    #[test]
    fn test_tarjan_scc_dag() {
        // DAG: 0 -> 1 -> 2 (each node is its own SCC)
        let mut g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(0);
        g.add_vertex(1);
        g.add_vertex(2);
        g.add_edge(DefaultGEdge::new(0, 1));
        g.add_edge(DefaultGEdge::new(1, 2));

        let sccs = tarjan_scc(&g);
        assert_eq!(sccs.len(), 3);
    }
}
