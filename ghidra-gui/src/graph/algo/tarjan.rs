//! Tarjan's strongly-connected-components algorithm.
//!
//! Ports `ghidra.graph.algo.TarjanStronglyConnectedAlgorthm`.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use crate::graph::{GDirectedGraph, GEdge};

/// Tarjan's SCC algorithm.
///
/// Computes all strongly-connected components of a directed graph in
/// O(V + E) time.
pub struct TarjanScc;

struct VertexInfo {
    index: usize,
    low_link: usize,
}

impl TarjanScc {
    /// Compute all strongly-connected components of `graph`.
    ///
    /// Each returned `HashSet` is one SCC.  Singleton nodes that are their
    /// own SCC are also included.
    pub fn compute<V, E, G>(graph: &G) -> Vec<HashSet<V>>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        let mut state = State {
            index: 0,
            vertex_info: HashMap::new(),
            stack: Vec::new(),
            on_stack: HashSet::new(),
            components: Vec::new(),
        };

        for v in graph.vertices() {
            if !state.vertex_info.contains_key(&v) {
                state.strong_connect(&v, graph);
            }
        }

        state.components
    }
}

struct State<V: Eq + Hash + Clone> {
    index: usize,
    vertex_info: HashMap<V, VertexInfo>,
    stack: Vec<V>,
    on_stack: HashSet<V>,
    components: Vec<HashSet<V>>,
}

impl<V: Eq + Hash + Clone> State<V> {
    fn strong_connect<E, G>(&mut self, v: &V, graph: &G)
    where
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        let v_info = VertexInfo {
            index: self.index,
            low_link: self.index,
        };
        self.index += 1;
        self.vertex_info.insert(v.clone(), v_info);
        self.push(v.clone());

        // Collect out-neighbours first to avoid borrow issues.
        let out_neighbours: Vec<V> = graph
            .out_edges(v)
            .into_iter()
            .map(|e| e.end().clone())
            .collect();

        for w in out_neighbours {
            if !self.vertex_info.contains_key(&w) {
                self.strong_connect(&w, graph);
                let w_low = self.vertex_info[&w].low_link;
                let v_low = &mut self.vertex_info.get_mut(v).unwrap().low_link;
                *v_low = (*v_low).min(w_low);
            } else if self.on_stack.contains(&w) {
                let w_index = self.vertex_info[&w].index;
                let v_low = &mut self.vertex_info.get_mut(v).unwrap().low_link;
                *v_low = (*v_low).min(w_index);
            }
        }

        let v_index = self.vertex_info[v].index;
        let v_low_link = self.vertex_info[v].low_link;

        if v_low_link == v_index {
            let mut component = HashSet::new();
            loop {
                let w = self.pop();
                component.insert(w.clone());
                if w == *v {
                    break;
                }
            }
            self.components.push(component);
        }
    }

    fn push(&mut self, v: V) {
        self.on_stack.insert(v.clone());
        self.stack.push(v);
    }

    fn pop(&mut self) -> V {
        let v = self.stack.pop().expect("stack should not be empty");
        self.on_stack.remove(&v);
        v
    }
}
