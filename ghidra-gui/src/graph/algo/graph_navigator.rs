//! Graph traversal direction control.
//!
//! Ports `ghidra.graph.algo.GraphNavigator<V, E>` which enables
//! walking a graph either top-down (source to sink) or bottom-up
//! (sink to source).

use std::hash::Hash;

use crate::graph::{GDirectedGraph, GEdge};

/// Direction of graph traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalDirection {
    /// Traverse from sources (entry nodes) toward sinks.
    TopDown,
    /// Traverse from sinks toward sources (entry nodes).
    BottomUp,
}

/// Controls the direction of graph traversal.
///
/// A `GraphNavigator` allows algorithms to be written once and work in
/// either direction -- top-down (from sources to sinks) or bottom-up
/// (from sinks to sources).  This is used by `DepthFirstSorter`,
/// `FindPaths`, and other graph algorithms.
///
/// Ports `ghidra.graph.algo.GraphNavigator<V, E>`.
#[derive(Debug, Clone)]
pub struct GraphNavigator<V: Eq + Hash + Clone, E: GEdge<V>> {
    direction: TraversalDirection,
    _phantom: std::marker::PhantomData<(V, E)>,
}

impl<V: Eq + Hash + Clone, E: GEdge<V>> GraphNavigator<V, E> {
    /// Create a navigator that traverses top-down (source -> sink).
    pub fn top_down() -> Self {
        Self {
            direction: TraversalDirection::TopDown,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Create a navigator that traverses bottom-up (sink -> source).
    pub fn bottom_up() -> Self {
        Self {
            direction: TraversalDirection::BottomUp,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Whether this navigator is top-down.
    pub fn is_top_down(&self) -> bool {
        self.direction == TraversalDirection::TopDown
    }

    /// Whether this navigator is bottom-up.
    pub fn is_bottom_up(&self) -> bool {
        self.direction == TraversalDirection::BottomUp
    }

    /// The current traversal direction.
    pub fn direction(&self) -> TraversalDirection {
        self.direction
    }

    /// Get the "successors" of a vertex in the navigation direction.
    ///
    /// For top-down: outgoing neighbors (direct successors).
    /// For bottom-up: incoming neighbors (direct predecessors).
    pub fn get_successors<G: GDirectedGraph<V, E>>(&self, graph: &G, vertex: &V) -> Vec<V> {
        match self.direction {
            TraversalDirection::TopDown => graph.successors(vertex),
            TraversalDirection::BottomUp => graph.predecessors(vertex),
        }
    }

    /// Get the "predecessors" of a vertex in the navigation direction.
    ///
    /// For top-down: incoming neighbors.
    /// For bottom-up: outgoing neighbors.
    pub fn get_predecessors<G: GDirectedGraph<V, E>>(&self, graph: &G, vertex: &V) -> Vec<V> {
        match self.direction {
            TraversalDirection::TopDown => graph.predecessors(vertex),
            TraversalDirection::BottomUp => graph.successors(vertex),
        }
    }

    /// Get the "source" vertices -- the starting points for traversal.
    ///
    /// For top-down: vertices with no incoming edges (graph sources).
    /// For bottom-up: vertices with no outgoing edges (graph sinks).
    pub fn get_sources<G: GDirectedGraph<V, E>>(&self, graph: &G) -> Vec<V> {
        match self.direction {
            TraversalDirection::TopDown => {
                // Sources: vertices with no predecessors.
                graph
                    .vertices()
                    .into_iter()
                    .filter(|v| graph.predecessors(v).is_empty())
                    .collect()
            }
            TraversalDirection::BottomUp => {
                // Sinks: vertices with no successors.
                graph
                    .vertices()
                    .into_iter()
                    .filter(|v| graph.successors(v).is_empty())
                    .collect()
            }
        }
    }

    /// Get the "sink" vertices -- the ending points for traversal.
    ///
    /// For top-down: vertices with no outgoing edges.
    /// For bottom-up: vertices with no incoming edges.
    pub fn get_sinks<G: GDirectedGraph<V, E>>(&self, graph: &G) -> Vec<V> {
        match self.direction {
            TraversalDirection::TopDown => {
                graph
                    .vertices()
                    .into_iter()
                    .filter(|v| graph.successors(v).is_empty())
                    .collect()
            }
            TraversalDirection::BottomUp => {
                graph
                    .vertices()
                    .into_iter()
                    .filter(|v| graph.predecessors(v).is_empty())
                    .collect()
            }
        }
    }

    /// Reverse the navigation direction.
    pub fn reversed(&self) -> Self {
        match self.direction {
            TraversalDirection::TopDown => Self::bottom_up(),
            TraversalDirection::BottomUp => Self::top_down(),
        }
    }

    /// Get the edge from a predecessor to a successor in this navigator's
    /// traversal order.
    pub fn get_edge<'a, G: GDirectedGraph<V, E>>(
        &self,
        graph: &'a G,
        from: &V,
        to: &V,
    ) -> Option<&'a E> {
        match self.direction {
            TraversalDirection::TopDown => graph.find_edge(from, to),
            TraversalDirection::BottomUp => graph.find_edge(to, from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DefaultDirectedGraph, DefaultGEdge};

    type E = DefaultGEdge<char>;
    type G = DefaultDirectedGraph<char, E>;

    fn make_dag() -> G {
        // a -> b -> d
        // a -> c -> d
        let mut g = G::new();
        g.add_edge(E::new('a', 'b'));
        g.add_edge(E::new('a', 'c'));
        g.add_edge(E::new('b', 'd'));
        g.add_edge(E::new('c', 'd'));
        g
    }

    #[test]
    fn top_down_sources_are_real_sources() {
        let g = make_dag();
        let nav = GraphNavigator::<char, E>::top_down();
        let sources = nav.get_sources(&g);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0], 'a');
    }

    #[test]
    fn bottom_up_sources_are_sinks() {
        let g = make_dag();
        let nav = GraphNavigator::<char, E>::bottom_up();
        let sources = nav.get_sources(&g);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0], 'd');
    }

    #[test]
    fn top_down_successors() {
        let g = make_dag();
        let nav = GraphNavigator::<char, E>::top_down();
        let mut succ = nav.get_successors(&g, &'a');
        succ.sort();
        assert_eq!(succ, vec!['b', 'c']);
    }

    #[test]
    fn bottom_up_successors_from_d() {
        let g = make_dag();
        let nav = GraphNavigator::<char, E>::bottom_up();
        let mut succ = nav.get_successors(&g, &'d');
        succ.sort();
        assert_eq!(succ, vec!['b', 'c']);
    }

    #[test]
    fn reversed_swaps_direction() {
        let nav = GraphNavigator::<char, E>::top_down();
        assert!(nav.is_top_down());
        let rev = nav.reversed();
        assert!(rev.is_bottom_up());
    }

    #[test]
    fn top_down_sinks_are_d() {
        let g = make_dag();
        let nav = GraphNavigator::<char, E>::top_down();
        let sinks = nav.get_sinks(&g);
        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks[0], 'd');
    }

    #[test]
    fn get_edge_respects_direction() {
        let g = make_dag();
        let nav = GraphNavigator::<char, E>::top_down();
        // top-down: find_edge(a, b) -> a->b exists
        assert!(nav.get_edge(&g, &'a', &'b').is_some());
        // bottom-up: find_edge(a, b) is actually find_edge(b, a) -> a->b exists
        let rev = nav.reversed();
        assert!(rev.get_edge(&g, &'b', &'a').is_some());
    }
}
