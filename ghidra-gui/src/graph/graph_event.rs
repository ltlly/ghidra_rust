//! Event types for graph change notifications.
//!
//! Ports `ghidra.graph.event.VisualGraphChangeListener`.

use std::hash::Hash;

use super::GEdge;

/// Events emitted by a visual graph when its structure changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphEvent<V: Eq + Hash + Clone, E: GEdge<V>> {
    /// A vertex was added.
    VertexAdded(V),
    /// A vertex was removed.
    VertexRemoved(V),
    /// An edge was added.
    EdgeAdded(E),
    /// An edge was removed.
    EdgeRemoved(E),
    /// The entire graph was cleared.
    GraphCleared,
    /// A vertex was selected.
    VertexSelected(V),
    /// A vertex was deselected.
    VertexDeselected(V),
}

/// Trait for receiving graph change notifications.
pub trait GraphChangeListener<V: Eq + Hash + Clone, E: GEdge<V>> {
    /// Called when a graph event occurs.
    fn on_graph_event(&self, event: &GraphEvent<V, E>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::DefaultGEdge;

    #[test]
    fn test_graph_event_variants() {
        let e: GraphEvent<i32, DefaultGEdge<i32>> = GraphEvent::VertexAdded(1);
        assert_eq!(e, GraphEvent::VertexAdded(1));
    }

    #[test]
    fn test_graph_event_edge() {
        let edge = DefaultGEdge::new(1, 2);
        let e: GraphEvent<i32, DefaultGEdge<i32>> = GraphEvent::EdgeAdded(edge);
        match e {
            GraphEvent::EdgeAdded(e) => {
                assert_eq!(*e.start(), 1);
                assert_eq!(*e.end(), 2);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_cleared_event() {
        let e: GraphEvent<i32, DefaultGEdge<i32>> = GraphEvent::GraphCleared;
        assert_eq!(e, GraphEvent::GraphCleared);
    }
}
