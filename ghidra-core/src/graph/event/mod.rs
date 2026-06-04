//! Graph event types ported from Ghidra's `ghidra.graph.event` package.
//!
//! Provides listener types for visual graph change notifications.

use std::fmt::Debug;

/// Event types that can occur on a visual graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VisualGraphEvent {
    /// A vertex was added to the graph.
    VertexAdded,
    /// A vertex was removed from the graph.
    VertexRemoved,
    /// An edge was added to the graph.
    EdgeAdded,
    /// An edge was removed from the graph.
    EdgeRemoved,
    /// The graph was cleared (all vertices and edges removed).
    GraphCleared,
    /// A vertex was selected.
    VertexSelected,
    /// A vertex was deselected.
    VertexDeselected,
    /// An edge was selected.
    EdgeSelected,
    /// An edge was deselected.
    EdgeDeselected,
    /// The graph layout changed.
    LayoutChanged,
}

/// Listener for visual graph change events.
///
/// Mirrors `ghidra.graph.event.VisualGraphChangeListener`.
pub trait VisualGraphChangeListener: Debug + Send + Sync {
    /// Called when a vertex is added.
    fn on_vertex_added(&self, vertex_id: &str);

    /// Called when a vertex is removed.
    fn on_vertex_removed(&self, vertex_id: &str);

    /// Called when an edge is added.
    fn on_edge_added(&self, edge_id: &str, start_id: &str, end_id: &str);

    /// Called when an edge is removed.
    fn on_edge_removed(&self, edge_id: &str);

    /// Called when the graph is cleared.
    fn on_graph_cleared(&self);

    /// Called when a vertex is selected.
    fn on_vertex_selected(&self, vertex_id: &str);

    /// Called when a vertex is deselected.
    fn on_vertex_deselected(&self, vertex_id: &str);

    /// Called when an edge is selected.
    fn on_edge_selected(&self, edge_id: &str);

    /// Called when an edge is deselected.
    fn on_edge_deselected(&self, edge_id: &str);

    /// Called when the layout changes.
    fn on_layout_changed(&self);
}

/// A recording listener for testing graph events.
#[derive(Debug, Default)]
pub struct RecordingGraphListener {
    events: std::sync::Mutex<Vec<(VisualGraphEvent, String)>>,
}

impl RecordingGraphListener {
    /// Create a new recording listener.
    pub fn new() -> Self {
        Self { events: std::sync::Mutex::new(Vec::new()) }
    }

    /// Get all recorded events.
    pub fn events(&self) -> Vec<(VisualGraphEvent, String)> {
        self.events.lock().unwrap().clone()
    }

    /// Clear recorded events.
    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }

    fn record(&self, event: VisualGraphEvent, detail: String) {
        self.events.lock().unwrap().push((event, detail));
    }
}

impl VisualGraphChangeListener for RecordingGraphListener {
    fn on_vertex_added(&self, vertex_id: &str) {
        self.record(VisualGraphEvent::VertexAdded, vertex_id.to_string());
    }
    fn on_vertex_removed(&self, vertex_id: &str) {
        self.record(VisualGraphEvent::VertexRemoved, vertex_id.to_string());
    }
    fn on_edge_added(&self, edge_id: &str, _start: &str, _end: &str) {
        self.record(VisualGraphEvent::EdgeAdded, edge_id.to_string());
    }
    fn on_edge_removed(&self, edge_id: &str) {
        self.record(VisualGraphEvent::EdgeRemoved, edge_id.to_string());
    }
    fn on_graph_cleared(&self) {
        self.record(VisualGraphEvent::GraphCleared, String::new());
    }
    fn on_vertex_selected(&self, vertex_id: &str) {
        self.record(VisualGraphEvent::VertexSelected, vertex_id.to_string());
    }
    fn on_vertex_deselected(&self, vertex_id: &str) {
        self.record(VisualGraphEvent::VertexDeselected, vertex_id.to_string());
    }
    fn on_edge_selected(&self, edge_id: &str) {
        self.record(VisualGraphEvent::EdgeSelected, edge_id.to_string());
    }
    fn on_edge_deselected(&self, edge_id: &str) {
        self.record(VisualGraphEvent::EdgeDeselected, edge_id.to_string());
    }
    fn on_layout_changed(&self) {
        self.record(VisualGraphEvent::LayoutChanged, String::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recording_listener() {
        let listener = RecordingGraphListener::new();
        listener.on_vertex_added("v1");
        listener.on_edge_added("e1", "v1", "v2");
        listener.on_vertex_selected("v1");

        let events = listener.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].0, VisualGraphEvent::VertexAdded);
        assert_eq!(events[0].1, "v1");
        assert_eq!(events[1].0, VisualGraphEvent::EdgeAdded);
        assert_eq!(events[2].0, VisualGraphEvent::VertexSelected);
    }

    #[test]
    fn test_listener_clear() {
        let listener = RecordingGraphListener::new();
        listener.on_graph_cleared();
        assert_eq!(listener.events().len(), 1);
        listener.clear();
        assert_eq!(listener.events().len(), 0);
    }

    #[test]
    fn test_graph_event_equality() {
        assert_eq!(VisualGraphEvent::VertexAdded, VisualGraphEvent::VertexAdded);
        assert_ne!(VisualGraphEvent::VertexAdded, VisualGraphEvent::VertexRemoved);
    }
}
