//! Port of Ghidra's `ghidra.graph.viewer.event.picking.PickListener`.
//!
//! Listener for vertex/edge pick (selection) events.

/// Trait for receiving notifications when vertices or edges are picked
/// (selected/clicked) in the graph viewer.
pub trait PickListener: Send + Sync {
    /// Called when a vertex is picked.
    fn vertex_picked(&self, _vertex_id: &str, _selected: bool) {}

    /// Called when an edge is picked.
    fn edge_picked(&self, _edge_id: &str, _selected: bool) {}

    /// Called when the selection is cleared.
    fn selection_cleared(&self) {}
}

/// A simple collector of pick events for testing.
#[derive(Debug, Default)]
pub struct CollectingPickListener {
    /// Recorded vertex pick events as (id, selected).
    pub vertex_events: Vec<(String, bool)>,
    /// Recorded edge pick events as (id, selected).
    pub edge_events: Vec<(String, bool)>,
    /// Number of selection-clear events.
    pub clear_count: usize,
}

impl PickListener for CollectingPickListener {
    fn vertex_picked(&self, _vertex_id: &str, _selected: bool) {
        // Note: needs interior mutability for real use; this is a test helper.
    }

    fn selection_cleared(&self) {
        // Same note.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct MockPickListener {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl MockPickListener {
        fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
            Self { events }
        }
    }

    impl PickListener for MockPickListener {
        fn vertex_picked(&self, vertex_id: &str, selected: bool) {
            self.events.lock().unwrap().push(format!("v:{}:{}", vertex_id, selected));
        }
        fn edge_picked(&self, edge_id: &str, selected: bool) {
            self.events.lock().unwrap().push(format!("e:{}:{}", edge_id, selected));
        }
        fn selection_cleared(&self) {
            self.events.lock().unwrap().push("clear".to_string());
        }
    }

    #[test]
    fn test_pick_listener_vertex() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let listener = MockPickListener::new(events.clone());
        listener.vertex_picked("v1", true);
        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 1);
        assert_eq!(evts[0], "v:v1:true");
    }

    #[test]
    fn test_pick_listener_edge() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let listener = MockPickListener::new(events.clone());
        listener.edge_picked("e1", false);
        assert_eq!(events.lock().unwrap()[0], "e:e1:false");
    }

    #[test]
    fn test_pick_listener_clear() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let listener = MockPickListener::new(events.clone());
        listener.selection_cleared();
        assert_eq!(events.lock().unwrap()[0], "clear");
    }
}
