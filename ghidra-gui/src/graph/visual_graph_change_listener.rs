//! Port of Ghidra's `ghidra.graph.event.VisualGraphChangeListener`.

/// Listener for structural changes to a visual graph.
///
/// Ports Ghidra's `VisualGraphChangeListener`.
pub trait VisualGraphChangeListener: Send + Sync {
    /// Called when a vertex is added.
    fn vertex_added(&self, _vertex_id: &str) {}
    /// Called when a vertex is removed.
    fn vertex_removed(&self, _vertex_id: &str) {}
    /// Called when an edge is added.
    fn edge_added(&self, _edge_id: &str) {}
    /// Called when an edge is removed.
    fn edge_removed(&self, _edge_id: &str) {}
    /// Called when the graph is cleared.
    fn graph_cleared(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct Mock { events: Arc<Mutex<Vec<String>>> }
    impl VisualGraphChangeListener for Mock {
        fn vertex_added(&self, id: &str) { self.events.lock().unwrap().push(format!("add:{}", id)); }
        fn vertex_removed(&self, id: &str) { self.events.lock().unwrap().push(format!("rm:{}", id)); }
        fn graph_cleared(&self) { self.events.lock().unwrap().push("clear".into()); }
    }

    #[test]
    fn test_change_listener() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let listener = Mock { events: events.clone() };
        listener.vertex_added("v1");
        listener.vertex_removed("v2");
        listener.graph_cleared();
        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 3);
        assert_eq!(evts[0], "add:v1");
        assert_eq!(evts[1], "rm:v2");
        assert_eq!(evts[2], "clear");
    }
}
