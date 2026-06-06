//! Port of Ghidra's `ghidra.graph.viewer.edge.PathHighlightListener`.
//!
//! Listener for path highlight state changes in the graph viewer.

/// Trait for receiving notifications about path highlight changes.
///
/// When a user hovers over a vertex, the graph viewer highlights the
/// paths (chains of edges) flowing into or out of that vertex. This
/// listener receives callbacks when the highlight state changes.
pub trait PathHighlightListener: Send + Sync {
    /// Called when path highlighting begins for a vertex.
    fn path_highlight_started(&self, _vertex_id: &str) {}

    /// Called when path highlighting ends.
    fn path_highlight_ended(&self) {}

    /// Called when the set of highlighted edges changes.
    fn highlighted_edges_changed(&self, _edge_ids: &[String]) {}
}

/// A simple mock listener for testing.
#[cfg(test)]
pub(crate) struct MockPathHighlightListener;

#[cfg(test)]
impl PathHighlightListener for MockPathHighlightListener {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct RecordingListener {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl PathHighlightListener for RecordingListener {
        fn path_highlight_started(&self, vertex_id: &str) {
            self.events.lock().unwrap().push(format!("start:{}", vertex_id));
        }
        fn path_highlight_ended(&self) {
            self.events.lock().unwrap().push("end".into());
        }
        fn highlighted_edges_changed(&self, edge_ids: &[String]) {
            self.events.lock().unwrap().push(format!("edges:{}", edge_ids.len()));
        }
    }

    #[test]
    fn test_highlight_lifecycle() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let listener = RecordingListener { events: events.clone() };
        listener.path_highlight_started("v1");
        listener.highlighted_edges_changed(&["e1".into(), "e2".into()]);
        listener.path_highlight_ended();

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 3);
        assert_eq!(evts[0], "start:v1");
        assert_eq!(evts[1], "edges:2");
        assert_eq!(evts[2], "end");
    }
}
