//! Port of Ghidra's `ghidra.graph.viewer.vertex.VertexClickListener`.

/// Listener for vertex click events in the graph viewer.
pub trait VertexClickListener: Send + Sync {
    /// Called when a vertex is clicked.
    fn vertex_clicked(&self, _vertex_id: &str) {}
    /// Called when a vertex is double-clicked.
    fn vertex_double_clicked(&self, _vertex_id: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct Mock { clicks: Arc<Mutex<Vec<String>>> }
    impl VertexClickListener for Mock {
        fn vertex_clicked(&self, id: &str) { self.clicks.lock().unwrap().push(id.into()); }
    }

    #[test]
    fn test_click_listener() {
        let clicks = Arc::new(Mutex::new(Vec::new()));
        let listener = Mock { clicks: clicks.clone() };
        listener.vertex_clicked("v1");
        listener.vertex_clicked("v2");
        assert_eq!(*clicks.lock().unwrap(), vec!["v1", "v2"]);
    }
}
