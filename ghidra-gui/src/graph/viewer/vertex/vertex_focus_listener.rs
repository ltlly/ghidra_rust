//! Port of Ghidra's `ghidra.graph.viewer.vertex.VertexFocusListener`.

/// Listener for vertex focus events.
pub trait VertexFocusListener: Send + Sync {
    /// Called when a vertex gains focus.
    fn focus_gained(&self, _vertex_id: &str) {}
    /// Called when a vertex loses focus.
    fn focus_lost(&self, _vertex_id: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[derive(Debug)]
    struct Counter { count: Arc<AtomicU32> }
    impl VertexFocusListener for Counter {
        fn focus_gained(&self, _id: &str) { self.count.fetch_add(1, Ordering::Relaxed); }
    }

    #[test]
    fn test_focus_listener() {
        let count = Arc::new(AtomicU32::new(0));
        let listener = Counter { count: count.clone() };
        listener.focus_gained("v1");
        listener.focus_gained("v2");
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }
}
