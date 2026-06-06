//! Port of Ghidra's `ghidra.graph.viewer.layout.LayoutListener`.

/// Listener for layout computation events.
pub trait LayoutListener: Send + Sync {
    /// Called when layout computation begins.
    fn layout_started(&self) {}
    /// Called periodically with progress (0.0 ..= 1.0).
    fn layout_progress(&self, _progress: f64) {}
    /// Called when layout computation finishes.
    fn layout_finished(&self) {}
    /// Called when layout is cancelled.
    fn layout_cancelled(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[derive(Debug)]
    struct TestListener { started: Arc<AtomicBool>, finished: Arc<AtomicBool> }
    impl LayoutListener for TestListener {
        fn layout_started(&self) { self.started.store(true, Ordering::Relaxed); }
        fn layout_finished(&self) { self.finished.store(true, Ordering::Relaxed); }
    }

    #[test]
    fn test_listener_callbacks() {
        let started = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let listener = TestListener { started: started.clone(), finished: finished.clone() };
        listener.layout_started();
        assert!(started.load(Ordering::Relaxed));
        listener.layout_finished();
        assert!(finished.load(Ordering::Relaxed));
    }
}
