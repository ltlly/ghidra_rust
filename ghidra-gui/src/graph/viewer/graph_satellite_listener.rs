//! Port of Ghidra's `ghidra.graph.viewer.GraphSatelliteListener`.

/// Listener for satellite (mini-map) view events.
pub trait GraphSatelliteListener: Send + Sync {
    /// Called when the satellite view is shown.
    fn satellite_shown(&self) {}
    /// Called when the satellite view is hidden.
    fn satellite_hidden(&self) {}
    /// Called when the user pans in the satellite view.
    fn satellite_panned(&self, _dx: f64, _dy: f64) {}
    /// Called when the user zooms in the satellite view.
    fn satellite_zoomed(&self, _scale: f64) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[derive(Debug)]
    struct Mock { shown: Arc<AtomicBool> }
    impl GraphSatelliteListener for Mock {
        fn satellite_shown(&self) { self.shown.store(true, Ordering::Relaxed); }
        fn satellite_hidden(&self) { self.shown.store(false, Ordering::Relaxed); }
    }

    #[test]
    fn test_satellite_listener() {
        let shown = Arc::new(AtomicBool::new(false));
        let listener = Mock { shown: shown.clone() };
        listener.satellite_shown();
        assert!(shown.load(Ordering::Relaxed));
        listener.satellite_hidden();
        assert!(!shown.load(Ordering::Relaxed));
    }
}
