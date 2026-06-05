//! TraceDataViewport - viewport for trace data access.
//!
//! Ported from Ghidra's `TraceTimeViewport` and related viewport types.
//! Provides a view into the trace that filters by time range and
//! supports efficient iteration over trace data.

use serde::{Deserialize, Serialize};

use super::lifespan::Lifespan;

/// A viewport into trace data that restricts the visible time range.
///
/// Ported from Ghidra's `TraceTimeViewport`. Used by listing views,
/// memory views, and other components that display a window into trace
/// data at specific time points.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDataViewport {
    /// The currently visible lifespan (time range).
    pub lifespan: Lifespan,
    /// The current snap (point in time) cursor.
    pub current_snap: i64,
    /// The minimum snap for the viewport.
    pub min_snap: i64,
    /// The maximum snap for the viewport (i64::MAX for unbounded).
    pub max_snap: i64,
    /// Whether to show only the current snap or the full range.
    pub single_snap_mode: bool,
}

impl TraceDataViewport {
    /// Create a new viewport showing a single snap.
    pub fn single(snap: i64) -> Self {
        Self {
            lifespan: Lifespan::span(snap, snap),
            current_snap: snap,
            min_snap: snap,
            max_snap: snap,
            single_snap_mode: true,
        }
    }

    /// Create a viewport spanning a range.
    pub fn range(min_snap: i64, max_snap: i64) -> Self {
        Self {
            lifespan: Lifespan::span(min_snap, max_snap),
            current_snap: min_snap,
            min_snap,
            max_snap,
            single_snap_mode: false,
        }
    }

    /// Create a viewport showing everything from a given snap onward.
    pub fn from_snap(snap: i64) -> Self {
        Self {
            lifespan: Lifespan::span(snap, i64::MAX),
            current_snap: snap,
            min_snap: snap,
            max_snap: i64::MAX,
            single_snap_mode: false,
        }
    }

    /// Navigate to a specific snap within the viewport.
    pub fn go_to_snap(&mut self, snap: i64) {
        self.current_snap = snap.clamp(self.min_snap, self.max_snap);
    }

    /// Navigate forward by one snap.
    pub fn forward(&mut self) -> bool {
        if self.current_snap < self.max_snap {
            self.current_snap += 1;
            true
        } else {
            false
        }
    }

    /// Navigate backward by one snap.
    pub fn backward(&mut self) -> bool {
        if self.current_snap > self.min_snap {
            self.current_snap -= 1;
            true
        } else {
            false
        }
    }

    /// Check if a given snap is within the viewport.
    pub fn contains_snap(&self, snap: i64) -> bool {
        if self.single_snap_mode {
            snap == self.current_snap
        } else {
            snap >= self.min_snap && snap <= self.max_snap
        }
    }

    /// Expand the viewport to include a new snap.
    pub fn expand_to_include(&mut self, snap: i64) {
        if snap < self.min_snap {
            self.min_snap = snap;
        }
        if snap > self.max_snap {
            self.max_snap = snap;
        }
        self.lifespan = Lifespan::span(self.min_snap, self.max_snap);
    }

    /// The number of snaps in the viewport (if bounded).
    pub fn snap_count(&self) -> Option<u64> {
        if self.max_snap == i64::MAX || self.min_snap == i64::MIN {
            None
        } else {
            Some((self.max_snap - self.min_snap + 1) as u64)
        }
    }

    /// Whether the viewport is showing a single snap.
    pub fn is_single_snap(&self) -> bool {
        self.single_snap_mode
    }

    /// Toggle between single-snap and range mode.
    pub fn toggle_mode(&mut self) {
        self.single_snap_mode = !self.single_snap_mode;
    }
}

impl Default for TraceDataViewport {
    fn default() -> Self {
        Self::single(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_viewport_single() {
        let vp = TraceDataViewport::single(5);
        assert!(vp.is_single_snap());
        assert!(vp.contains_snap(5));
        assert!(!vp.contains_snap(6));
        assert_eq!(vp.current_snap, 5);
    }

    #[test]
    fn test_viewport_range() {
        let vp = TraceDataViewport::range(0, 10);
        assert!(!vp.is_single_snap());
        assert!(vp.contains_snap(0));
        assert!(vp.contains_snap(5));
        assert!(vp.contains_snap(10));
        assert!(!vp.contains_snap(11));
    }

    #[test]
    fn test_viewport_navigate() {
        let mut vp = TraceDataViewport::range(0, 10);
        assert_eq!(vp.current_snap, 0);

        assert!(vp.forward());
        assert_eq!(vp.current_snap, 1);

        assert!(vp.backward());
        assert_eq!(vp.current_snap, 0);

        assert!(!vp.backward()); // at min
    }

    #[test]
    fn test_viewport_go_to() {
        let mut vp = TraceDataViewport::range(0, 10);
        vp.go_to_snap(5);
        assert_eq!(vp.current_snap, 5);

        vp.go_to_snap(100); // clamped
        assert_eq!(vp.current_snap, 10);
    }

    #[test]
    fn test_viewport_expand() {
        let mut vp = TraceDataViewport::range(5, 10);
        vp.expand_to_include(0);
        assert_eq!(vp.min_snap, 0);
        assert!(vp.contains_snap(0));

        vp.expand_to_include(20);
        assert_eq!(vp.max_snap, 20);
        assert!(vp.contains_snap(20));
    }

    #[test]
    fn test_viewport_snap_count() {
        let vp = TraceDataViewport::range(0, 9);
        assert_eq!(vp.snap_count(), Some(10));

        let vp = TraceDataViewport::from_snap(0);
        assert!(vp.snap_count().is_none());
    }

    #[test]
    fn test_viewport_toggle() {
        let mut vp = TraceDataViewport::range(0, 10);
        assert!(!vp.is_single_snap());
        vp.toggle_mode();
        assert!(vp.is_single_snap());
    }

    #[test]
    fn test_viewport_from_snap() {
        let vp = TraceDataViewport::from_snap(5);
        assert!(vp.contains_snap(5));
        assert!(vp.contains_snap(1000));
        assert!(!vp.contains_snap(4));
    }

    #[test]
    fn test_viewport_default() {
        let vp = TraceDataViewport::default();
        assert_eq!(vp.current_snap, 0);
        assert!(vp.is_single_snap());
    }

    #[test]
    fn test_viewport_serde() {
        let vp = TraceDataViewport::range(0, 10);
        let json = serde_json::to_string(&vp).unwrap();
        let back: TraceDataViewport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.min_snap, 0);
        assert_eq!(back.max_snap, 10);
    }
}
