//! DBTraceTimeViewport - time range viewport for trace viewing.
//!
//! Ported from Ghidra's `DBTraceTimeViewport`. Provides viewport management
//! for controlling which time range of a trace is visible in the UI.

use crate::model::Lifespan;

/// A time viewport controlling the visible range of a trace.
///
/// The viewport has a snap (current time position) and a visible range.
/// Listeners can be notified when the viewport changes.
#[derive(Debug, Clone)]
pub struct TraceTimeViewport {
    /// The current snap (time position).
    snap: i64,
    /// The visible range start (inclusive).
    range_start: i64,
    /// The visible range end (inclusive).
    range_end: i64,
    /// Whether the viewport is pinned (won't follow new data).
    pinned: bool,
}

impl TraceTimeViewport {
    /// Create a new viewport with the given initial range.
    pub fn new(snap: i64, range_start: i64, range_end: i64) -> Self {
        Self {
            snap,
            range_start,
            range_end,
            pinned: false,
        }
    }

    /// Create a viewport that shows a single snap.
    pub fn single_snap(snap: i64) -> Self {
        Self {
            snap,
            range_start: snap,
            range_end: snap,
            pinned: false,
        }
    }

    /// Create a viewport that shows all time.
    pub fn all_time() -> Self {
        Self {
            snap: 0,
            range_start: i64::MIN,
            range_end: i64::MAX,
            pinned: false,
        }
    }

    /// Get the current snap.
    pub fn snap(&self) -> i64 {
        self.snap
    }

    /// Set the current snap.
    pub fn set_snap(&mut self, snap: i64) {
        self.snap = snap;
    }

    /// Get the visible range.
    pub fn range(&self) -> Lifespan {
        Lifespan::span(self.range_start, self.range_end)
    }

    /// Get the range start.
    pub fn range_start(&self) -> i64 {
        self.range_start
    }

    /// Get the range end.
    pub fn range_end(&self) -> i64 {
        self.range_end
    }

    /// Set the visible range.
    pub fn set_range(&mut self, start: i64, end: i64) {
        self.range_start = start;
        self.range_end = end;
    }

    /// Expand the range to include the given snap.
    pub fn expand_to(&mut self, snap: i64) {
        if snap < self.range_start {
            self.range_start = snap;
        }
        if snap > self.range_end {
            self.range_end = snap;
        }
    }

    /// Whether the viewport is pinned.
    pub fn is_pinned(&self) -> bool {
        self.pinned
    }

    /// Set whether the viewport is pinned.
    pub fn set_pinned(&mut self, pinned: bool) {
        self.pinned = pinned;
    }

    /// Whether the given snap is within the visible range.
    pub fn contains(&self, snap: i64) -> bool {
        snap >= self.range_start && snap <= self.range_end
    }

    /// The number of snaps in the visible range.
    pub fn range_size(&self) -> u64 {
        if self.range_start > self.range_end {
            0
        } else {
            (self.range_end - self.range_start + 1) as u64
        }
    }

    /// Zoom in to a sub-range around the current snap.
    pub fn zoom_in(&mut self, factor: f64) {
        let half_range = ((self.range_end - self.range_start) as f64 / 2.0 / factor) as i64;
        self.range_start = self.snap - half_range;
        self.range_end = self.snap + half_range;
    }

    /// Zoom out from the current range.
    pub fn zoom_out(&mut self, factor: f64) {
        let half_range = ((self.range_end - self.range_start) as f64 / 2.0 * factor) as i64;
        self.range_start = self.snap - half_range;
        self.range_end = self.snap + half_range;
    }
}

impl Default for TraceTimeViewport {
    fn default() -> Self {
        Self::single_snap(0)
    }
}

/// A viewport with a single snap focus (the scratch/working snap).
///
/// This is the most common viewport for debugging: one current position.
#[derive(Debug, Clone)]
pub struct SingleSnapViewport {
    inner: TraceTimeViewport,
}

impl SingleSnapViewport {
    /// Create a new single-snap viewport.
    pub fn new(snap: i64) -> Self {
        Self {
            inner: TraceTimeViewport::single_snap(snap),
        }
    }

    /// Get the current snap.
    pub fn snap(&self) -> i64 {
        self.inner.snap()
    }

    /// Set the snap.
    pub fn set_snap(&mut self, snap: i64) {
        self.inner.set_snap(snap);
        self.inner.set_range(snap, snap);
    }

    /// Get the inner viewport.
    pub fn inner(&self) -> &TraceTimeViewport {
        &self.inner
    }
}

impl Default for SingleSnapViewport {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_viewport_new() {
        let vp = TraceTimeViewport::new(5, 0, 10);
        assert_eq!(vp.snap(), 5);
        assert_eq!(vp.range_start(), 0);
        assert_eq!(vp.range_end(), 10);
        assert!(vp.contains(3));
        assert!(!vp.contains(11));
    }

    #[test]
    fn test_time_viewport_single() {
        let vp = TraceTimeViewport::single_snap(42);
        assert_eq!(vp.snap(), 42);
        assert_eq!(vp.range_size(), 1);
        assert!(vp.contains(42));
        assert!(!vp.contains(43));
    }

    #[test]
    fn test_time_viewport_expand() {
        let mut vp = TraceTimeViewport::new(5, 3, 7);
        vp.expand_to(1);
        assert_eq!(vp.range_start(), 1);
        vp.expand_to(20);
        assert_eq!(vp.range_end(), 20);
    }

    #[test]
    fn test_time_viewport_pinned() {
        let mut vp = TraceTimeViewport::new(0, 0, 100);
        assert!(!vp.is_pinned());
        vp.set_pinned(true);
        assert!(vp.is_pinned());
    }

    #[test]
    fn test_time_viewport_zoom() {
        let mut vp = TraceTimeViewport::new(50, 0, 100);
        vp.zoom_in(2.0);
        assert_eq!(vp.range_start(), 25);
        assert_eq!(vp.range_end(), 75);
    }

    #[test]
    fn test_single_snap_viewport() {
        let mut vp = SingleSnapViewport::new(10);
        assert_eq!(vp.snap(), 10);
        vp.set_snap(20);
        assert_eq!(vp.snap(), 20);
        assert_eq!(vp.inner().range_start(), 20);
        assert_eq!(vp.inner().range_end(), 20);
    }
}
