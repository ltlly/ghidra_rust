//! TraceTimeViewport - the viewport for time-based navigation in traces.
//!
//! Ported from Ghidra's `ghidra.trace.model.TraceTimeViewport`.

use serde::{Deserialize, Serialize};

/// A viewport that tracks the current time (snap) position in a trace.
///
/// This is used by the UI to track which snapshot the user is viewing,
/// and to support time-based navigation (forward/backward through snapshots).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTimeViewport {
    /// The currently viewed snap.
    pub current_snap: i64,
    /// The minimum snap that has been viewed in this session.
    pub min_viewed_snap: i64,
    /// The maximum snap that has been viewed in this session.
    pub max_viewed_snap: i64,
    /// Whether to follow the latest snap (live tracking).
    pub follow_live: bool,
}

impl TraceTimeViewport {
    /// Create a new viewport at snap 0.
    pub fn new() -> Self {
        Self {
            current_snap: 0,
            min_viewed_snap: 0,
            max_viewed_snap: 0,
            follow_live: false,
        }
    }

    /// Create a viewport at a specific snap.
    pub fn at(snap: i64) -> Self {
        Self {
            current_snap: snap,
            min_viewed_snap: snap,
            max_viewed_snap: snap,
            follow_live: false,
        }
    }

    /// Set the current snap and update the viewed range.
    pub fn set_snap(&mut self, snap: i64) {
        self.current_snap = snap;
        if snap < self.min_viewed_snap {
            self.min_viewed_snap = snap;
        }
        if snap > self.max_viewed_snap {
            self.max_viewed_snap = snap;
        }
    }

    /// Move to the next snap.
    pub fn next_snap(&mut self) {
        self.set_snap(self.current_snap + 1);
    }

    /// Move to the previous snap.
    pub fn previous_snap(&mut self) {
        if self.current_snap > 0 {
            self.set_snap(self.current_snap - 1);
        }
    }

    /// Enable live following.
    pub fn enable_follow_live(&mut self) {
        self.follow_live = true;
    }

    /// Disable live following.
    pub fn disable_follow_live(&mut self) {
        self.follow_live = false;
    }

    /// Get the range of viewed snaps.
    pub fn viewed_range(&self) -> (i64, i64) {
        (self.min_viewed_snap, self.max_viewed_snap)
    }

    /// Reset the viewed range to the current snap.
    pub fn reset_viewed_range(&mut self) {
        self.min_viewed_snap = self.current_snap;
        self.max_viewed_snap = self.current_snap;
    }
}

impl Default for TraceTimeViewport {
    fn default() -> Self {
        Self::new()
    }
}

/// A single-snap viewport that is always at a fixed snap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleSnapViewport {
    /// The fixed snap.
    pub snap: i64,
}

impl SingleSnapViewport {
    /// Create a new single-snap viewport.
    pub fn new(snap: i64) -> Self {
        Self { snap }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_viewport_navigation() {
        let mut vp = TraceTimeViewport::at(10);
        assert_eq!(vp.current_snap, 10);

        vp.next_snap();
        assert_eq!(vp.current_snap, 11);

        vp.previous_snap();
        assert_eq!(vp.current_snap, 10);
    }

    #[test]
    fn test_viewed_range() {
        let mut vp = TraceTimeViewport::new();
        vp.set_snap(5);
        vp.set_snap(15);
        vp.set_snap(3);

        assert_eq!(vp.viewed_range(), (3, 15));
        assert_eq!(vp.current_snap, 3);
    }

    #[test]
    fn test_follow_live() {
        let mut vp = TraceTimeViewport::new();
        assert!(!vp.follow_live);

        vp.enable_follow_live();
        assert!(vp.follow_live);

        vp.disable_follow_live();
        assert!(!vp.follow_live);
    }

    #[test]
    fn test_reset_viewed_range() {
        let mut vp = TraceTimeViewport::at(10);
        vp.set_snap(20);
        vp.set_snap(5);
        assert_eq!(vp.viewed_range(), (5, 20));

        vp.reset_viewed_range();
        assert_eq!(vp.viewed_range(), (5, 5));
    }

    #[test]
    fn test_previous_at_zero() {
        let mut vp = TraceTimeViewport::at(0);
        vp.previous_snap();
        assert_eq!(vp.current_snap, 0);
    }

    #[test]
    fn test_single_snap_viewport() {
        let vp = SingleSnapViewport::new(42);
        assert_eq!(vp.snap, 42);
    }
}
