//! Trace data viewport implementation.
//!
//! Ported from Ghidra's `ghidra.trace.database.DBTraceTimeViewport`.
//!
//! The trace time viewport controls which snap(s) are visible and
//! how they map to the display. It supports:
//! - Single-snap views (classic debugger view)
//! - Multi-snap views (timeline comparisons)
//! - Thread-specific views (where each thread has its own snap)
//!
//! This is used by the GUI to determine which data to display
//! in the listing, memory view, register panel, etc.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

// ---------------------------------------------------------------------------
// Viewport snap configuration
// ---------------------------------------------------------------------------

/// Configuration for a single-snap viewport.
///
/// Ported from the concept of a "fixed" or "current" snap view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleSnapViewport {
    /// The currently displayed snap.
    pub snap: i64,
    /// The thread key for thread-specific views (-1 for global).
    pub thread_key: i64,
}

impl SingleSnapViewport {
    /// Create a new single-snap viewport.
    pub fn new(snap: i64) -> Self {
        Self {
            snap,
            thread_key: -1,
        }
    }

    /// Create a thread-specific viewport.
    pub fn for_thread(snap: i64, thread_key: i64) -> Self {
        Self { snap, thread_key }
    }

    /// Whether this viewport is thread-specific.
    pub fn is_thread_specific(&self) -> bool {
        self.thread_key >= 0
    }
}

impl Default for SingleSnapViewport {
    fn default() -> Self {
        Self { snap: 0, thread_key: -1 }
    }
}

// ---------------------------------------------------------------------------
// TraceTimeViewport
// ---------------------------------------------------------------------------

/// The trace time viewport, controlling which snap(s) are visible.
///
/// Ported from `ghidra.trace.database.DBTraceTimeViewport`.
///
/// In Ghidra's trace model, data is indexed by (address, snap) tuples.
/// The viewport determines which snap(s) the user is currently viewing.
/// For single-snap views (the common case), this is just a snap number.
/// For multi-snap views (used in timeline comparisons), it's a range.
#[derive(Debug, Clone)]
pub struct TraceTimeViewport {
    /// The current primary snap.
    current_snap: i64,
    /// Whether we're viewing a single snap or a range.
    is_range: bool,
    /// The start of the range view (inclusive).
    range_start: i64,
    /// The end of the range view (inclusive).
    range_end: i64,
    /// Thread-specific snap overrides.
    thread_snaps: std::collections::BTreeMap<i64, i64>,
}

impl TraceTimeViewport {
    /// Create a new viewport at snap 0.
    pub fn new() -> Self {
        Self {
            current_snap: 0,
            is_range: false,
            range_start: 0,
            range_end: 0,
            thread_snaps: std::collections::BTreeMap::new(),
        }
    }

    /// Get the current snap.
    pub fn current_snap(&self) -> i64 {
        self.current_snap
    }

    /// Set the current snap.
    pub fn set_snap(&mut self, snap: i64) {
        self.current_snap = snap;
        self.is_range = false;
    }

    /// Get the snap for a specific thread.
    ///
    /// Returns the thread-specific snap if set, otherwise the global snap.
    pub fn snap_for_thread(&self, thread_key: i64) -> i64 {
        self.thread_snaps
            .get(&thread_key)
            .copied()
            .unwrap_or(self.current_snap)
    }

    /// Set a thread-specific snap.
    pub fn set_thread_snap(&mut self, thread_key: i64, snap: i64) {
        self.thread_snaps.insert(thread_key, snap);
    }

    /// Clear a thread-specific snap override.
    pub fn clear_thread_snap(&mut self, thread_key: i64) {
        self.thread_snaps.remove(&thread_key);
    }

    /// Set the viewport to a range view.
    pub fn set_range(&mut self, start: i64, end: i64) {
        self.is_range = true;
        self.range_start = start;
        self.range_end = end;
        self.current_snap = start;
    }

    /// Whether the viewport is showing a range.
    pub fn is_range_view(&self) -> bool {
        self.is_range
    }

    /// Get the range start (or the single snap if not a range view).
    pub fn range_start(&self) -> i64 {
        if self.is_range {
            self.range_start
        } else {
            self.current_snap
        }
    }

    /// Get the range end (or the single snap if not a range view).
    pub fn range_end(&self) -> i64 {
        if self.is_range {
            self.range_end
        } else {
            self.current_snap
        }
    }

    /// Get the visible lifespan.
    pub fn visible_lifespan(&self) -> Lifespan {
        if self.is_range {
            Lifespan::span(self.range_start, self.range_end)
        } else {
            Lifespan::span(self.current_snap, self.current_snap)
        }
    }

    /// Check whether the given snap is visible in this viewport.
    pub fn is_snap_visible(&self, snap: i64) -> bool {
        if self.is_range {
            snap >= self.range_start && snap <= self.range_end
        } else {
            snap == self.current_snap
        }
    }

    /// Get all thread keys with specific snap overrides.
    pub fn thread_overrides(&self) -> Vec<(i64, i64)> {
        self.thread_snaps.iter().map(|(&k, &v)| (k, v)).collect()
    }
}

impl Default for TraceTimeViewport {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_snap_viewport() {
        let vp = SingleSnapViewport::new(10);
        assert_eq!(vp.snap, 10);
        assert!(!vp.is_thread_specific());

        let vp_thread = SingleSnapViewport::for_thread(10, 5);
        assert!(vp_thread.is_thread_specific());
        assert_eq!(vp_thread.thread_key, 5);
    }

    #[test]
    fn test_time_viewport_basic() {
        let mut vp = TraceTimeViewport::new();
        assert_eq!(vp.current_snap(), 0);

        vp.set_snap(10);
        assert_eq!(vp.current_snap(), 10);
        assert!(!vp.is_range_view());
        assert!(vp.is_snap_visible(10));
        assert!(!vp.is_snap_visible(9));
    }

    #[test]
    fn test_time_viewport_range() {
        let mut vp = TraceTimeViewport::new();
        vp.set_range(5, 15);

        assert!(vp.is_range_view());
        assert_eq!(vp.range_start(), 5);
        assert_eq!(vp.range_end(), 15);
        assert!(vp.is_snap_visible(5));
        assert!(vp.is_snap_visible(10));
        assert!(vp.is_snap_visible(15));
        assert!(!vp.is_snap_visible(4));
        assert!(!vp.is_snap_visible(16));
    }

    #[test]
    fn test_time_viewport_thread_overrides() {
        let mut vp = TraceTimeViewport::new();
        vp.set_snap(0);
        vp.set_thread_snap(1, 10);
        vp.set_thread_snap(2, 20);

        assert_eq!(vp.snap_for_thread(0), 0); // No override
        assert_eq!(vp.snap_for_thread(1), 10);
        assert_eq!(vp.snap_for_thread(2), 20);

        vp.clear_thread_snap(1);
        assert_eq!(vp.snap_for_thread(1), 0); // Cleared
    }

    #[test]
    fn test_time_viewport_visible_lifespan() {
        let mut vp = TraceTimeViewport::new();
        vp.set_snap(5);
        assert_eq!(vp.visible_lifespan(), Lifespan::span(5, 5));

        vp.set_range(3, 8);
        assert_eq!(vp.visible_lifespan(), Lifespan::span(3, 8));
    }

    #[test]
    fn test_time_viewport_thread_overrides_list() {
        let mut vp = TraceTimeViewport::new();
        vp.set_thread_snap(1, 10);
        vp.set_thread_snap(2, 20);

        let overrides = vp.thread_overrides();
        assert_eq!(overrides.len(), 2);
        assert!(overrides.contains(&(1, 10)));
        assert!(overrides.contains(&(2, 20)));
    }
}
