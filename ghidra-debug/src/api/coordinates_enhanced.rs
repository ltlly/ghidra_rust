//! Enhanced DebuggerCoordinates - navigation, viewport, and coordinate
//! management.
//!
//! Ported from Ghidra's `DebuggerCoordinates` (853 lines in Java).
//! This module extends the basic coordinates with viewport tracking,
//! coordinate filtering, comparison helpers, and navigation methods.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::api::tracemgr::DebuggerCoordinates;

/// A viewport tracks a range of time snaps being viewed.
///
/// This corresponds to Ghidra's `TraceTimeViewport` concept and allows
/// UI components to know what time range is currently visible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeViewport {
    /// The minimum snap in the viewport (inclusive).
    pub min_snap: i64,
    /// The maximum snap in the viewport (inclusive).
    pub max_snap: i64,
    /// The current focus snap within the viewport.
    pub focus_snap: i64,
}

impl TimeViewport {
    /// Create a new viewport at the given snap with zero width.
    pub fn at(snap: i64) -> Self {
        Self {
            min_snap: snap,
            max_snap: snap,
            focus_snap: snap,
        }
    }

    /// Create a viewport spanning the given range.
    pub fn spanned(min: i64, max: i64) -> Self {
        Self {
            min_snap: min,
            max_snap: max,
            focus_snap: min,
        }
    }

    /// Whether the given snap is within the viewport range.
    pub fn contains(&self, snap: i64) -> bool {
        snap >= self.min_snap && snap <= self.max_snap
    }

    /// The number of snaps in the viewport.
    pub fn span_length(&self) -> u64 {
        (self.max_snap - self.min_snap + 1).max(0) as u64
    }

    /// Shift the viewport by the given delta.
    pub fn shift(&mut self, delta: i64) {
        self.min_snap += delta;
        self.max_snap += delta;
        self.focus_snap += delta;
    }

    /// Set the focus snap (clamped to viewport bounds).
    pub fn set_focus(&mut self, snap: i64) {
        self.focus_snap = snap.clamp(self.min_snap, self.max_snap);
    }

    /// Expand the viewport to include the given snap.
    pub fn expand_to(&mut self, snap: i64) {
        if snap < self.min_snap {
            self.min_snap = snap;
        }
        if snap > self.max_snap {
            self.max_snap = snap;
        }
    }
}

/// A coordinate filter allows selecting which coordinates match a criterion.
///
/// Used by UI components to filter displayed coordinates by trace, thread,
/// or time range.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoordinateFilter {
    /// If set, only coordinates with this trace key match.
    pub trace_key: Option<i64>,
    /// If set, only coordinates with this thread key match.
    pub thread_key: Option<i64>,
    /// If set, only coordinates with this snap match.
    pub snap: Option<i64>,
    /// If set, only coordinates within this snap range match.
    pub snap_range: Option<(i64, i64)>,
}

impl CoordinateFilter {
    /// Create an empty filter (matches everything).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a filter for a specific trace.
    pub fn for_trace(trace_key: i64) -> Self {
        Self {
            trace_key: Some(trace_key),
            ..Default::default()
        }
    }

    /// Add a thread filter.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }

    /// Add a snap filter.
    pub fn with_snap(mut self, snap: i64) -> Self {
        self.snap = Some(snap);
        self
    }

    /// Add a snap range filter.
    pub fn with_snap_range(mut self, min: i64, max: i64) -> Self {
        self.snap_range = Some((min, max));
        self
    }

    /// Test whether the given coordinates match this filter.
    pub fn matches(&self, coords: &DebuggerCoordinates) -> bool {
        if let Some(trace) = self.trace_key {
            if coords.trace_key != Some(trace) {
                return false;
            }
        }
        if let Some(thread) = self.thread_key {
            if coords.thread_key != Some(thread) {
                return false;
            }
        }
        if let Some(snap) = self.snap {
            if coords.snap != Some(snap) {
                return false;
            }
        }
        if let Some((min, max)) = self.snap_range {
            match coords.snap {
                Some(s) if s >= min && s <= max => {}
                _ => return false,
            }
        }
        true
    }
}

/// A coordinate set tracks a collection of active coordinates.
///
/// Used for managing multiple active debugging sessions or views.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoordinateSet {
    /// Active coordinate keys.
    keys: BTreeSet<i64>,
    /// The currently focused coordinates.
    pub focused: Option<DebuggerCoordinates>,
}

impl CoordinateSet {
    /// Create an empty coordinate set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add coordinates to the set.
    pub fn insert(&mut self, coords: &DebuggerCoordinates) {
        if let Some(key) = coords.trace_key {
            self.keys.insert(key);
        }
    }

    /// Remove coordinates from the set by trace key.
    pub fn remove(&mut self, trace_key: i64) {
        self.keys.remove(&trace_key);
        if self.focused.as_ref().and_then(|c| c.trace_key) == Some(trace_key) {
            self.focused = None;
        }
    }

    /// Set the focused coordinates.
    pub fn focus(&mut self, coords: DebuggerCoordinates) {
        self.insert(&coords);
        self.focused = Some(coords);
    }

    /// The number of active coordinate keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Whether the set contains the given trace key.
    pub fn contains(&self, trace_key: i64) -> bool {
        self.keys.contains(&trace_key)
    }

    /// Get all trace keys in the set.
    pub fn trace_keys(&self) -> &BTreeSet<i64> {
        &self.keys
    }

    /// Get the focused coordinates.
    pub fn get_focused(&self) -> Option<&DebuggerCoordinates> {
        self.focused.as_ref()
    }
}

/// Extension methods for `DebuggerCoordinates`.
pub trait DebuggerCoordinatesExt {
    /// Produce new coordinates with a different snap.
    fn go_snap(&self, snap: i64) -> DebuggerCoordinates;

    /// Produce new coordinates with a different thread.
    fn go_thread(&self, thread_key: i64) -> DebuggerCoordinates;

    /// Produce new coordinates with no thread selected.
    fn go_no_thread(&self) -> DebuggerCoordinates;

    /// Produce new coordinates pointing to the innermost frame.
    fn go_innermost_frame(&self) -> DebuggerCoordinates;

    /// Whether these coordinates represent a "complete" position
    /// (trace + snap + thread all present).
    fn is_complete(&self) -> bool;

    /// Create a summary string for display.
    fn display_summary(&self) -> String;
}

impl DebuggerCoordinatesExt for DebuggerCoordinates {
    fn go_snap(&self, snap: i64) -> DebuggerCoordinates {
        Self {
            snap: Some(snap),
            ..self.clone()
        }
    }

    fn go_thread(&self, thread_key: i64) -> DebuggerCoordinates {
        Self {
            thread_key: Some(thread_key),
            frame_level: Some(0),
            ..self.clone()
        }
    }

    fn go_no_thread(&self) -> DebuggerCoordinates {
        Self {
            thread_key: None,
            frame_level: None,
            ..self.clone()
        }
    }

    fn go_innermost_frame(&self) -> DebuggerCoordinates {
        Self {
            frame_level: Some(0),
            ..self.clone()
        }
    }

    fn is_complete(&self) -> bool {
        self.trace_key.is_some() && self.snap.is_some() && self.thread_key.is_some()
    }

    fn display_summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(trace) = self.trace_key {
            parts.push(format!("trace={}", trace));
        }
        if let Some(snap) = self.snap {
            parts.push(format!("snap={}", snap));
        }
        if let Some(key) = self.thread_key {
            parts.push(format!("thread_key={}", key));
        }
        if let Some(frame) = self.frame_level {
            if frame > 0 {
                parts.push(format!("frame={}", frame));
            }
        }
        if let Some(proc) = self.process_key {
            parts.push(format!("process={}", proc));
        }
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_viewport_at() {
        let vp = TimeViewport::at(5);
        assert_eq!(vp.min_snap, 5);
        assert_eq!(vp.max_snap, 5);
        assert_eq!(vp.focus_snap, 5);
        assert!(vp.contains(5));
        assert!(!vp.contains(6));
        assert_eq!(vp.span_length(), 1);
    }

    #[test]
    fn test_time_viewport_spanned() {
        let vp = TimeViewport::spanned(0, 10);
        assert!(vp.contains(0));
        assert!(vp.contains(5));
        assert!(vp.contains(10));
        assert!(!vp.contains(11));
        assert_eq!(vp.span_length(), 11);
    }

    #[test]
    fn test_time_viewport_shift() {
        let mut vp = TimeViewport::spanned(0, 10);
        vp.shift(5);
        assert_eq!(vp.min_snap, 5);
        assert_eq!(vp.max_snap, 15);
        assert_eq!(vp.focus_snap, 5);
    }

    #[test]
    fn test_time_viewport_focus() {
        let mut vp = TimeViewport::spanned(0, 10);
        vp.set_focus(5);
        assert_eq!(vp.focus_snap, 5);
        vp.set_focus(20);
        assert_eq!(vp.focus_snap, 10);
        vp.set_focus(-5);
        assert_eq!(vp.focus_snap, 0);
    }

    #[test]
    fn test_time_viewport_expand() {
        let mut vp = TimeViewport::at(5);
        vp.expand_to(10);
        assert_eq!(vp.max_snap, 10);
        vp.expand_to(0);
        assert_eq!(vp.min_snap, 0);
        assert_eq!(vp.span_length(), 11);
    }

    #[test]
    fn test_coordinate_filter_empty() {
        let filter = CoordinateFilter::new();
        let coords = DebuggerCoordinates::trace(1).with_snap(5);
        assert!(filter.matches(&coords));
    }

    #[test]
    fn test_coordinate_filter_trace() {
        let filter = CoordinateFilter::for_trace(1);
        assert!(filter.matches(&DebuggerCoordinates::trace(1)));
        assert!(!filter.matches(&DebuggerCoordinates::trace(2)));
        assert!(!filter.matches(&DebuggerCoordinates::none()));
    }

    #[test]
    fn test_coordinate_filter_combined() {
        let filter = CoordinateFilter::for_trace(1)
            .with_thread(42)
            .with_snap_range(0, 10);
        let coords = DebuggerCoordinates::trace(1)
            .with_snap(5)
            .with_thread(42);
        assert!(filter.matches(&coords));

        let wrong_snap = coords.clone().go_snap(15);
        assert!(!filter.matches(&wrong_snap));
    }

    #[test]
    fn test_coordinate_set() {
        let mut set = CoordinateSet::new();
        assert!(set.is_empty());

        let coords1 = DebuggerCoordinates::trace(1).with_snap(0);
        let coords2 = DebuggerCoordinates::trace(2).with_snap(5);
        set.insert(&coords1);
        set.insert(&coords2);
        assert_eq!(set.len(), 2);
        assert!(set.contains(1));
        assert!(set.contains(2));

        set.focus(coords1.clone());
        assert!(set.get_focused().is_some());

        set.remove(1);
        assert_eq!(set.len(), 1);
        assert!(!set.contains(1));
        assert!(set.get_focused().is_none());
    }

    #[test]
    fn test_coordinates_ext_go_snap() {
        let base = DebuggerCoordinates::trace(1).with_snap(0);
        let moved = base.go_snap(5);
        assert_eq!(moved.snap, Some(5));
        assert_eq!(moved.trace_key, base.trace_key);
    }

    #[test]
    fn test_coordinates_ext_go_thread() {
        let base = DebuggerCoordinates::trace(1).with_snap(0);
        let with_thread = base.go_thread(100);
        assert_eq!(with_thread.thread_key, Some(100));
        assert_eq!(with_thread.frame_level, Some(0));
    }

    #[test]
    fn test_coordinates_ext_go_no_thread() {
        let base = DebuggerCoordinates::trace(1)
            .with_snap(0)
            .with_thread(1)
            .with_frame(3);
        let no_thread = base.go_no_thread();
        assert!(no_thread.thread_key.is_none());
        assert!(no_thread.frame_level.is_none());
        assert_eq!(no_thread.trace_key, base.trace_key);
    }

    #[test]
    fn test_coordinates_ext_is_complete() {
        let incomplete = DebuggerCoordinates::trace(1);
        assert!(!incomplete.is_complete());

        let complete = DebuggerCoordinates::trace(1)
            .with_snap(0)
            .with_thread(1);
        assert!(complete.is_complete());
    }

    #[test]
    fn test_coordinates_ext_display_summary() {
        let coords = DebuggerCoordinates::trace(1)
            .with_snap(5)
            .with_thread(42)
            .with_frame(2);
        let summary = coords.display_summary();
        assert!(summary.contains("trace=1"));
        assert!(summary.contains("snap=5"));
        assert!(summary.contains("thread_key=42"));
        assert!(summary.contains("frame=2"));
    }
}
