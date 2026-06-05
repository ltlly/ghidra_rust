//! Extended trace program view types.
//!
//! Ported from Ghidra's `TraceVariableSnapProgramView` and
//! `TickSpecificTraceView` in `ghidra.trace.model.program`.
//! Provides views of a trace at a variable or specific snapshot.

use serde::{Deserialize, Serialize};

use super::lifespan::Lifespan;

/// A view of a trace at a variable snapshot.
///
/// Unlike a fixed-snap view, this can be adjusted to view
/// different snapshots without creating a new view object.
///
/// Ported from Ghidra's `TraceVariableSnapProgramView`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceVariableSnapProgramView {
    /// The trace ID.
    pub trace_id: String,
    /// The current snap this view is set to.
    pub current_snap: i64,
    /// The minimum snap for this view.
    pub min_snap: i64,
    /// The maximum snap for this view.
    pub max_snap: i64,
    /// The view name.
    pub name: String,
}

impl TraceVariableSnapProgramView {
    /// Create a new variable-snap program view.
    pub fn new(trace_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            current_snap: 0,
            min_snap: i64::MIN,
            max_snap: i64::MAX,
            name: name.into(),
        }
    }

    /// Get the current snap.
    pub fn snap(&self) -> i64 {
        self.current_snap
    }

    /// Set the current snap.
    pub fn set_snap(&mut self, snap: i64) {
        self.current_snap = snap.clamp(self.min_snap, self.max_snap);
    }

    /// Get the valid snap range.
    pub fn snap_range(&self) -> Lifespan {
        Lifespan::span(self.min_snap, self.max_snap)
    }

    /// Set the snap range.
    pub fn set_snap_range(&mut self, min: i64, max: i64) {
        self.min_snap = min;
        self.max_snap = max;
        self.current_snap = self.current_snap.clamp(min, max);
    }
}

/// A view that is tied to a specific tick (snap).
///
/// Ported from Ghidra's `TickSpecificTraceView`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickSpecificTraceView {
    /// The trace ID.
    pub trace_id: String,
    /// The specific tick/snap.
    pub tick: i64,
    /// Whether this view is for a specific thread.
    pub thread_key: Option<i64>,
}

impl TickSpecificTraceView {
    /// Create a new tick-specific view.
    pub fn new(trace_id: impl Into<String>, tick: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            tick,
            thread_key: None,
        }
    }

    /// Set the thread.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }
}

/// A bookmark entry in a program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewBookmarkEntry {
    /// Unique key.
    pub key: i64,
    /// The bookmark type.
    pub bookmark_type: String,
    /// The address.
    pub address: u64,
    /// The address space.
    pub space: String,
    /// The category.
    pub category: String,
    /// The comment.
    pub comment: String,
}

impl ProgramViewBookmarkEntry {
    /// Create a new bookmark entry.
    pub fn new(
        key: i64,
        bookmark_type: impl Into<String>,
        address: u64,
        space: impl Into<String>,
    ) -> Self {
        Self {
            key,
            bookmark_type: bookmark_type.into(),
            address,
            space: space.into(),
            category: String::new(),
            comment: String::new(),
        }
    }

    /// Set the category.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = category.into();
        self
    }

    /// Set the comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = comment.into();
        self
    }
}

/// A snapshot entry in a program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewSnapshotEntry {
    /// The snap key.
    pub key: i64,
    /// Description.
    pub description: String,
    /// Real-world timestamp.
    pub timestamp: i64,
    /// Event thread key.
    pub event_thread_key: Option<i64>,
    /// Schedule string.
    pub schedule: Option<String>,
    /// Version.
    pub version: i64,
}

impl ProgramViewSnapshotEntry {
    /// Create a new snapshot entry.
    pub fn new(key: i64) -> Self {
        Self {
            key,
            description: String::new(),
            timestamp: 0,
            event_thread_key: None,
            schedule: None,
            version: 0,
        }
    }

    /// Check if this is a fork.
    pub fn is_fork(&self) -> bool {
        self.schedule.as_deref().map_or(false, |s| !s.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_snap_view_new() {
        let view = TraceVariableSnapProgramView::new("trace1", "main_view");
        assert_eq!(view.snap(), 0);
        assert_eq!(view.name, "main_view");
    }

    #[test]
    fn test_variable_snap_view_set_snap() {
        let mut view = TraceVariableSnapProgramView::new("t", "v");
        view.set_snap(5);
        assert_eq!(view.snap(), 5);
    }

    #[test]
    fn test_variable_snap_view_clamp() {
        let mut view = TraceVariableSnapProgramView::new("t", "v");
        view.set_snap_range(0, 100);
        view.set_snap(200);
        assert_eq!(view.snap(), 100);
        view.set_snap(-10);
        assert_eq!(view.snap(), 0);
    }

    #[test]
    fn test_tick_specific_view() {
        let view = TickSpecificTraceView::new("t", 42).with_thread(7);
        assert_eq!(view.tick, 42);
        assert_eq!(view.thread_key, Some(7));
    }

    #[test]
    fn test_bookmark_entry_new() {
        let b = ProgramViewBookmarkEntry::new(1, "Analysis", 0x1000, "ram")
            .with_category("warning")
            .with_comment("check this");
        assert_eq!(b.bookmark_type, "Analysis");
        assert_eq!(b.comment, "check this");
    }

    #[test]
    fn test_snapshot_entry() {
        let s = ProgramViewSnapshotEntry::new(0);
        assert_eq!(s.key, 0);
        assert!(!s.is_fork());
    }

    #[test]
    fn test_snapshot_entry_fork() {
        let mut s = ProgramViewSnapshotEntry::new(5);
        s.schedule = Some("4:1".to_string());
        assert!(s.is_fork());
    }
}
