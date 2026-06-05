//! Debugger coordinates: a snapshot of the user's current position in the
//! debugger.
//!
//! Ported from Ghidra's `DebuggerCoordinates` record. This immutable value
//! type carries all the information about the "current" state of the debugger
//! view: which trace, snap, thread, frame, and program are in focus.

use serde::{Deserialize, Serialize};

/// A snapshot of the user's current position in the debugger.
///
/// Each field is independently optional, allowing partial coordinates
/// (e.g., a trace with no thread selected). The `frame()` method
/// produces a new coordinates with the frame level changed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DebuggerCoordinates {
    /// The trace key (None if no trace is active).
    pub trace_key: Option<String>,
    /// The snapshot (time) key.
    pub snap: Option<i64>,
    /// The thread key (None if no thread selected).
    pub thread_key: Option<i64>,
    /// The thread name for display.
    pub thread_name: Option<String>,
    /// The frame level (0 = innermost).
    pub frame_level: u32,
    /// The program URL mapped to this location.
    pub program_url: Option<String>,
    /// The platform name.
    pub platform_name: Option<String>,
    /// The language ID.
    pub language_id: Option<String>,
    /// The compiler spec ID.
    pub compiler_spec_id: Option<String>,
}

impl DebuggerCoordinates {
    /// Create empty coordinates.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create coordinates for a trace.
    pub fn for_trace(trace_key: impl Into<String>) -> Self {
        Self {
            trace_key: Some(trace_key.into()),
            ..Default::default()
        }
    }

    /// Set the snap.
    pub fn with_snap(mut self, snap: i64) -> Self {
        self.snap = Some(snap);
        self
    }

    /// Set the thread.
    pub fn with_thread(mut self, key: i64, name: impl Into<String>) -> Self {
        self.thread_key = Some(key);
        self.thread_name = Some(name.into());
        self
    }

    /// Set the frame level.
    pub fn with_frame(mut self, level: u32) -> Self {
        self.frame_level = level;
        self
    }

    /// Produce new coordinates with a different frame level.
    pub fn frame(&self, level: u32) -> Self {
        Self {
            frame_level: level,
            ..self.clone()
        }
    }

    /// Set the platform info.
    pub fn with_platform(
        mut self,
        name: impl Into<String>,
        lang_id: impl Into<String>,
        cspec_id: impl Into<String>,
    ) -> Self {
        self.platform_name = Some(name.into());
        self.language_id = Some(lang_id.into());
        self.compiler_spec_id = Some(cspec_id.into());
        self
    }

    /// Whether a trace is selected.
    pub fn has_trace(&self) -> bool {
        self.trace_key.is_some()
    }

    /// Whether a thread is selected.
    pub fn has_thread(&self) -> bool {
        self.thread_key.is_some()
    }

    /// Whether these coordinates are the same trace/thread/snap as another.
    pub fn same_location(&self, other: &DebuggerCoordinates) -> bool {
        self.trace_key == other.trace_key
            && self.snap == other.snap
            && self.thread_key == other.thread_key
            && self.frame_level == other.frame_level
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_coordinates() {
        let coords = DebuggerCoordinates::new();
        assert!(!coords.has_trace());
        assert!(!coords.has_thread());
    }

    #[test]
    fn test_for_trace() {
        let coords = DebuggerCoordinates::for_trace("trace1");
        assert!(coords.has_trace());
        assert_eq!(coords.trace_key.as_deref(), Some("trace1"));
    }

    #[test]
    fn test_builder() {
        let coords = DebuggerCoordinates::for_trace("t1")
            .with_snap(5)
            .with_thread(1, "main")
            .with_frame(0)
            .with_platform("linux", "x86:LE:64:default", "default");

        assert_eq!(coords.snap, Some(5));
        assert_eq!(coords.thread_key, Some(1));
        assert_eq!(coords.frame_level, 0);
        assert_eq!(coords.platform_name.as_deref(), Some("linux"));
    }

    #[test]
    fn test_frame_method() {
        let coords = DebuggerCoordinates::for_trace("t1")
            .with_snap(0)
            .with_thread(1, "main");

        let frame3 = coords.frame(3);
        assert_eq!(frame3.frame_level, 3);
        assert_eq!(frame3.trace_key, coords.trace_key);
        assert_eq!(frame3.thread_key, coords.thread_key);
    }

    #[test]
    fn test_same_location() {
        let a = DebuggerCoordinates::for_trace("t1")
            .with_snap(0)
            .with_thread(1, "main")
            .with_frame(0);
        let b = a.clone();
        assert!(a.same_location(&b));

        let c = a.frame(1);
        assert!(!a.same_location(&c));
    }

    #[test]
    fn test_serde() {
        let coords = DebuggerCoordinates::for_trace("t1")
            .with_snap(5)
            .with_thread(42, "main");
        let json = serde_json::to_string(&coords).unwrap();
        let back: DebuggerCoordinates = serde_json::from_str(&json).unwrap();
        assert_eq!(back.trace_key, Some("t1".into()));
        assert_eq!(back.snap, Some(5));
    }
}
