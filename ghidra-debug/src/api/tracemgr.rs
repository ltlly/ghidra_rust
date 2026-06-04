//! DebuggerCoordinates - represents a position in the trace coordinate system.
//!
//! Ported from Ghidra's `ghidra.debug.api.tracemgr.DebuggerCoordinates`.
//! Captures the current trace, snap, thread, and frame that the user is viewing.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// The coordinates of the user's current position in a trace.
///
/// This captures: which trace, which snapshot, which thread, and which
/// frame the user is viewing. Used extensively by UI components to stay
/// synchronized.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DebuggerCoordinates {
    /// The trace key (or None if no trace is selected).
    pub trace_key: Option<i64>,
    /// The current snap (or None if no snap is selected).
    pub snap: Option<i64>,
    /// The thread key (or None if no thread is selected).
    pub thread_key: Option<i64>,
    /// The frame level (or None if no frame is selected).
    pub frame_level: Option<i32>,
    /// The process key (or None if no process is selected).
    pub process_key: Option<i64>,
}

impl DebuggerCoordinates {
    /// Create coordinates with no trace selected.
    pub fn none() -> Self {
        Self::default()
    }

    /// Create coordinates with just a trace.
    pub fn trace(trace_key: i64) -> Self {
        Self {
            trace_key: Some(trace_key),
            ..Self::default()
        }
    }

    /// Set the snap.
    pub fn with_snap(mut self, snap: i64) -> Self {
        self.snap = Some(snap);
        self
    }

    /// Set the thread.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }

    /// Set the frame level.
    pub fn with_frame(mut self, frame_level: i32) -> Self {
        self.frame_level = Some(frame_level);
        self
    }

    /// Set the process.
    pub fn with_process(mut self, process_key: i64) -> Self {
        self.process_key = Some(process_key);
        self
    }

    /// Whether a trace is selected.
    pub fn has_trace(&self) -> bool {
        self.trace_key.is_some()
    }

    /// Whether a snap is selected.
    pub fn has_snap(&self) -> bool {
        self.snap.is_some()
    }

    /// Whether a thread is selected.
    pub fn has_thread(&self) -> bool {
        self.thread_key.is_some()
    }

    /// Get the lifespan for just this snap.
    pub fn lifespan(&self) -> Option<Lifespan> {
        self.snap.map(Lifespan::at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none() {
        let coords = DebuggerCoordinates::none();
        assert!(!coords.has_trace());
        assert!(!coords.has_snap());
        assert!(!coords.has_thread());
    }

    #[test]
    fn test_builder() {
        let coords = DebuggerCoordinates::trace(1)
            .with_snap(5)
            .with_thread(100)
            .with_frame(0)
            .with_process(42);

        assert!(coords.has_trace());
        assert_eq!(coords.trace_key, Some(1));
        assert_eq!(coords.snap, Some(5));
        assert_eq!(coords.thread_key, Some(100));
        assert_eq!(coords.frame_level, Some(0));
        assert_eq!(coords.process_key, Some(42));
    }

    #[test]
    fn test_lifespan() {
        let coords = DebuggerCoordinates::trace(1).with_snap(5);
        let ls = coords.lifespan();
        assert!(ls.is_some());
        assert_eq!(ls.unwrap(), Lifespan::at(5));

        let no_snap = DebuggerCoordinates::trace(1);
        assert!(no_snap.lifespan().is_none());
    }

    #[test]
    fn test_serde() {
        let coords = DebuggerCoordinates::trace(1).with_snap(5).with_thread(100);
        let json = serde_json::to_string(&coords).unwrap();
        let back: DebuggerCoordinates = serde_json::from_str(&json).unwrap();
        assert_eq!(back.trace_key, Some(1));
    }
}
