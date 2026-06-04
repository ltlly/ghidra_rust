//! Debugger coordinates - the position in a debug session.
//!
//! Ported from Ghidra's `ghidra.debug.api.tracemgr.DebuggerCoordinates`.
//! Coordinates represent the user's current position in a debug session,
//! combining the trace, snap, thread, and frame.

use serde::{Deserialize, Serialize};

/// The user's current position in a debug session.
///
/// Ported from Ghidra's `DebuggerCoordinates` record. This combines
/// the trace, the current time (snap), the current thread, and the
/// current stack frame into a single navigable position.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DebuggerCoordinates {
    /// The trace ID, or `None` if no trace is open.
    pub trace_id: Option<String>,
    /// The current snap (time).
    pub snap: i64,
    /// The current thread key, or `None` if no thread is selected.
    pub thread_key: Option<i64>,
    /// The current frame number.
    pub frame: i32,
    /// The current address offset, or `None` if not set.
    pub offset: Option<u64>,
    /// The address space name for the offset.
    pub space: Option<String>,
}

impl Default for DebuggerCoordinates {
    fn default() -> Self {
        Self {
            trace_id: None,
            snap: 0,
            thread_key: None,
            frame: 0,
            offset: None,
            space: None,
        }
    }
}

impl DebuggerCoordinates {
    /// Create "nowhere" -- no trace, no position.
    pub fn nowhere() -> Self {
        Self::default()
    }

    /// Create coordinates pointing at a trace.
    pub fn at_trace(trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: Some(trace_id.into()),
            ..Default::default()
        }
    }

    /// Set the snap.
    pub fn with_snap(mut self, snap: i64) -> Self {
        self.snap = snap;
        self
    }

    /// Set the thread.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }

    /// Set the frame.
    pub fn with_frame(mut self, frame: i32) -> Self {
        self.frame = frame;
        self
    }

    /// Set the offset.
    pub fn with_offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Set the address space.
    pub fn with_space(mut self, space: impl Into<String>) -> Self {
        self.space = Some(space.into());
        self
    }

    /// Whether these coordinates point to a trace.
    pub fn has_trace(&self) -> bool {
        self.trace_id.is_some()
    }

    /// Whether these coordinates point to a thread.
    pub fn has_thread(&self) -> bool {
        self.thread_key.is_some()
    }

    /// Whether these coordinates point to an address.
    pub fn has_offset(&self) -> bool {
        self.offset.is_some()
    }

    /// Whether this represents "nowhere" (no trace selected).
    pub fn is_nowhere(&self) -> bool {
        self.trace_id.is_none()
    }

    /// Get the trace ID, panicking if nowhere.
    pub fn trace_id(&self) -> &str {
        self.trace_id.as_deref().unwrap_or("")
    }

    /// Get the thread key, if set.
    pub fn thread_key(&self) -> Option<i64> {
        self.thread_key
    }

    /// Navigate to a different snap.
    pub fn go_to_snap(&self, snap: i64) -> Self {
        Self {
            snap,
            ..self.clone()
        }
    }

    /// Navigate to a different thread.
    pub fn go_to_thread(&self, thread_key: i64) -> Self {
        Self {
            thread_key: Some(thread_key),
            frame: 0,
            ..self.clone()
        }
    }

    /// Navigate to a different frame.
    pub fn go_to_frame(&self, frame: i32) -> Self {
        Self {
            frame,
            ..self.clone()
        }
    }

    /// Navigate to a different address.
    pub fn go_to_address(&self, space: impl Into<String>, offset: u64) -> Self {
        Self {
            space: Some(space.into()),
            offset: Some(offset),
            ..self.clone()
        }
    }

    /// Derive coordinates for a child thread with the same trace and snap.
    pub fn derive(&self, thread_key: i64) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            snap: self.snap,
            thread_key: Some(thread_key),
            frame: 0,
            offset: None,
            space: None,
        }
    }

    /// Derive coordinates for a specific snap within the same trace/thread.
    pub fn derive_snap(&self, snap: i64) -> Self {
        Self {
            snap,
            ..self.clone()
        }
    }
}

/// An iterator/enumerator for active lifespans within coordinates.
///
/// Ported from Ghidra's `EnumeratingIterator` concept -- iterates
/// over (snap, value) pairs within a given lifespan.
#[derive(Debug, Clone)]
pub struct LifespanEnumerator<T> {
    entries: Vec<(i64, T)>,
    index: usize,
}

impl<T: Clone> LifespanEnumerator<T> {
    /// Create a new enumerator from snap/value pairs.
    pub fn new(entries: Vec<(i64, T)>) -> Self {
        Self { entries, index: 0 }
    }

    /// Get the remaining entries.
    pub fn remaining(&self) -> &[(i64, T)] {
        &self.entries[self.index..]
    }
}

impl<T: Clone> Iterator for LifespanEnumerator<T> {
    type Item = (i64, T);

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.entries.len() {
            let item = self.entries[self.index].clone();
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.entries.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl<T: Clone> ExactSizeIterator for LifespanEnumerator<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordinates_nowhere() {
        let coords = DebuggerCoordinates::nowhere();
        assert!(coords.is_nowhere());
        assert!(!coords.has_trace());
        assert!(!coords.has_thread());
    }

    #[test]
    fn test_coordinates_builder() {
        let coords = DebuggerCoordinates::at_trace("trace1")
            .with_snap(5)
            .with_thread(42)
            .with_frame(2)
            .with_offset(0x400000)
            .with_space("ram");

        assert!(coords.has_trace());
        assert!(coords.has_thread());
        assert!(coords.has_offset());
        assert_eq!(coords.trace_id(), "trace1");
        assert_eq!(coords.snap, 5);
        assert_eq!(coords.thread_key(), Some(42));
        assert_eq!(coords.frame, 2);
        assert_eq!(coords.offset, Some(0x400000));
        assert_eq!(coords.space.as_deref(), Some("ram"));
    }

    #[test]
    fn test_coordinates_navigation() {
        let coords = DebuggerCoordinates::at_trace("trace1")
            .with_snap(0)
            .with_thread(1);

        let at_snap_5 = coords.go_to_snap(5);
        assert_eq!(at_snap_5.snap, 5);
        assert_eq!(at_snap_5.thread_key(), Some(1));

        let at_thread_2 = coords.go_to_thread(2);
        assert_eq!(at_thread_2.thread_key(), Some(2));
        assert_eq!(at_thread_2.frame, 0); // frame reset on thread change

        let at_frame_3 = at_thread_2.go_to_frame(3);
        assert_eq!(at_frame_3.frame, 3);

        let at_addr = coords.go_to_address("ram", 0x400000);
        assert_eq!(at_addr.offset, Some(0x400000));
        assert_eq!(at_addr.space.as_deref(), Some("ram"));
    }

    #[test]
    fn test_coordinates_derive() {
        let coords = DebuggerCoordinates::at_trace("trace1")
            .with_snap(10)
            .with_thread(1);

        let child = coords.derive(2);
        assert_eq!(child.trace_id(), "trace1");
        assert_eq!(child.snap, 10);
        assert_eq!(child.thread_key(), Some(2));
        assert_eq!(child.frame, 0);
        assert!(child.offset.is_none());

        let at_snap = coords.derive_snap(20);
        assert_eq!(at_snap.snap, 20);
        assert_eq!(at_snap.thread_key(), Some(1));
    }

    #[test]
    fn test_lifespan_enumerator() {
        let entries = vec![(0, "a"), (5, "b"), (10, "c")];
        let mut enumerator = LifespanEnumerator::new(entries);
        assert_eq!(enumerator.len(), 3);

        assert_eq!(enumerator.next(), Some((0, "a")));
        assert_eq!(enumerator.len(), 2);
        assert_eq!(enumerator.next(), Some((5, "b")));
        assert_eq!(enumerator.next(), Some((10, "c")));
        assert_eq!(enumerator.next(), None);
    }

    #[test]
    fn test_coordinates_serde() {
        let coords = DebuggerCoordinates::at_trace("trace1")
            .with_snap(5)
            .with_thread(42);
        let json = serde_json::to_string(&coords).unwrap();
        let back: DebuggerCoordinates = serde_json::from_str(&json).unwrap();
        assert_eq!(back.trace_id(), "trace1");
        assert_eq!(back.thread_key(), Some(42));
    }
}
