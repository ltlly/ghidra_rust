//! LocationTracker - tracks the current debug location.
//!
//! Ported from Ghidra's `ghidra.debug.api.LocationTracker`.

use serde::{Deserialize, Serialize};

/// Tracks the current location in a debug session.
///
/// Ported from Ghidra's `LocationTracker` and `LocationTrackingSpec`.
/// Maintains the current thread, frame, and program counter position.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocationTracker {
    /// The current thread key (None if not set).
    pub thread: Option<i64>,
    /// The current stack frame level.
    pub frame: u32,
    /// The current program counter address (as offset).
    pub pc: Option<u64>,
    /// The current snap.
    pub snap: i64,
    /// Whether to follow the debugger's live position.
    pub follow_live: bool,
}

impl LocationTracker {
    /// Create a new location tracker.
    pub fn new() -> Self {
        Self {
            thread: None,
            frame: 0,
            pc: None,
            snap: 0,
            follow_live: true,
        }
    }

    /// Set the current thread.
    pub fn set_thread(&mut self, thread: Option<i64>) {
        self.thread = thread;
    }

    /// Set the current frame level.
    pub fn set_frame(&mut self, frame: u32) {
        self.frame = frame;
    }

    /// Set the current program counter.
    pub fn set_pc(&mut self, pc: Option<u64>) {
        self.pc = pc;
    }

    /// Set the current snap.
    pub fn set_snap(&mut self, snap: i64) {
        self.snap = snap;
    }

    /// Whether a thread is selected.
    pub fn has_thread(&self) -> bool {
        self.thread.is_some()
    }

    /// Get the current thread key.
    pub fn current_thread(&self) -> Option<i64> {
        self.thread
    }

    /// Get the current program counter.
    pub fn current_pc(&self) -> Option<u64> {
        self.pc
    }

    /// Clear all location state.
    pub fn clear(&mut self) {
        self.thread = None;
        self.frame = 0;
        self.pc = None;
    }

    /// Update the location from a trace event.
    pub fn update_from_event(&mut self, event: &LocationEvent) {
        if let Some(t) = event.thread {
            self.thread = Some(t);
        }
        if let Some(f) = event.frame {
            self.frame = f;
        }
        if let Some(pc) = event.pc {
            self.pc = Some(pc);
        }
        if let Some(s) = event.snap {
            self.snap = s;
        }
    }
}

/// A location change event.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocationEvent {
    /// The thread that changed.
    pub thread: Option<i64>,
    /// The new frame level.
    pub frame: Option<u32>,
    /// The new program counter.
    pub pc: Option<u64>,
    /// The new snap.
    pub snap: Option<i64>,
}

impl LocationEvent {
    /// Create a PC change event.
    pub fn pc_change(thread: i64, pc: u64) -> Self {
        Self {
            thread: Some(thread),
            pc: Some(pc),
            ..Default::default()
        }
    }

    /// Create a snap change event.
    pub fn snap_change(snap: i64) -> Self {
        Self {
            snap: Some(snap),
            ..Default::default()
        }
    }
}

/// A specification for what constitutes a "location" for tracking purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationTrackingSpec {
    /// The name of this tracking specification.
    pub name: String,
    /// Whether to track thread changes.
    pub track_threads: bool,
    /// Whether to track frame changes.
    pub track_frames: bool,
    /// Whether to track PC changes.
    pub track_pc: bool,
    /// Whether to track snap changes.
    pub track_snaps: bool,
}

impl LocationTrackingSpec {
    /// Default tracking spec that tracks everything.
    pub fn full() -> Self {
        Self {
            name: "Full".into(),
            track_threads: true,
            track_frames: true,
            track_pc: true,
            track_snaps: true,
        }
    }

    /// Track only thread and PC.
    pub fn thread_pc() -> Self {
        Self {
            name: "Thread+PC".into(),
            track_threads: true,
            track_frames: false,
            track_pc: true,
            track_snaps: false,
        }
    }

    /// Track only snaps.
    pub fn snap_only() -> Self {
        Self {
            name: "Snap".into(),
            track_threads: false,
            track_frames: false,
            track_pc: false,
            track_snaps: true,
        }
    }

    /// Filter an event based on this spec.
    pub fn filter_event(&self, event: &LocationEvent) -> LocationEvent {
        LocationEvent {
            thread: if self.track_threads {
                event.thread
            } else {
                None
            },
            frame: if self.track_frames {
                event.frame
            } else {
                None
            },
            pc: if self.track_pc { event.pc } else { None },
            snap: if self.track_snaps {
                event.snap
            } else {
                None
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_location_tracker_new() {
        let lt = LocationTracker::new();
        assert!(lt.thread.is_none());
        assert_eq!(lt.frame, 0);
        assert!(lt.follow_live);
    }

    #[test]
    fn test_location_tracker_set() {
        let mut lt = LocationTracker::new();
        lt.set_thread(Some(42));
        lt.set_frame(2);
        lt.set_pc(Some(0x1000));
        lt.set_snap(5);
        assert!(lt.has_thread());
        assert_eq!(lt.current_thread(), Some(42));
        assert_eq!(lt.current_pc(), Some(0x1000));
    }

    #[test]
    fn test_location_tracker_clear() {
        let mut lt = LocationTracker::new();
        lt.set_thread(Some(1));
        lt.set_pc(Some(100));
        lt.clear();
        assert!(!lt.has_thread());
        assert!(lt.current_pc().is_none());
    }

    #[test]
    fn test_update_from_event() {
        let mut lt = LocationTracker::new();
        let evt = LocationEvent::pc_change(10, 0x400000);
        lt.update_from_event(&evt);
        assert_eq!(lt.current_thread(), Some(10));
        assert_eq!(lt.current_pc(), Some(0x400000));
    }

    #[test]
    fn test_tracking_spec_filter() {
        let spec = LocationTrackingSpec::thread_pc();
        let evt = LocationEvent {
            thread: Some(1),
            frame: Some(3),
            pc: Some(0x100),
            snap: Some(5),
        };
        let filtered = spec.filter_event(&evt);
        assert_eq!(filtered.thread, Some(1));
        assert!(filtered.frame.is_none());
        assert_eq!(filtered.pc, Some(0x100));
        assert!(filtered.snap.is_none());
    }

    #[test]
    fn test_tracking_spec_full() {
        let spec = LocationTrackingSpec::full();
        assert!(spec.track_threads);
        assert!(spec.track_frames);
        assert!(spec.track_pc);
        assert!(spec.track_snaps);
    }

    #[test]
    fn test_serde() {
        let lt = LocationTracker::new();
        let json = serde_json::to_string(&lt).unwrap();
        let back: LocationTracker = serde_json::from_str(&json).unwrap();
        assert_eq!(back.frame, 0);
    }
}
