//! Coordinate helpers ported from ghidra.trace.util.
//!
//! Provides helpers for working with trace coordinates (snap, thread, frame).

/// A trace coordinate identifying a point in trace execution.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceCoordinate {
    /// The snap (time point).
    pub snap: i64,
    /// The thread key, if any.
    pub thread_key: Option<u64>,
    /// The frame level, if any.
    pub frame_level: Option<i32>,
}

impl TraceCoordinate {
    /// Create a coordinate at the given snap.
    pub fn at_snap(snap: i64) -> Self {
        Self {
            snap,
            thread_key: None,
            frame_level: None,
        }
    }

    /// Create a coordinate at the given snap and thread.
    pub fn at_snap_thread(snap: i64, thread_key: u64) -> Self {
        Self {
            snap,
            thread_key: Some(thread_key),
            frame_level: None,
        }
    }

    /// Create a coordinate at the given snap, thread, and frame.
    pub fn at_snap_thread_frame(snap: i64, thread_key: u64, frame_level: i32) -> Self {
        Self {
            snap,
            thread_key: Some(thread_key),
            frame_level: Some(frame_level),
        }
    }
}

impl std::fmt::Display for TraceCoordinate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "snap={}", self.snap)?;
        if let Some(t) = self.thread_key {
            write!(f, ", thread={}", t)?;
        }
        if let Some(fl) = self.frame_level {
            write!(f, ", frame={}", fl)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordinate_creation() {
        let c = TraceCoordinate::at_snap(42);
        assert_eq!(c.snap, 42);
        assert!(c.thread_key.is_none());
    }

    #[test]
    fn test_full_coordinate() {
        let c = TraceCoordinate::at_snap_thread_frame(1, 2, 3);
        assert_eq!(c.thread_key, Some(2));
        assert_eq!(c.frame_level, Some(3));
    }

    #[test]
    fn test_display() {
        let c = TraceCoordinate::at_snap_thread(5, 10);
        assert!(format!("{}", c).contains("snap=5"));
        assert!(format!("{}", c).contains("thread=10"));
    }
}
