//! TraceLocation, TraceClosedException, TraceUniqueObject.
//!
//! Ported from Ghidra's `ghidra.trace.model` package.
//! Provides fundamental types for trace addressing, error handling,
//! and unique object identification.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::Lifespan;

/// A location in a trace (snap + address + optional thread).
///
/// Used to specify a unique position within a trace, combining a snapshot
/// key, an address (offset), and optionally a thread.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceLocation {
    /// The snap (snapshot key).
    pub snap: i64,
    /// The address offset.
    pub offset: u64,
    /// The address space name.
    pub space: Option<String>,
    /// The thread key, if this location is thread-specific.
    pub thread_key: Option<i64>,
}

impl TraceLocation {
    /// Create a new trace location.
    pub fn new(snap: i64, offset: u64) -> Self {
        Self {
            snap,
            offset,
            space: None,
            thread_key: None,
        }
    }

    /// Create a location with a specific address space.
    pub fn with_space(mut self, space: impl Into<String>) -> Self {
        self.space = Some(space.into());
        self
    }

    /// Create a location with a specific thread.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }
}

impl PartialOrd for TraceLocation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TraceLocation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.snap
            .cmp(&other.snap)
            .then_with(|| self.space.cmp(&other.space))
            .then_with(|| self.offset.cmp(&other.offset))
            .then_with(|| self.thread_key.cmp(&other.thread_key))
    }
}

impl std::fmt::Display for TraceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref space) = self.space {
            write!(f, "snap={}, {}:{:#x}", self.snap, space, self.offset)?;
        } else {
            write!(f, "snap={}, {:#x}", self.snap, self.offset)?;
        }
        if let Some(tid) = self.thread_key {
            write!(f, ", thread={}", tid)?;
        }
        Ok(())
    }
}

/// Exception indicating a trace has been closed.
///
/// Thrown when operations are attempted on a closed trace.
#[derive(Debug, Error)]
#[error("trace is closed: {message}")]
pub struct TraceClosedException {
    /// The error message.
    pub message: String,
    /// The underlying cause, if any.
    #[source]
    pub cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl TraceClosedException {
    /// Create a new TraceClosedException.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cause: None,
        }
    }

    /// Create with a cause.
    pub fn with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            cause: Some(Box::new(cause)),
        }
    }
}

/// Trait for objects with a unique, immutable key.
///
/// Used by TraceObject and other database-backed entities to provide
/// stable identity.
pub trait TraceUniqueObject {
    /// Get an opaque unique id for this object, whose hash is immutable.
    fn object_key(&self) -> i64;

    /// Check if this object is deleted.
    fn is_deleted(&self) -> bool;
}

/// Default implementation of `TraceUniqueObject` for types with `key` and `deleted` fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniqueObjectBase {
    /// The unique key.
    pub key: i64,
    /// Whether this object is deleted.
    pub deleted: bool,
}

impl UniqueObjectBase {
    /// Create a new unique object base.
    pub fn new(key: i64) -> Self {
        Self {
            key,
            deleted: false,
        }
    }
}

impl TraceUniqueObject for UniqueObjectBase {
    fn object_key(&self) -> i64 {
        self.key
    }

    fn is_deleted(&self) -> bool {
        self.deleted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_location_basic() {
        let loc = TraceLocation::new(5, 0x400000);
        assert_eq!(loc.snap, 5);
        assert_eq!(loc.offset, 0x400000);
        assert!(loc.space.is_none());
        assert!(loc.thread_key.is_none());
    }

    #[test]
    fn test_trace_location_with_space() {
        let loc = TraceLocation::new(0, 0x1000).with_space("ram");
        assert_eq!(loc.space.as_deref(), Some("ram"));
    }

    #[test]
    fn test_trace_location_with_thread() {
        let loc = TraceLocation::new(0, 0x1000).with_thread(42);
        assert_eq!(loc.thread_key, Some(42));
    }

    #[test]
    fn test_trace_location_display() {
        let loc = TraceLocation::new(3, 0x400000);
        assert_eq!(loc.to_string(), "snap=3, 0x400000");

        let loc = TraceLocation::new(3, 0x400000).with_space("ram");
        assert_eq!(loc.to_string(), "snap=3, ram:0x400000");

        let loc = TraceLocation::new(3, 0x400000)
            .with_space("ram")
            .with_thread(42);
        assert_eq!(loc.to_string(), "snap=3, ram:0x400000, thread=42");
    }

    #[test]
    fn test_trace_location_ordering() {
        let a = TraceLocation::new(0, 0x100);
        let b = TraceLocation::new(0, 0x200);
        let c = TraceLocation::new(1, 0x100);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn test_trace_location_serde() {
        let loc = TraceLocation::new(5, 0x400000).with_space("ram");
        let json = serde_json::to_string(&loc).unwrap();
        let back: TraceLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, loc);
    }

    #[test]
    fn test_trace_closed_exception() {
        let e = TraceClosedException::new("cannot modify closed trace");
        assert_eq!(e.message, "cannot modify closed trace");
        assert!(e.cause.is_none());
        let err_str = format!("{}", e);
        assert!(err_str.contains("trace is closed"));
    }

    #[test]
    fn test_unique_object_base() {
        let mut obj = UniqueObjectBase::new(42);
        assert_eq!(obj.object_key(), 42);
        assert!(!obj.is_deleted());
        obj.deleted = true;
        assert!(obj.is_deleted());
    }
}
