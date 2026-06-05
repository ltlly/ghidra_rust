//! TraceUniqueObject - base for objects that are uniquely identified in a trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.TraceUniqueObject`.

use serde::{Deserialize, Serialize};

/// A trait for objects uniquely identified by a key within a trace.
///
/// This is the base for trace objects like threads, modules, breakpoints,
/// bookmarks, etc. Each object has a unique key within its manager.
pub trait TraceUniqueObject {
    /// Get the unique key for this object.
    fn key(&self) -> i64;
}

/// Base implementation for unique trace objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniqueObjectBase {
    /// The unique key.
    pub key: i64,
}

impl UniqueObjectBase {
    /// Create a new unique object.
    pub fn new(key: i64) -> Self {
        Self { key }
    }
}

impl TraceUniqueObject for UniqueObjectBase {
    fn key(&self) -> i64 {
        self.key
    }
}

/// A trait for objects that may be in a "closed" state.
pub trait CloseableTraceObject: TraceUniqueObject {
    /// Check if this object has been closed / invalidated.
    fn is_closed(&self) -> bool;

    /// Assert the object is not closed, returning an error if it is.
    fn assert_open(&self) -> Result<(), TraceClosedObjectError> {
        if self.is_closed() {
            Err(TraceClosedObjectError { key: self.key() })
        } else {
            Ok(())
        }
    }
}

/// Error returned when operating on a closed trace object.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Trace object {key} is closed")]
pub struct TraceClosedObjectError {
    /// The key of the closed object.
    pub key: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unique_object() {
        let obj = UniqueObjectBase::new(42);
        assert_eq!(obj.key(), 42);
    }

    #[test]
    fn test_closed_error() {
        let err = TraceClosedObjectError { key: 10 };
        assert!(err.to_string().contains("10"));
    }

    struct TestObject {
        key: i64,
        closed: bool,
    }

    impl TraceUniqueObject for TestObject {
        fn key(&self) -> i64 {
            self.key
        }
    }

    impl CloseableTraceObject for TestObject {
        fn is_closed(&self) -> bool {
            self.closed
        }
    }

    #[test]
    fn test_closeable_object() {
        let obj = TestObject {
            key: 1,
            closed: false,
        };
        assert!(obj.assert_open().is_ok());

        let closed_obj = TestObject {
            key: 2,
            closed: true,
        };
        assert!(closed_obj.assert_open().is_err());
    }
}
