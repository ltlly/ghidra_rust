//! Debugger model action context types.
//!
//! Ported from Ghidra's `ghidra.debug.api.model` package:
//! - `DebuggerObjectActionContext`: Action context for target objects.
//! - `DebuggerSingleObjectPathActionContext`: Action context for a single object path.

use serde::{Deserialize, Serialize};

/// An action context providing information about the target object
/// upon which an action should operate.
///
/// Ported from Ghidra's `DebuggerObjectActionContext`.
pub trait DebuggerObjectActionContext {
    /// Get the trace key associated with this context.
    fn trace_key(&self) -> Option<i64>;

    /// Get the snap (time) at which the action should occur.
    fn snap(&self) -> Option<i64>;

    /// Get the thread ID for thread-scoped actions.
    fn thread_id(&self) -> Option<u64>;

    /// Get the object path components (path from root to the target object).
    fn object_path(&self) -> &[String];
}

/// An action context that refers to a single object path.
///
/// This is the most common action context, used when the user
/// selects a single object in the model tree.
///
/// Ported from Ghidra's `DebuggerSingleObjectPathActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerSingleObjectPathActionContext {
    /// The trace key.
    pub trace_key: Option<i64>,
    /// The snap (time).
    pub snap: Option<i64>,
    /// The thread ID.
    pub thread_id: Option<u64>,
    /// The object path from root to the target object.
    pub path: Vec<String>,
}

impl DebuggerSingleObjectPathActionContext {
    /// Create a new context with the given object path.
    pub fn new(path: Vec<String>) -> Self {
        Self {
            trace_key: None,
            snap: None,
            thread_id: None,
            path,
        }
    }

    /// Set the trace key.
    pub fn with_trace_key(mut self, key: i64) -> Self {
        self.trace_key = Some(key);
        self
    }

    /// Set the snap.
    pub fn with_snap(mut self, snap: i64) -> Self {
        self.snap = Some(snap);
        self
    }

    /// Set the thread ID.
    pub fn with_thread_id(mut self, thread_id: u64) -> Self {
        self.thread_id = Some(thread_id);
        self
    }

    /// Get the leaf (last) component of the object path.
    pub fn leaf(&self) -> Option<&str> {
        self.path.last().map(|s| s.as_str())
    }

    /// Get the parent path (all components except the last).
    pub fn parent_path(&self) -> &[String] {
        if self.path.is_empty() {
            &[]
        } else {
            &self.path[..self.path.len() - 1]
        }
    }

    /// Check if this context has a valid path.
    pub fn has_path(&self) -> bool {
        !self.path.is_empty()
    }
}

impl DebuggerObjectActionContext for DebuggerSingleObjectPathActionContext {
    fn trace_key(&self) -> Option<i64> {
        self.trace_key
    }

    fn snap(&self) -> Option<i64> {
        self.snap
    }

    fn thread_id(&self) -> Option<u64> {
        self.thread_id
    }

    fn object_path(&self) -> &[String] {
        &self.path
    }
}

/// A multi-object action context for operations on multiple selected objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerMultiObjectActionContext {
    /// The trace key.
    pub trace_key: Option<i64>,
    /// The snap (time).
    pub snap: Option<i64>,
    /// All selected object paths.
    pub paths: Vec<Vec<String>>,
}

impl DebuggerMultiObjectActionContext {
    /// Create a new multi-object context.
    pub fn new(paths: Vec<Vec<String>>) -> Self {
        Self {
            trace_key: None,
            snap: None,
            paths,
        }
    }

    /// Set the trace key.
    pub fn with_trace_key(mut self, key: i64) -> Self {
        self.trace_key = Some(key);
        self
    }

    /// Set the snap.
    pub fn with_snap(mut self, snap: i64) -> Self {
        self.snap = Some(snap);
        self
    }

    /// Get the number of selected objects.
    pub fn count(&self) -> usize {
        self.paths.len()
    }

    /// Check if multiple objects are selected.
    pub fn is_multi(&self) -> bool {
        self.paths.len() > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_object_context() {
        let ctx = DebuggerSingleObjectPathActionContext::new(vec![
            "Processes".into(),
            "pid:1234".into(),
            "Threads".into(),
            "tid:5678".into(),
        ])
        .with_trace_key(1)
        .with_snap(0)
        .with_thread_id(5678);

        assert_eq!(ctx.trace_key(), Some(1));
        assert_eq!(ctx.snap(), Some(0));
        assert_eq!(ctx.thread_id(), Some(5678));
        assert_eq!(ctx.leaf(), Some("tid:5678"));
        assert_eq!(ctx.parent_path().len(), 3);
        assert!(ctx.has_path());
    }

    #[test]
    fn test_empty_context() {
        let ctx = DebuggerSingleObjectPathActionContext::new(vec![]);
        assert!(ctx.leaf().is_none());
        assert!(ctx.parent_path().is_empty());
        assert!(!ctx.has_path());
    }

    #[test]
    fn test_multi_object_context() {
        let ctx = DebuggerMultiObjectActionContext::new(vec![
            vec!["Processes".into(), "pid:1".into()],
            vec!["Processes".into(), "pid:2".into()],
        ])
        .with_trace_key(1);

        assert_eq!(ctx.count(), 2);
        assert!(ctx.is_multi());
    }
}
