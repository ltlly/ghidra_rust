//! Extended debugger action context types.
//!
//! Ported from Ghidra's `ghidra.debug.api.model` package:
//! - `DebuggerObjectPathActionContext`: Action context carrying a trace object
//!   path, used by scripts and advanced model operations.
//!
//! Note: Other action context types (DebuggerProgramLocationActionContext,
//! DebuggerMemoryBytesActionContext, DebuggerWatchActionContext,
//! DebuggerTraceFileActionContext) are defined in `gui_action_contexts.rs`.

use serde::{Deserialize, Serialize};

use crate::target::KeyPath;

/// An action context from the debugger model tree, carrying a trace
/// object path.
///
/// Ported from Ghidra's `DebuggerObjectActionContext` (extended variant
/// with path support for scripting).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerObjectPathActionContext {
    /// The trace key.
    pub trace_key: Option<i64>,
    /// The snap.
    pub snap: Option<i64>,
    /// The object path in the target tree.
    pub path: KeyPath,
    /// The thread key (for thread-scoped objects).
    pub thread_key: Option<u64>,
    /// The frame level.
    pub frame: Option<i32>,
}

impl DebuggerObjectPathActionContext {
    /// Create a new object path context.
    pub fn new(path: KeyPath) -> Self {
        Self {
            trace_key: None,
            snap: None,
            path,
            thread_key: None,
            frame: None,
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

    /// Set the thread key and frame.
    pub fn with_thread(mut self, thread_key: u64, frame: i32) -> Self {
        self.thread_key = Some(thread_key);
        self.frame = Some(frame);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_path_context() {
        let path = KeyPath::parse("Processes[1]/Threads[2]");
        let ctx = DebuggerObjectPathActionContext::new(path.clone())
            .with_trace_key(5)
            .with_snap(100)
            .with_thread(2, 0);

        assert_eq!(ctx.trace_key, Some(5));
        assert_eq!(ctx.snap, Some(100));
        assert_eq!(ctx.thread_key, Some(2));
        assert_eq!(ctx.frame, Some(0));
        assert_eq!(ctx.path, path);
    }

    #[test]
    fn test_object_path_context_minimal() {
        let path = KeyPath::parse("Environment");
        let ctx = DebuggerObjectPathActionContext::new(path.clone());
        assert!(ctx.trace_key.is_none());
        assert!(ctx.snap.is_none());
        assert!(ctx.thread_key.is_none());
        assert!(ctx.frame.is_none());
    }
}
