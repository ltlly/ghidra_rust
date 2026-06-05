//! Trace stack manager - manages stack frames and unwinding.
//!
//! Ported from Ghidra's `TraceStackManager`, `TraceStack`, `TraceStackFrame`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A stack frame within a trace's call stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStackFrame {
    /// Frame level (0 = innermost).
    pub level: u32,
    /// Program counter (return address) for this frame.
    pub pc: u64,
    /// Stack pointer for this frame.
    pub sp: u64,
    /// Frame pointer for this frame (if available).
    pub fp: Option<u64>,
    /// The function name (if known).
    pub function_name: Option<String>,
}

impl TraceStackFrame {
    /// Create a new stack frame.
    pub fn new(level: u32, pc: u64, sp: u64) -> Self {
        Self {
            level,
            pc,
            sp,
            fp: None,
            function_name: None,
        }
    }

    /// Set the frame pointer.
    pub fn with_fp(mut self, fp: u64) -> Self {
        self.fp = Some(fp);
        self
    }

    /// Set the function name.
    pub fn with_function(mut self, name: impl Into<String>) -> Self {
        self.function_name = Some(name.into());
        self
    }
}

/// A call stack for a thread at a given snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStack {
    /// The thread key.
    pub thread_key: i64,
    /// The snapshot.
    pub snap: i64,
    /// The stack frames (innermost first).
    pub frames: Vec<TraceStackFrame>,
}

impl TraceStack {
    /// Create a new empty stack.
    pub fn new(thread_key: i64, snap: i64) -> Self {
        Self {
            thread_key,
            snap,
            frames: Vec::new(),
        }
    }

    /// Add a frame.
    pub fn push_frame(&mut self, frame: TraceStackFrame) {
        self.frames.push(frame);
    }

    /// Depth of the stack.
    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Get the innermost frame.
    pub fn top_frame(&self) -> Option<&TraceStackFrame> {
        self.frames.first()
    }
}

/// Manages stacks for all threads.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceStackManager {
    /// Stacks keyed by (thread_key, snap).
    stacks: BTreeMap<(i64, i64), TraceStack>,
}

impl TraceStackManager {
    /// Create a new stack manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a stack for a thread at a snapshot.
    pub fn set_stack(&mut self, stack: TraceStack) {
        self.stacks.insert((stack.thread_key, stack.snap), stack);
    }

    /// Get a stack for a thread at a snapshot.
    pub fn get_stack(&self, thread_key: i64, snap: i64) -> Option<&TraceStack> {
        self.stacks.get(&(thread_key, snap))
    }

    /// Remove a stack.
    pub fn remove_stack(&mut self, thread_key: i64, snap: i64) -> Option<TraceStack> {
        self.stacks.remove(&(thread_key, snap))
    }

    /// Count of stacks.
    pub fn count(&self) -> usize {
        self.stacks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_frames() {
        let mut stack = TraceStack::new(1, 0);
        stack.push_frame(
            TraceStackFrame::new(0, 0x400100, 0x7fff00).with_function("main"),
        );
        stack.push_frame(
            TraceStackFrame::new(1, 0x400200, 0x7ffe00).with_function("foo"),
        );
        assert_eq!(stack.depth(), 2);
        assert_eq!(
            stack.top_frame().unwrap().function_name.as_deref(),
            Some("main")
        );
    }

    #[test]
    fn test_stack_manager() {
        let mut mgr = TraceStackManager::new();
        let mut stack = TraceStack::new(1, 0);
        stack.push_frame(TraceStackFrame::new(0, 0x400100, 0x7fff00));
        mgr.set_stack(stack);
        assert!(mgr.get_stack(1, 0).is_some());
        assert!(mgr.get_stack(2, 0).is_none());
    }
}
