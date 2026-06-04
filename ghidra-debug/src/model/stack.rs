//! TraceStack - stack frames and call stacks in a trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.stack` package.
//! Represents call stacks and their frames for threads in a trace.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::Lifespan;

/// A single frame in a call stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStackFrame {
    /// The frame level (0 = innermost/current).
    pub level: i32,
    /// The program counter (PC) for this frame.
    pub pc: u64,
    /// The stack pointer for this frame.
    pub sp: u64,
    /// The frame pointer for this frame (if available).
    pub fp: Option<u64>,
    /// The return address for this frame.
    pub return_address: Option<u64>,
    /// Optional function name.
    pub function_name: Option<String>,
}

impl TraceStackFrame {
    /// Create a new stack frame.
    pub fn new(level: i32, pc: u64, sp: u64) -> Self {
        Self {
            level,
            pc,
            sp,
            fp: None,
            return_address: None,
            function_name: None,
        }
    }

    /// Set the frame pointer.
    pub fn with_fp(mut self, fp: u64) -> Self {
        self.fp = Some(fp);
        self
    }

    /// Set the return address.
    pub fn with_return_address(mut self, addr: u64) -> Self {
        self.return_address = Some(addr);
        self
    }

    /// Set the function name.
    pub fn with_function_name(mut self, name: impl Into<String>) -> Self {
        self.function_name = Some(name.into());
        self
    }

    /// Whether this is the innermost frame (level 0).
    pub fn is_innermost(&self) -> bool {
        self.level == 0
    }
}

/// A call stack for a thread at a given snap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStack {
    /// The thread key this stack belongs to.
    pub thread_key: i64,
    /// The lifespan during which this stack configuration is valid.
    pub lifespan: Lifespan,
    /// The frames in this stack, ordered by level (0 = innermost).
    pub frames: Vec<TraceStackFrame>,
}

impl TraceStack {
    /// Create a new stack for a thread.
    pub fn new(thread_key: i64, lifespan: Lifespan) -> Self {
        Self {
            thread_key,
            lifespan,
            frames: Vec::new(),
        }
    }

    /// Add a frame to this stack.
    pub fn push_frame(&mut self, frame: TraceStackFrame) {
        self.frames.push(frame);
    }

    /// Get the number of frames.
    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Get a frame by level.
    pub fn frame(&self, level: i32) -> Option<&TraceStackFrame> {
        self.frames.iter().find(|f| f.level == level)
    }

    /// Get the innermost frame (level 0).
    pub fn innermost(&self) -> Option<&TraceStackFrame> {
        self.frame(0)
    }

    /// Get the outermost frame (highest level).
    pub fn outermost(&self) -> Option<&TraceStackFrame> {
        self.frames.iter().max_by_key(|f| f.level)
    }

    /// Whether this stack is valid at the given snap.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }
}

/// Manages call stacks for all threads in a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceStackManager {
    /// Stacks keyed by thread_key, each having a list of stack snapshots.
    stacks: BTreeMap<i64, Vec<TraceStack>>,
}

impl TraceStackManager {
    /// Create a new stack manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the stack for a thread at a given lifespan.
    pub fn set_stack(&mut self, stack: TraceStack) {
        let thread_key = stack.thread_key;
        self.stacks.entry(thread_key).or_default().push(stack);
    }

    /// Get the active stack for a thread at the given snap.
    pub fn get_stack(&self, thread_key: i64, snap: i64) -> Option<&TraceStack> {
        self.stacks
            .get(&thread_key)
            .and_then(|stacks| {
                stacks
                    .iter()
                    .filter(|s| s.lifespan.contains(snap))
                    .max_by_key(|s| s.lifespan.lmin())
            })
    }

    /// Get all stacks for a thread.
    pub fn stacks_for_thread(&self, thread_key: i64) -> Option<&Vec<TraceStack>> {
        self.stacks.get(&thread_key)
    }

    /// Clear all stacks for a thread.
    pub fn clear_thread(&mut self, thread_key: i64) {
        self.stacks.remove(&thread_key);
    }

    /// Get the current PC for a thread at the given snap.
    pub fn get_pc(&self, thread_key: i64, snap: i64) -> Option<u64> {
        self.get_stack(thread_key, snap)
            .and_then(|s| s.innermost())
            .map(|f| f.pc)
    }

    /// Get the current SP for a thread at the given snap.
    pub fn get_sp(&self, thread_key: i64, snap: i64) -> Option<u64> {
        self.get_stack(thread_key, snap)
            .and_then(|s| s.innermost())
            .map(|f| f.sp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_frame() {
        let frame = TraceStackFrame::new(0, 0x400000, 0x7fff00)
            .with_fp(0x7fff10)
            .with_return_address(0x400100)
            .with_function_name("main");
        assert!(frame.is_innermost());
        assert_eq!(frame.fp, Some(0x7fff10));
        assert_eq!(frame.function_name.as_deref(), Some("main"));
    }

    #[test]
    fn test_stack_frames() {
        let mut stack = TraceStack::new(1, Lifespan::at(0));
        stack.push_frame(TraceStackFrame::new(0, 0x400100, 0x7fff00));
        stack.push_frame(TraceStackFrame::new(1, 0x400200, 0x7ffe00));
        stack.push_frame(TraceStackFrame::new(2, 0x400300, 0x7ffd00));

        assert_eq!(stack.depth(), 3);
        assert_eq!(stack.innermost().unwrap().pc, 0x400100);
        assert_eq!(stack.outermost().unwrap().pc, 0x400300);
        assert!(stack.frame(1).is_some());
        assert!(stack.frame(5).is_none());
    }

    #[test]
    fn test_stack_manager() {
        let mut mgr = TraceStackManager::new();

        let mut stack = TraceStack::new(1, Lifespan::at(0));
        stack.push_frame(TraceStackFrame::new(0, 0x400000, 0x7fff00));
        stack.push_frame(TraceStackFrame::new(1, 0x400200, 0x7ffe00));
        mgr.set_stack(stack);

        assert_eq!(mgr.get_pc(1, 0), Some(0x400000));
        assert_eq!(mgr.get_sp(1, 0), Some(0x7fff00));
        assert!(mgr.get_stack(1, 0).is_some());
        assert!(mgr.get_stack(2, 0).is_none());
        assert!(mgr.get_pc(1, 1).is_none()); // snap 1 not in lifespan
    }

    #[test]
    fn test_stack_manager_clear() {
        let mut mgr = TraceStackManager::new();
        let stack = TraceStack::new(1, Lifespan::at(0));
        mgr.set_stack(stack);
        mgr.clear_thread(1);
        assert!(mgr.get_stack(1, 0).is_none());
    }

    #[test]
    fn test_stack_serde() {
        let mut stack = TraceStack::new(1, Lifespan::at(0));
        stack.push_frame(TraceStackFrame::new(0, 0x400000, 0x7fff00));
        let json = serde_json::to_string(&stack).unwrap();
        let back: TraceStack = serde_json::from_str(&json).unwrap();
        assert_eq!(back.thread_key, 1);
        assert_eq!(back.depth(), 1);
    }
}
