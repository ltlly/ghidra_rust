//! Stack model for the Debug framework.
//!
//! Ported from `ghidra.trace.model.stack` — includes [`TraceStackFrame`],
//! [`TraceStack`], and [`TraceStackManager`].

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use super::core_types::Lifespan;

// ---------------------------------------------------------------------------
// TraceStackFrame
// ---------------------------------------------------------------------------

/// A frame in a call stack.
///
/// Ported from `ghidra.trace.model.stack.TraceStackFrame`.
#[derive(Debug, Clone)]
pub struct TraceStackFrame {
    /// Unique key for this frame.
    key: u64,
    /// The owning stack key.
    pub stack_key: u64,
    /// The frame level (0 = innermost).
    pub level: u32,
    /// The program counter (return address) for this frame.
    pub pc: Option<u64>,
    /// The stack pointer for this frame.
    pub sp: Option<u64>,
    /// The frame pointer for this frame.
    pub fp: Option<u64>,
    /// The lifespan of this frame.
    pub lifespan: Lifespan,
    /// Whether deleted.
    deleted: bool,
}

impl TraceStackFrame {
    /// Create a new stack frame.
    pub fn new(
        key: u64,
        stack_key: u64,
        level: u32,
        pc: Option<u64>,
        sp: Option<u64>,
        fp: Option<u64>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            stack_key,
            level,
            pc,
            sp,
            fp,
            lifespan,
            deleted: false,
        }
    }

    /// Returns the unique key.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Check if valid at the given snapshot.
    pub fn is_valid(&self, snap: i64) -> bool {
        !self.deleted && self.lifespan.contains(snap)
    }

    /// Delete this frame.
    pub fn delete(&mut self) {
        self.deleted = true;
    }
}

impl fmt::Display for TraceStackFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Frame(level={}, pc={:?}, sp={:?})",
            self.level, self.pc, self.sp
        )
    }
}

// ---------------------------------------------------------------------------
// TraceStack
// ---------------------------------------------------------------------------

/// A call stack for a thread.
///
/// Ported from `ghidra.trace.model.stack.TraceStack`.
#[derive(Debug, Clone)]
pub struct TraceStack {
    /// Unique key for this stack.
    key: u64,
    /// The owning thread key.
    pub thread_key: u64,
    /// The frames in this stack (ordered by level: 0 = innermost).
    frames: Vec<TraceStackFrame>,
    /// The lifespan of this stack.
    pub lifespan: Lifespan,
    /// Whether deleted.
    deleted: bool,
}

impl TraceStack {
    /// Create a new stack with a given number of frames.
    pub fn new(key: u64, thread_key: u64, frames: Vec<TraceStackFrame>, lifespan: Lifespan) -> Self {
        Self {
            key,
            thread_key,
            frames,
            lifespan,
            deleted: false,
        }
    }

    /// Create an empty stack.
    pub fn empty(key: u64, thread_key: u64, lifespan: Lifespan) -> Self {
        Self {
            key,
            thread_key,
            frames: Vec::new(),
            lifespan,
            deleted: false,
        }
    }

    /// Returns the unique key.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Returns the number of frames.
    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Get the frame at the given level.
    pub fn get_frame(&self, level: usize) -> Option<&TraceStackFrame> {
        self.frames.get(level)
    }

    /// Get the mutable frame at the given level.
    pub fn get_frame_mut(&mut self, level: usize) -> Option<&mut TraceStackFrame> {
        self.frames.get_mut(level)
    }

    /// Get all frames.
    pub fn frames(&self) -> &[TraceStackFrame] {
        &self.frames
    }

    /// Push a frame onto the stack (innermost).
    pub fn push_frame(&mut self, frame: TraceStackFrame) {
        self.frames.insert(0, frame);
        // Re-level all frames
        for (i, f) in self.frames.iter_mut().enumerate() {
            f.level = i as u32;
        }
    }

    /// Pop the innermost frame from the stack.
    pub fn pop_frame(&mut self) -> Option<TraceStackFrame> {
        if self.frames.is_empty() {
            return None;
        }
        let frame = self.frames.remove(0);
        // Re-level remaining frames
        for (i, f) in self.frames.iter_mut().enumerate() {
            f.level = i as u32;
        }
        Some(frame)
    }

    /// Set the depth of the stack.
    pub fn set_depth(&mut self, depth: usize, at_inner: bool) {
        while self.frames.len() < depth {
            let level = self.frames.len() as u32;
            self.frames.push(TraceStackFrame::new(
                0, self.key, level, None, None, None, self.lifespan,
            ));
        }
        while self.frames.len() > depth {
            if at_inner {
                self.frames.remove(0);
            } else {
                self.frames.pop();
            }
        }
        // Re-level
        for (i, f) in self.frames.iter_mut().enumerate() {
            f.level = i as u32;
        }
    }

    /// Check if valid at the given snapshot.
    pub fn is_valid(&self, snap: i64) -> bool {
        !self.deleted && self.lifespan.contains(snap)
    }

    /// Delete this stack.
    pub fn delete(&mut self) {
        self.deleted = true;
        self.frames.clear();
    }

    /// Remove this stack from the given snap onward.
    pub fn remove(&mut self, snap: i64) {
        self.lifespan = self.lifespan.with_max(snap - 1);
    }
}

impl fmt::Display for TraceStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Stack(thread={}, depth={})", self.thread_key, self.depth())
    }
}

// ---------------------------------------------------------------------------
// TraceStackManager
// ---------------------------------------------------------------------------

/// Manages stacks within a trace.
///
/// Ported from `ghidra.trace.model.stack.TraceStackManager`.
#[derive(Debug)]
pub struct TraceStackManager {
    next_key: AtomicU64,
    stacks: BTreeMap<u64, TraceStack>,
}

impl TraceStackManager {
    /// Create a new empty stack manager.
    pub fn new() -> Self {
        Self {
            next_key: AtomicU64::new(1),
            stacks: BTreeMap::new(),
        }
    }

    fn alloc_key(&self) -> u64 {
        self.next_key.fetch_add(1, Ordering::Relaxed)
    }

    /// Get (or create) the stack for a thread at a given snapshot.
    pub fn get_stack(&mut self, thread_key: u64, snap: i64) -> Option<&mut TraceStack> {
        // Find existing stack for this thread at this snap
        let existing_key = self
            .stacks
            .values()
            .find(|s| s.thread_key == thread_key && s.is_valid(snap))
            .map(|s| s.key);
        if let Some(key) = existing_key {
            return self.stacks.get_mut(&key);
        }
        None
    }

    /// Create a new stack for a thread.
    pub fn create_stack(
        &mut self,
        thread_key: u64,
        snap: i64,
        frame_pcs: &[u64],
    ) -> u64 {
        let key = self.alloc_key();
        let frames: Vec<TraceStackFrame> = frame_pcs
            .iter()
            .enumerate()
            .map(|(i, &pc)| {
                TraceStackFrame::new(
                    self.alloc_key(),
                    key,
                    i as u32,
                    Some(pc),
                    None,
                    None,
                    Lifespan::now_on(snap),
                )
            })
            .collect();
        self.stacks.insert(
            key,
            TraceStack::new(key, thread_key, frames, Lifespan::now_on(snap)),
        );
        key
    }

    /// Get a stack by key.
    pub fn get_stack_by_key(&self, key: u64) -> Option<&TraceStack> {
        self.stacks.get(&key)
    }

    /// Get a mutable stack by key.
    pub fn get_stack_by_key_mut(&mut self, key: u64) -> Option<&mut TraceStack> {
        self.stacks.get_mut(&key)
    }

    /// Find the stack for a thread at a given snap.
    pub fn find_stack(&self, thread_key: u64, snap: i64) -> Option<&TraceStack> {
        self.stacks
            .values()
            .find(|s| s.thread_key == thread_key && s.is_valid(snap))
    }

    /// Iterate over all stacks.
    pub fn stacks(&self) -> impl Iterator<Item = &TraceStack> {
        self.stacks.values()
    }

    /// Remove a stack by key.
    pub fn remove_stack(&mut self, key: u64) -> Option<TraceStack> {
        self.stacks.remove(&key)
    }
}

impl Default for TraceStackManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_frame() {
        let frame = TraceStackFrame::new(1, 10, 0, Some(0x400000), Some(0x7FFF00), None, Lifespan::now_on(0));
        assert_eq!(frame.key(), 1);
        assert_eq!(frame.level, 0);
        assert_eq!(frame.pc, Some(0x400000));
        assert_eq!(frame.sp, Some(0x7FFF00));
        assert!(frame.is_valid(0));
    }

    #[test]
    fn test_stack_basic() {
        let frames = vec![
            TraceStackFrame::new(1, 10, 0, Some(0x400100), Some(0x7FFF00), None, Lifespan::now_on(0)),
            TraceStackFrame::new(2, 10, 1, Some(0x400200), Some(0x7FFE00), None, Lifespan::now_on(0)),
            TraceStackFrame::new(3, 10, 2, Some(0x400300), Some(0x7FFD00), None, Lifespan::now_on(0)),
        ];
        let stack = TraceStack::new(10, 100, frames, Lifespan::now_on(0));

        assert_eq!(stack.key(), 10);
        assert_eq!(stack.thread_key, 100);
        assert_eq!(stack.depth(), 3);
        assert_eq!(stack.get_frame(0).unwrap().pc, Some(0x400100));
        assert_eq!(stack.get_frame(1).unwrap().pc, Some(0x400200));
        assert_eq!(stack.get_frame(2).unwrap().pc, Some(0x400300));
        assert!(stack.get_frame(3).is_none());
    }

    #[test]
    fn test_stack_push_pop() {
        let mut stack = TraceStack::empty(1, 100, Lifespan::now_on(0));
        assert_eq!(stack.depth(), 0);

        stack.push_frame(TraceStackFrame::new(1, 1, 0, Some(0x400100), None, None, Lifespan::now_on(0)));
        stack.push_frame(TraceStackFrame::new(2, 1, 0, Some(0x400200), None, None, Lifespan::now_on(0)));

        assert_eq!(stack.depth(), 2);
        // First frame pushed is now at level 1
        assert_eq!(stack.get_frame(0).unwrap().pc, Some(0x400200));
        assert_eq!(stack.get_frame(1).unwrap().pc, Some(0x400100));

        let popped = stack.pop_frame().unwrap();
        assert_eq!(popped.pc, Some(0x400200));
        assert_eq!(stack.depth(), 1);
    }

    #[test]
    fn test_stack_set_depth() {
        let mut stack = TraceStack::empty(1, 100, Lifespan::now_on(0));
        stack.set_depth(5, false);
        assert_eq!(stack.depth(), 5);

        stack.set_depth(3, false);
        assert_eq!(stack.depth(), 3);

        stack.set_depth(4, true);
        assert_eq!(stack.depth(), 4);
    }

    #[test]
    fn test_stack_manager() {
        let mut mgr = TraceStackManager::new();
        let key = mgr.create_stack(100, 0, &[0x400100, 0x400200, 0x400300]);

        let stack = mgr.get_stack_by_key(key).unwrap();
        assert_eq!(stack.depth(), 3);
        assert_eq!(stack.thread_key, 100);

        let found = mgr.find_stack(100, 0).unwrap();
        assert_eq!(found.key(), key);
    }

    #[test]
    fn test_stack_manager_not_found() {
        let mgr = TraceStackManager::new();
        assert!(mgr.find_stack(999, 0).is_none());
    }

    #[test]
    fn test_stack_manager_remove() {
        let mut mgr = TraceStackManager::new();
        let key = mgr.create_stack(100, 0, &[0x400100]);
        assert_eq!(mgr.stacks().count(), 1);
        mgr.remove_stack(key);
        assert_eq!(mgr.stacks().count(), 0);
    }

    #[test]
    fn test_stack_display() {
        let stack = TraceStack::empty(1, 100, Lifespan::now_on(0));
        assert_eq!(format!("{stack}"), "Stack(thread=100, depth=0)");
    }

    #[test]
    fn test_stack_frame_display() {
        let frame = TraceStackFrame::new(1, 10, 0, Some(0x400000), Some(0x7FFF00), None, Lifespan::now_on(0));
        let s = format!("{frame}");
        assert!(s.contains("level=0"));
        assert!(s.contains("pc=Some(4194304)"));
        assert!(s.contains("sp=Some(8388352)"));
    }
}
