//! DBTraceStack - database-backed stack implementation.
//!
//! Ported from `ghidra.trace.database.stack.DBTraceStack`. Provides call
//! stack management backed by a trace object. Supports depth management,
//! frame retrieval, and frame attribute copying when the call stack changes.
//!
//! The Java original implements `TraceStack` and `DBTraceObjectInterface`.
//! Since the Rust codebase uses concrete structs rather than interfaces,
//! this module provides a DB-level stack that wraps the existing
//! `TraceStack` and `TraceStackFrame` types with additional database
//! operations.

use crate::model::stack::{TraceStack, TraceStackFrame};
use std::fmt;

/// Database-backed implementation of a trace stack.
///
/// Extends the basic `TraceStack` with object-tree-backed storage operations.
/// In the Java original, this wraps a `DBTraceObject` and translates change
/// events. In Rust, this provides the additional methods that the DB layer
/// needs: frame copying, shifting, and clearing during depth changes.
#[derive(Debug, Clone)]
pub struct DBTraceStack {
    /// The backing trace object ID for this stack.
    pub object_id: u64,
    /// The key path of this stack within the target object tree.
    pub path: Vec<String>,
    /// The underlying stack data.
    pub stack: TraceStack,
}

impl DBTraceStack {
    /// Create a new stack backed by the given object ID and path.
    pub fn new(object_id: u64, path: Vec<String>, stack: TraceStack) -> Self {
        Self {
            object_id,
            path,
            stack,
        }
    }

    /// Copy frame attributes (currently just program counter) from one frame
    /// to another at the given snapshot.
    pub fn copy_frame_attributes(from: &TraceStackFrame, to: &mut TraceStackFrame) {
        to.pc = from.pc;
    }

    /// Shift frame attributes between positions when the stack depth changes.
    ///
    /// When `from < to`, copies in reverse order to avoid overwriting.
    /// When `from > to`, copies in forward order.
    pub fn shift_frame_attributes(
        from_idx: usize,
        to_idx: usize,
        count: usize,
        frames: &mut [TraceStackFrame],
    ) {
        if from_idx == to_idx {
            return;
        }
        if from_idx < to_idx {
            for i in (0..count).rev() {
                let src_pc = frames[from_idx + i].pc;
                frames[to_idx + i].pc = src_pc;
            }
        } else {
            for i in 0..count {
                let src_pc = frames[from_idx + i].pc;
                frames[to_idx + i].pc = src_pc;
            }
        }
    }

    /// Clear frame attributes (set program counter to 0) for a range.
    pub fn clear_frame_attributes(start: usize, end: usize, frames: &mut [TraceStackFrame]) {
        for i in start..end.min(frames.len()) {
            frames[i].pc = 0;
        }
    }

    /// Get the depth of the stack at a given snap.
    pub fn get_depth(&self) -> usize {
        self.stack.depth()
    }

    /// Get a frame by level.
    pub fn get_frame(&self, level: i32) -> Option<&TraceStackFrame> {
        self.stack.frame(level)
    }

    /// Get all frames.
    pub fn get_frames(&self) -> &[TraceStackFrame] {
        &self.stack.frames
    }

    /// Set the depth, adding or removing frames as needed.
    pub fn set_depth(&mut self, new_depth: usize, at_inner: bool) {
        let current = self.stack.frames.len();
        if new_depth == current {
            return;
        }
        if new_depth < current {
            if at_inner {
                let diff = current - new_depth;
                Self::shift_frame_attributes(diff, 0, new_depth, &mut self.stack.frames);
            }
            self.stack.frames.truncate(new_depth);
        } else {
            while self.stack.frames.len() < new_depth {
                let level = self.stack.frames.len() as i32;
                self.stack.frames.push(TraceStackFrame::new(level, 0, 0));
            }
            if at_inner {
                let diff = new_depth - current;
                Self::shift_frame_attributes(0, diff, current, &mut self.stack.frames);
                Self::clear_frame_attributes(0, diff, &mut self.stack.frames);
            }
        }
    }

    /// Whether this stack is valid at the given snap.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        self.stack.is_valid_at(snap)
    }

    /// Whether this stack has fixed (non-dynamic) frames.
    pub fn has_fixed_frames(&self) -> bool {
        false
    }
}

impl fmt::Display for DBTraceStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DBTraceStack(object={}, thread={}, depth={})",
            self.object_id,
            self.stack.thread_key,
            self.stack.depth()
        )
    }
}

/// Helper to split a mutable slice at two indices, returning references to both.
/// Returns `(None, None)` if indices are equal or out of bounds.
pub fn split_at_mut_pair<'a, T>(
    slice: &'a mut [T],
    i: usize,
    j: usize,
) -> (Option<&'a mut T>, Option<&'a mut T>) {
    if i == j || i >= slice.len() || j >= slice.len() {
        return (None, None);
    }
    let (min, max) = if i < j { (i, j) } else { (j, i) };
    let (left, right) = slice.split_at_mut(max);
    if i < j {
        (left.get_mut(min), right.first_mut())
    } else {
        (right.first_mut(), left.get_mut(min))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Lifespan;

    fn make_stack(depth: usize) -> DBTraceStack {
        let mut stack = TraceStack::new(1, Lifespan::at_least(0));
        for i in 0..depth {
            stack.push_frame(TraceStackFrame::new(i as i32, 0x400000 + i as u64 * 0x10, 0x7fff0000));
        }
        DBTraceStack::new(42, vec!["Thread0".into(), "Stack".into()], stack)
    }

    #[test]
    fn test_db_trace_stack_new() {
        let stack = make_stack(3);
        assert_eq!(stack.object_id, 42);
        assert_eq!(stack.path.len(), 2);
        assert!(stack.has_fixed_frames() == false);
        assert!(stack.is_valid_at(0));
        assert_eq!(stack.get_depth(), 3);
    }

    #[test]
    fn test_db_trace_stack_empty() {
        let stack = make_stack(0);
        assert_eq!(stack.get_depth(), 0);
        assert!(stack.get_frames().is_empty());
        assert!(stack.get_frame(0).is_none());
    }

    #[test]
    fn test_copy_frame_attributes() {
        let from = TraceStackFrame::new(0, 0x400000, 0x7fff0000);
        let mut to = TraceStackFrame::new(1, 0, 0);

        DBTraceStack::copy_frame_attributes(&from, &mut to);
        assert_eq!(to.pc, 0x400000);
    }

    #[test]
    fn test_clear_frame_attributes() {
        let mut frames = vec![
            TraceStackFrame::new(0, 0x100, 0),
            TraceStackFrame::new(1, 0x200, 0),
            TraceStackFrame::new(2, 0x300, 0),
        ];
        DBTraceStack::clear_frame_attributes(1, 3, &mut frames);

        assert_eq!(frames[0].pc, 0x100);
        assert_eq!(frames[1].pc, 0);
        assert_eq!(frames[2].pc, 0);
    }

    #[test]
    fn test_shift_frame_attributes_forward() {
        let mut frames = vec![
            TraceStackFrame::new(0, 0x100, 0),
            TraceStackFrame::new(1, 0x200, 0),
            TraceStackFrame::new(2, 0x300, 0),
        ];
        // Shift frame 0 to position 1
        DBTraceStack::shift_frame_attributes(0, 1, 1, &mut frames);
        assert_eq!(frames[1].pc, 0x100);
    }

    #[test]
    fn test_set_depth_grow() {
        let mut stack = make_stack(2);
        stack.set_depth(4, false);
        assert_eq!(stack.get_depth(), 4);
        assert_eq!(stack.get_frame(3).unwrap().level, 3);
    }

    #[test]
    fn test_set_depth_shrink() {
        let mut stack = make_stack(4);
        stack.set_depth(2, false);
        assert_eq!(stack.get_depth(), 2);
    }

    #[test]
    fn test_set_depth_no_change() {
        let mut stack = make_stack(3);
        stack.set_depth(3, false);
        assert_eq!(stack.get_depth(), 3);
    }

    #[test]
    fn test_split_at_mut_pair_basic() {
        let mut data = vec![10, 20, 30, 40];
        let (a, b) = split_at_mut_pair(&mut data, 1, 3);
        assert_eq!(*a.unwrap(), 20);
        assert_eq!(*b.unwrap(), 40);
    }

    #[test]
    fn test_split_at_mut_pair_same_index() {
        let mut data = vec![10, 20];
        let (a, b) = split_at_mut_pair(&mut data, 0, 0);
        assert!(a.is_none());
        assert!(b.is_none());
    }

    #[test]
    fn test_display() {
        let stack = make_stack(3);
        let s = format!("{stack}");
        assert!(s.contains("42"));
        assert!(s.contains("depth=3"));
    }
}
