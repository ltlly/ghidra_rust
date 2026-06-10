//! TraceStackFrame -- enhanced stack frame modeling for the debug trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.stack.TraceStackFrame` and
//! `ghidra.trace.database.stack.DBTraceStackFrame`.
//!
//! This module provides a richer stack frame type than the basic
//! `model::stack::TraceStackFrame`, adding per-frame register values,
//! source location metadata, frame classification, and full stack
//! lifecycle management with snapshot-indexed history.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

// ---------------------------------------------------------------------------
// FrameRegisterValue
// ---------------------------------------------------------------------------

/// A register value captured as part of a stack frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameRegisterValue {
    /// Register name (e.g., "RBP", "RIP", "RDI").
    pub name: String,
    /// Raw byte value (little-endian).
    pub value: Vec<u8>,
}

impl FrameRegisterValue {
    /// Create a new register value.
    pub fn new(name: impl Into<String>, value: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }

    /// Create from a u64 (little-endian).
    pub fn from_u64_le(name: impl Into<String>, val: u64) -> Self {
        Self {
            name: name.into(),
            value: val.to_le_bytes().to_vec(),
        }
    }

    /// Interpret the value as a little-endian u64, if <= 8 bytes.
    pub fn as_u64_le(&self) -> Option<u64> {
        if self.value.len() > 8 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf[..self.value.len()].copy_from_slice(&self.value);
        Some(u64::from_le_bytes(buf))
    }
}

// ---------------------------------------------------------------------------
// SourceLocation
// ---------------------------------------------------------------------------

/// Source-level location information for a stack frame.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceLocation {
    /// Source file path.
    pub file: Option<String>,
    /// Line number (1-based).
    pub line: Option<u32>,
    /// Column number (1-based).
    pub column: Option<u32>,
}

impl SourceLocation {
    /// Create an empty source location.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the file.
    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    /// Set the line.
    pub fn with_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    /// Set the column.
    pub fn with_column(mut self, column: u32) -> Self {
        self.column = Some(column);
        self
    }

    /// Whether any source info is available.
    pub fn is_some(&self) -> bool {
        self.file.is_some() || self.line.is_some()
    }
}

// ---------------------------------------------------------------------------
// FrameKind
// ---------------------------------------------------------------------------

/// Classification of a stack frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FrameKind {
    /// A normal user-code frame.
    Normal,
    /// A signal / interrupt trampoline frame.
    Signal,
    /// A synthetic frame inserted by the debugger.
    Synthetic,
    /// A frame for inline function context.
    Inline,
    /// A frame whose origin is unknown.
    Unknown,
}

impl Default for FrameKind {
    fn default() -> Self {
        Self::Normal
    }
}

// ---------------------------------------------------------------------------
// TraceStackFrameEntry
// ---------------------------------------------------------------------------

/// An enhanced stack frame entry for the debug trace.
///
/// Ported from Ghidra's `DBTraceStackFrame`. Extends the basic
/// `model::stack::TraceStackFrame` with per-frame register values,
/// source location, frame kind, and an associated thread key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStackFrameEntry {
    /// The thread key this frame belongs to.
    pub thread_key: i64,
    /// The snap at which this frame was captured.
    pub snap: i64,
    /// The frame level (0 = innermost / current).
    pub level: i32,
    /// The program counter for this frame.
    pub pc: u64,
    /// The stack pointer for this frame.
    pub sp: u64,
    /// The frame pointer, if available.
    pub fp: Option<u64>,
    /// The return address, if available.
    pub return_address: Option<u64>,
    /// The function name, if resolved.
    pub function_name: Option<String>,
    /// The frame classification.
    pub kind: FrameKind,
    /// Source location, if resolved.
    pub source: SourceLocation,
    /// Per-frame register values (callee-saved, arguments, etc.).
    registers: BTreeMap<String, FrameRegisterValue>,
}

impl TraceStackFrameEntry {
    /// Create a new stack frame.
    pub fn new(thread_key: i64, snap: i64, level: i32, pc: u64, sp: u64) -> Self {
        Self {
            thread_key,
            snap,
            level,
            pc,
            sp,
            fp: None,
            return_address: None,
            function_name: None,
            kind: FrameKind::Normal,
            source: SourceLocation::new(),
            registers: BTreeMap::new(),
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
    pub fn with_function(mut self, name: impl Into<String>) -> Self {
        self.function_name = Some(name.into());
        self
    }

    /// Set the frame kind.
    pub fn with_kind(mut self, kind: FrameKind) -> Self {
        self.kind = kind;
        self
    }

    /// Set the source location.
    pub fn with_source(mut self, source: SourceLocation) -> Self {
        self.source = source;
        self
    }

    /// Whether this is the innermost frame (level 0).
    pub fn is_innermost(&self) -> bool {
        self.level == 0
    }

    /// Set a register value for this frame.
    pub fn set_register(&mut self, reg: FrameRegisterValue) {
        self.registers.insert(reg.name.clone(), reg);
    }

    /// Get a register value by name.
    pub fn register(&self, name: &str) -> Option<&FrameRegisterValue> {
        self.registers.get(name)
    }

    /// Get a register as u64 (little-endian).
    pub fn register_u64_le(&self, name: &str) -> Option<u64> {
        self.registers.get(name).and_then(|r| r.as_u64_le())
    }

    /// All register names in this frame.
    pub fn register_names(&self) -> Vec<&str> {
        self.registers.keys().map(|s| s.as_str()).collect()
    }

    /// The number of registers in this frame.
    pub fn register_count(&self) -> usize {
        self.registers.len()
    }

    /// All register values.
    pub fn registers(&self) -> &BTreeMap<String, FrameRegisterValue> {
        &self.registers
    }
}

// ---------------------------------------------------------------------------
// TraceStackEntry
// ---------------------------------------------------------------------------

/// A complete stack snapshot for a thread at a given snap.
///
/// Ported from Ghidra's `DBTraceStack`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStackEntry {
    /// The thread key.
    pub thread_key: i64,
    /// The snap at which this stack was captured.
    pub snap: i64,
    /// The lifespan during which this stack configuration is valid.
    pub lifespan: Lifespan,
    /// Frames ordered by level (0 = innermost).
    frames: Vec<TraceStackFrameEntry>,
}

impl TraceStackEntry {
    /// Create a new stack snapshot.
    pub fn new(thread_key: i64, snap: i64, lifespan: Lifespan) -> Self {
        Self {
            thread_key,
            snap,
            lifespan,
            frames: Vec::new(),
        }
    }

    /// Add a frame.
    pub fn push_frame(&mut self, frame: TraceStackFrameEntry) {
        self.frames.push(frame);
    }

    /// The number of frames (stack depth).
    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Whether this stack has any frames.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Get a frame by level.
    pub fn frame(&self, level: i32) -> Option<&TraceStackFrameEntry> {
        self.frames.iter().find(|f| f.level == level)
    }

    /// Get the innermost frame (level 0).
    pub fn innermost(&self) -> Option<&TraceStackFrameEntry> {
        self.frame(0)
    }

    /// Get the outermost frame (highest level).
    pub fn outermost(&self) -> Option<&TraceStackFrameEntry> {
        self.frames.iter().max_by_key(|f| f.level)
    }

    /// Get the current PC from the innermost frame.
    pub fn pc(&self) -> Option<u64> {
        self.innermost().map(|f| f.pc)
    }

    /// Get the current SP from the innermost frame.
    pub fn sp(&self) -> Option<u64> {
        self.innermost().map(|f| f.sp)
    }

    /// All frames.
    pub fn frames(&self) -> &[TraceStackFrameEntry] {
        &self.frames
    }

    /// Whether this stack is valid at the given snap.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }
}

// ---------------------------------------------------------------------------
// TraceStackFrameManager
// ---------------------------------------------------------------------------

/// Manages stack snapshots for all threads in a trace.
///
/// Ported from Ghidra's `DBTraceStackManager`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceStackFrameManager {
    /// Stack snapshots keyed by thread_key, each a list of snapshots.
    stacks: BTreeMap<i64, Vec<TraceStackEntry>>,
}

impl TraceStackFrameManager {
    /// Create a new manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set (add or replace) a stack snapshot.
    pub fn set_stack(&mut self, stack: TraceStackEntry) {
        let thread_key = stack.thread_key;
        self.stacks.entry(thread_key).or_default().push(stack);
    }

    /// Get the active stack for a thread at the given snap.
    pub fn get_stack(&self, thread_key: i64, snap: i64) -> Option<&TraceStackEntry> {
        self.stacks.get(&thread_key).and_then(|stacks| {
            stacks
                .iter()
                .filter(|s| s.is_valid_at(snap))
                .max_by_key(|s| s.lifespan.lmin())
        })
    }

    /// Get all stacks for a thread.
    pub fn stacks_for_thread(&self, thread_key: i64) -> Option<&Vec<TraceStackEntry>> {
        self.stacks.get(&thread_key)
    }

    /// Clear all stacks for a thread.
    pub fn clear_thread(&mut self, thread_key: i64) {
        self.stacks.remove(&thread_key);
    }

    /// Get the current PC for a thread at the given snap.
    pub fn get_pc(&self, thread_key: i64, snap: i64) -> Option<u64> {
        self.get_stack(thread_key, snap)
            .and_then(|s| s.pc())
    }

    /// Get the current SP for a thread at the given snap.
    pub fn get_sp(&self, thread_key: i64, snap: i64) -> Option<u64> {
        self.get_stack(thread_key, snap)
            .and_then(|s| s.sp())
    }

    /// Get the stack depth for a thread at the given snap.
    pub fn get_depth(&self, thread_key: i64, snap: i64) -> Option<usize> {
        self.get_stack(thread_key, snap).map(|s| s.depth())
    }

    /// The number of threads with stack data.
    pub fn thread_count(&self) -> usize {
        self.stacks.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_register_value() {
        let r = FrameRegisterValue::from_u64_le("RIP", 0x401000);
        assert_eq!(r.name, "RIP");
        assert_eq!(r.as_u64_le(), Some(0x401000));
    }

    #[test]
    fn test_frame_register_value_too_large() {
        let r = FrameRegisterValue::new("WIDE", vec![0; 9]);
        assert_eq!(r.as_u64_le(), None);
    }

    #[test]
    fn test_source_location() {
        let s = SourceLocation::new()
            .with_file("main.c")
            .with_line(42)
            .with_column(10);
        assert!(s.is_some());
        assert_eq!(s.file.as_deref(), Some("main.c"));
        assert_eq!(s.line, Some(42));
        assert_eq!(s.column, Some(10));

        let empty = SourceLocation::new();
        assert!(!empty.is_some());
    }

    #[test]
    fn test_frame_kind_default() {
        assert_eq!(FrameKind::default(), FrameKind::Normal);
    }

    #[test]
    fn test_stack_frame_creation() {
        let f = TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000);
        assert_eq!(f.thread_key, 1);
        assert_eq!(f.snap, 0);
        assert_eq!(f.level, 0);
        assert_eq!(f.pc, 0x401000);
        assert_eq!(f.sp, 0x7FFF0000);
        assert!(f.is_innermost());
        assert_eq!(f.kind, FrameKind::Normal);
    }

    #[test]
    fn test_stack_frame_builder() {
        let f = TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000)
            .with_fp(0x7FFF0010)
            .with_return_address(0x402000)
            .with_function("main")
            .with_kind(FrameKind::Normal)
            .with_source(
                SourceLocation::new()
                    .with_file("main.c")
                    .with_line(10),
            );

        assert_eq!(f.fp, Some(0x7FFF0010));
        assert_eq!(f.return_address, Some(0x402000));
        assert_eq!(f.function_name.as_deref(), Some("main"));
        assert!(f.source.is_some());
    }

    #[test]
    fn test_stack_frame_registers() {
        let mut f = TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000);
        f.set_register(FrameRegisterValue::from_u64_le("RBP", 0x7FFF0010));
        f.set_register(FrameRegisterValue::from_u64_le("RDI", 0x42));

        assert_eq!(f.register_count(), 2);
        assert_eq!(f.register_u64_le("RBP"), Some(0x7FFF0010));
        assert_eq!(f.register_u64_le("RDI"), Some(0x42));
        assert!(f.register_u64_le("RAX").is_none());

        let names = f.register_names();
        assert!(names.contains(&"RBP"));
        assert!(names.contains(&"RDI"));
    }

    #[test]
    fn test_stack_entry_basics() {
        let stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        assert_eq!(stack.thread_key, 1);
        assert_eq!(stack.depth(), 0);
        assert!(stack.is_empty());
        assert!(stack.is_valid_at(0));
        assert!(!stack.is_valid_at(1));
    }

    #[test]
    fn test_stack_entry_frames() {
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 1, 0x402000, 0x7FFF0020));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 2, 0x403000, 0x7FFF0040));

        assert_eq!(stack.depth(), 3);
        assert!(!stack.is_empty());
        assert_eq!(stack.innermost().unwrap().pc, 0x401000);
        assert_eq!(stack.outermost().unwrap().pc, 0x403000);
        assert_eq!(stack.pc(), Some(0x401000));
        assert_eq!(stack.sp(), Some(0x7FFF0000));
        assert!(stack.frame(1).is_some());
        assert!(stack.frame(5).is_none());
    }

    #[test]
    fn test_stack_manager_basic() {
        let mut mgr = TraceStackFrameManager::new();
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x400000, 0x7FFF0000));
        mgr.set_stack(stack);

        assert_eq!(mgr.get_pc(1, 0), Some(0x400000));
        assert_eq!(mgr.get_sp(1, 0), Some(0x7FFF0000));
        assert_eq!(mgr.get_depth(1, 0), Some(1));
        assert!(mgr.get_stack(1, 0).is_some());
        assert!(mgr.get_stack(2, 0).is_none());
        assert!(mgr.get_pc(1, 1).is_none());
    }

    #[test]
    fn test_stack_manager_clear() {
        let mut mgr = TraceStackFrameManager::new();
        let stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        mgr.set_stack(stack);
        assert_eq!(mgr.thread_count(), 1);
        mgr.clear_thread(1);
        assert_eq!(mgr.thread_count(), 0);
        assert!(mgr.get_stack(1, 0).is_none());
    }

    #[test]
    fn test_stack_frame_signal_kind() {
        let f = TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000)
            .with_kind(FrameKind::Signal);
        assert_eq!(f.kind, FrameKind::Signal);
    }

    #[test]
    fn test_stack_frame_serde() {
        let mut f = TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000)
            .with_function("main");
        f.set_register(FrameRegisterValue::from_u64_le("RBP", 0x7FFF0010));

        let json = serde_json::to_string(&f).unwrap();
        let back: TraceStackFrameEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pc, 0x401000);
        assert_eq!(back.function_name.as_deref(), Some("main"));
        assert_eq!(back.register_u64_le("RBP"), Some(0x7FFF0010));
    }

    #[test]
    fn test_stack_entry_serde() {
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x400000, 0x7FFF0000));

        let json = serde_json::to_string(&stack).unwrap();
        let back: TraceStackEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.thread_key, 1);
        assert_eq!(back.depth(), 1);
    }

    #[test]
    fn test_stack_manager_serde() {
        let mut mgr = TraceStackFrameManager::new();
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x400000, 0x7FFF0000));
        mgr.set_stack(stack);

        let json = serde_json::to_string(&mgr).unwrap();
        let back: TraceStackFrameManager = serde_json::from_str(&json).unwrap();
        assert_eq!(back.get_pc(1, 0), Some(0x400000));
    }

    #[test]
    fn test_frame_kind_variants() {
        let kinds = [
            FrameKind::Normal,
            FrameKind::Signal,
            FrameKind::Synthetic,
            FrameKind::Inline,
            FrameKind::Unknown,
        ];
        for kind in &kinds {
            let f = TraceStackFrameEntry::new(1, 0, 0, 0, 0).with_kind(*kind);
            assert_eq!(f.kind, *kind);
        }
    }
}
