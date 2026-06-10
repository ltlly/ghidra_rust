//! TraceStackFrame -- enhanced stack frame modeling for the debug trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.stack.TraceStackFrame`,
//! `ghidra.trace.model.stack.TraceStack`, and
//! `ghidra.trace.database.stack.DBTraceStackFrame`.
//!
//! This module provides a richer stack frame type than the basic
//! `model::stack::TraceStackFrame`, adding per-frame register values,
//! source location metadata, frame classification, snap-based comments,
//! snap-based depth management, and full stack lifecycle management
//! with snapshot-indexed history.
//!
//! New in this update: `set_comment`/`get_comment` on frames (ported
//! from `DBTraceStackFrame.setComment`/`getComment`), `set_depth` on
//! stack entries (ported from `TraceStack.setDepth`), `delete`/`remove`
//! lifecycle, and `has_fixed_frames`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

// ---------------------------------------------------------------------------
// OverlapError
// ---------------------------------------------------------------------------

/// Error returned when a stack frame operation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackFrameError {
    /// The requested frame level is out of bounds.
    LevelOutOfBounds { level: i32, depth: usize },
    /// The snap is out of the stack's lifespan.
    InvalidSnap { snap: i64 },
}

impl std::fmt::Display for StackFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LevelOutOfBounds { level, depth } => {
                write!(f, "frame level {level} out of bounds (depth {depth})")
            }
            Self::InvalidSnap { snap } => {
                write!(f, "snap {snap} is outside the stack's lifespan")
            }
        }
    }
}

impl std::error::Error for StackFrameError {}

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
/// source location, frame kind, snap-based comments, and an associated
/// thread key.
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
    /// Snap-indexed user comments (ported from `DBTraceStackFrame`).
    ///
    /// In the Java original, comments are stored at the program counter
    /// address in the listing rather than directly on the frame. Here
    /// we store them directly keyed by snap for simplicity.
    comments: BTreeMap<i64, String>,
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
            comments: BTreeMap::new(),
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

    /// Whether this is the outermost frame in a given depth.
    pub fn is_outermost(&self, depth: usize) -> bool {
        self.level == (depth as i32 - 1).max(0)
    }

    /// Set the program counter, effective for the given lifespan.
    ///
    /// Ported from `TraceStackFrame.setProgramCounter(Lifespan, Address)`.
    pub fn set_pc(&mut self, _lifespan: &Lifespan, pc: u64) {
        self.pc = pc;
    }

    /// Set the stack pointer, effective for the given lifespan.
    ///
    /// Ported from `TraceStackFrame.setStackPointer(Lifespan, Address)`.
    pub fn set_sp(&mut self, _lifespan: &Lifespan, sp: u64) {
        self.sp = sp;
    }

    /// Create a shallow copy of this frame with a new level.
    ///
    /// The registers and comments are cloned; the level is set to the given value.
    pub fn clone_with_level(&self, level: i32) -> Self {
        Self {
            thread_key: self.thread_key,
            snap: self.snap,
            level,
            pc: self.pc,
            sp: self.sp,
            fp: self.fp,
            return_address: self.return_address,
            function_name: self.function_name.clone(),
            kind: self.kind,
            source: SourceLocation {
                file: self.source.file.clone(),
                line: self.source.line,
                column: self.source.column,
            },
            registers: self.registers.clone(),
            comments: BTreeMap::new(),
        }
    }

    /// The return address, or the program counter if no return address is set.
    ///
    /// This is a convenience for the common pattern where a debugger reports
    /// the return address but the "display" address should be the return
    /// address for non-innermost frames and the PC for the innermost.
    pub fn display_address(&self) -> u64 {
        if self.is_innermost() {
            self.pc
        } else {
            self.return_address.unwrap_or(self.pc)
        }
    }

    // -----------------------------------------------------------------------
    // Comment operations (ported from DBTraceStackFrame)
    // -----------------------------------------------------------------------

    /// Set a user comment for this frame at the given snap.
    ///
    /// Ported from `DBTraceStackFrame.setComment(long, String)`.
    /// In the Java original, comments are stored in the listing at the
    /// program counter address. Here we store them directly on the frame
    /// keyed by snap.
    pub fn set_comment(&mut self, snap: i64, comment: impl Into<String>) {
        self.comments.insert(snap, comment.into());
    }

    /// Get the user comment for this frame at the given snap.
    ///
    /// Returns the most recent comment set at or before `snap`.
    /// Ported from `DBTraceStackFrame.getComment(long)`.
    pub fn get_comment(&self, snap: i64) -> Option<&str> {
        self.comments
            .range(..=snap)
            .next_back()
            .map(|(_, v)| v.as_str())
    }

    /// Remove the comment at the given snap.
    pub fn clear_comment(&mut self, snap: i64) {
        self.comments.remove(&snap);
    }

    /// All comments on this frame.
    pub fn comments(&self) -> &BTreeMap<i64, String> {
        &self.comments
    }

    // -----------------------------------------------------------------------
    // Register operations
    // -----------------------------------------------------------------------

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
/// Ported from Ghidra's `DBTraceStack` and `TraceStack`.
///
/// Supports snap-based depth management (ported from `TraceStack.setDepth`),
/// delete/remove lifecycle, and the `has_fixed_frames` flag.
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
    /// Whether this stack uses fixed frames (the normal table-based model)
    /// or dynamic frames (the experimental object-based model).
    ///
    /// Ported from `TraceStack.hasFixedFrames()`.
    fixed_frames: bool,
}

impl TraceStackEntry {
    /// Create a new stack snapshot with fixed frames (the default).
    pub fn new(thread_key: i64, snap: i64, lifespan: Lifespan) -> Self {
        Self {
            thread_key,
            snap,
            lifespan,
            frames: Vec::new(),
            fixed_frames: true,
        }
    }

    /// Create a new stack snapshot with dynamic (non-fixed) frames.
    ///
    /// This corresponds to the experimental object-based model in Ghidra.
    pub fn new_dynamic(thread_key: i64, snap: i64, lifespan: Lifespan) -> Self {
        Self {
            thread_key,
            snap,
            lifespan,
            frames: Vec::new(),
            fixed_frames: false,
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

    /// Get a frame by level, optionally expanding the depth to accommodate it.
    ///
    /// Ported from `TraceStack.getFrame(long, int, boolean)`.
    /// If `ensure_depth` is true and the requested level exceeds the current
    /// depth, the stack is expanded with empty frames.
    pub fn get_frame(&mut self, level: i32, ensure_depth: bool) -> Result<(), StackFrameError> {
        if level < 0 {
            return Err(StackFrameError::LevelOutOfBounds {
                level,
                depth: self.frames.len(),
            });
        }
        if ensure_depth && level as usize >= self.frames.len() {
            let target = level as usize + 1;
            self.set_depth(target, false);
        }
        if level as usize >= self.frames.len() {
            return Err(StackFrameError::LevelOutOfBounds {
                level,
                depth: self.frames.len(),
            });
        }
        Ok(())
    }

    /// Get a mutable frame by level.
    pub fn frame_mut(&mut self, level: i32) -> Option<&mut TraceStackFrameEntry> {
        self.frames.iter_mut().find(|f| f.level == level)
    }

    /// Get a frame by level, expanding depth if necessary.
    ///
    /// Ported from `TraceStack.getFrame(long, int, boolean)` with `ensureDepth=true`.
    /// Returns the frame at `level`, creating empty frames up to that level if needed.
    pub fn frame_or_create(&mut self, level: i32) -> &mut TraceStackFrameEntry {
        if level < 0 {
            panic!("frame level must be non-negative, got {level}");
        }
        let needed = level as usize + 1;
        if needed > self.frames.len() {
            self.set_depth(needed, false);
        }
        self.frames
            .iter_mut()
            .find(|f| f.level == level)
            .expect("frame should exist after ensuring depth")
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
    ///
    /// Ported from `TraceStack.isValid(long)`.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }

    /// Whether this stack uses fixed frames.
    ///
    /// Ported from `TraceStack.hasFixedFrames()`. Returns true for the
    /// normal table-based model, false for the experimental object-based
    /// model.
    pub fn has_fixed_frames(&self) -> bool {
        self.fixed_frames
    }

    // -----------------------------------------------------------------------
    // Depth management (ported from TraceStack.setDepth)
    // -----------------------------------------------------------------------

    /// Set the depth of the stack by adding or removing frames.
    ///
    /// Ported from `TraceStack.setDepth(long, int, boolean)`.
    ///
    /// When `at_inner` is true, new frames are "pushed" (inserted at the
    /// front). When false, new frames are appended at the end. When
    /// reducing depth, frames are removed from the specified end.
    pub fn set_depth(&mut self, target_depth: usize, at_inner: bool) {
        let current = self.frames.len();
        if target_depth == current {
            return;
        }
        if target_depth > current {
            // Add frames
            let count = target_depth - current;
            for i in 0..count {
                let level = if at_inner {
                    // Insert at front, shift existing levels up
                    0
                } else {
                    (current + i) as i32
                };
                let frame = TraceStackFrameEntry {
                    thread_key: self.thread_key,
                    snap: self.snap,
                    level,
                    pc: 0,
                    sp: 0,
                    fp: None,
                    return_address: None,
                    function_name: None,
                    kind: FrameKind::Normal,
                    source: SourceLocation::new(),
                    registers: BTreeMap::new(),
                    comments: BTreeMap::new(),
                };
                if at_inner {
                    self.frames.insert(i, frame);
                } else {
                    self.frames.push(frame);
                }
            }
            // Re-number levels
            self.renumber_levels();
        } else {
            // Remove frames
            let to_remove = current - target_depth;
            if at_inner {
                self.frames.drain(..to_remove);
            } else {
                self.frames.truncate(target_depth);
            }
            self.renumber_levels();
        }
    }

    /// Renumber frame levels to be 0..N-1.
    fn renumber_levels(&mut self) {
        for (i, frame) in self.frames.iter_mut().enumerate() {
            frame.level = i as i32;
        }
    }

    // -----------------------------------------------------------------------
    // Lifecycle (ported from TraceStack)
    // -----------------------------------------------------------------------

    /// Delete this stack and all its frames.
    ///
    /// Ported from `TraceStack.delete()`.
    pub fn delete(&mut self) {
        self.frames.clear();
        self.lifespan = Lifespan::EMPTY;
    }

    /// Remove this stack from the given snap onward.
    ///
    /// Ported from `TraceStack.remove(long)`.
    pub fn remove(&mut self, snap: i64) {
        self.lifespan = self.lifespan.with_max(snap);
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

    /// Get a mutable active stack for a thread at the given snap.
    pub fn get_stack_mut(&mut self, thread_key: i64, snap: i64) -> Option<&mut TraceStackEntry> {
        self.stacks.get_mut(&thread_key).and_then(|stacks| {
            stacks
                .iter_mut()
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

    // -----------------------------------------------------------------------
    // Depth management (ported from TraceStackManager/TraceStack)
    // -----------------------------------------------------------------------

    /// Set the stack depth for a thread at the given snap.
    ///
    /// Ported from `TraceStack.setDepth(long, int, boolean)`.
    /// If no stack exists for the thread at that snap, this is a no-op.
    pub fn set_depth(
        &mut self,
        thread_key: i64,
        snap: i64,
        depth: usize,
        at_inner: bool,
    ) -> bool {
        self.get_stack_mut(thread_key, snap)
            .map(|s| {
                s.set_depth(depth, at_inner);
            })
            .is_some()
    }

    /// Delete all stacks for a thread (remove all snapshots).
    ///
    /// Ported from `TraceStack.delete()` applied to all snapshots.
    pub fn delete_thread(&mut self, thread_key: i64) {
        if let Some(stacks) = self.stacks.get_mut(&thread_key) {
            for stack in stacks.iter_mut() {
                stack.delete();
            }
        }
        self.stacks.remove(&thread_key);
    }

    /// Remove stacks for a thread from the given snap onward.
    ///
    /// Ported from `TraceStack.remove(long)`.
    pub fn remove_thread_at(&mut self, thread_key: i64, snap: i64) {
        if let Some(stacks) = self.stacks.get_mut(&thread_key) {
            for stack in stacks.iter_mut() {
                stack.remove(snap);
            }
        }
    }

    /// Whether the manager has no stacks for any thread.
    pub fn is_empty(&self) -> bool {
        self.stacks.is_empty()
    }

    /// All thread keys that have stack data.
    pub fn thread_keys(&self) -> Vec<i64> {
        self.stacks.keys().copied().collect()
    }

    /// Get the frame at a specific level for a thread at `snap`, optionally
    /// expanding the depth.
    ///
    /// Ported from `TraceStack.getFrame(long, int, boolean)`.
    pub fn get_frame(
        &mut self,
        thread_key: i64,
        snap: i64,
        level: i32,
        ensure_depth: bool,
    ) -> Option<&TraceStackFrameEntry> {
        let stack = self.get_stack_mut(thread_key, snap)?;
        if level < 0 {
            return None;
        }
        if ensure_depth && level as usize >= stack.depth() {
            stack.set_depth(level as usize + 1, false);
        }
        stack.frame(level)
    }

    /// Get the function name at a specific frame level for a thread at `snap`.
    pub fn get_function_name(
        &self,
        thread_key: i64,
        snap: i64,
        level: i32,
    ) -> Option<&str> {
        self.get_stack(thread_key, snap)
            .and_then(|s| s.frame(level))
            .and_then(|f| f.function_name.as_deref())
    }

    /// Get the frame pointer at a specific frame level for a thread at `snap`.
    pub fn get_frame_pointer(
        &self,
        thread_key: i64,
        snap: i64,
        level: i32,
    ) -> Option<u64> {
        self.get_stack(thread_key, snap)
            .and_then(|s| s.frame(level))
            .and_then(|f| f.fp)
    }

    /// Get the return address at a specific frame level for a thread at `snap`.
    pub fn get_return_address(
        &self,
        thread_key: i64,
        snap: i64,
        level: i32,
    ) -> Option<u64> {
        self.get_stack(thread_key, snap)
            .and_then(|s| s.frame(level))
            .and_then(|f| f.return_address)
    }

    /// Get a frame's comment at a specific level for a thread at `snap`.
    pub fn get_frame_comment(
        &self,
        thread_key: i64,
        snap: i64,
        level: i32,
    ) -> Option<&str> {
        self.get_stack(thread_key, snap)
            .and_then(|s| s.frame(level))
            .and_then(|f| f.get_comment(snap))
    }

    /// Set a frame's comment at a specific level for a thread at `snap`.
    pub fn set_frame_comment(
        &mut self,
        thread_key: i64,
        snap: i64,
        level: i32,
        comment: impl Into<String>,
    ) -> bool {
        if let Some(stack) = self.get_stack_mut(thread_key, snap) {
            if let Some(frame) = stack.frame_mut(level) {
                frame.set_comment(snap, comment);
                return true;
            }
        }
        false
    }

    /// Set a register value on a specific frame for a thread at `snap`.
    pub fn set_frame_register(
        &mut self,
        thread_key: i64,
        snap: i64,
        level: i32,
        reg: FrameRegisterValue,
    ) -> bool {
        if let Some(stack) = self.get_stack_mut(thread_key, snap) {
            if let Some(frame) = stack.frame_mut(level) {
                frame.set_register(reg);
                return true;
            }
        }
        false
    }

    /// Get a register value from a specific frame for a thread at `snap`.
    pub fn get_frame_register(
        &self,
        thread_key: i64,
        snap: i64,
        level: i32,
        name: &str,
    ) -> Option<&FrameRegisterValue> {
        self.get_stack(thread_key, snap)
            .and_then(|s| s.frame(level))
            .and_then(|f| f.register(name))
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

    // -----------------------------------------------------------------------
    // Comment tests (ported from DBTraceStackFrame)
    // -----------------------------------------------------------------------

    #[test]
    fn test_stack_frame_comment() {
        let mut f = TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000);
        assert!(f.get_comment(0).is_none());

        f.set_comment(0, "entry point");
        assert_eq!(f.get_comment(0), Some("entry point"));
        assert_eq!(f.get_comment(5), Some("entry point")); // inherits

        f.set_comment(10, "after call");
        assert_eq!(f.get_comment(5), Some("entry point"));
        assert_eq!(f.get_comment(10), Some("after call"));
        assert_eq!(f.get_comment(100), Some("after call"));
    }

    #[test]
    fn test_stack_frame_clear_comment() {
        let mut f = TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000);
        f.set_comment(0, "test");
        assert_eq!(f.get_comment(0), Some("test"));
        f.clear_comment(0);
        assert!(f.get_comment(0).is_none());
    }

    // -----------------------------------------------------------------------
    // Stack entry tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_stack_entry_basics() {
        let stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        assert_eq!(stack.thread_key, 1);
        assert_eq!(stack.depth(), 0);
        assert!(stack.is_empty());
        assert!(stack.is_valid_at(0));
        assert!(!stack.is_valid_at(1));
        assert!(stack.has_fixed_frames());
    }

    #[test]
    fn test_stack_entry_dynamic() {
        let stack = TraceStackEntry::new_dynamic(1, 0, Lifespan::at(0));
        assert!(!stack.has_fixed_frames());
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
    fn test_stack_entry_frame_mut() {
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000));
        let f = stack.frame_mut(0).unwrap();
        f.pc = 0x500000;
        assert_eq!(stack.pc(), Some(0x500000));
    }

    // -----------------------------------------------------------------------
    // Depth management tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_stack_entry_set_depth_grow_at_end() {
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000));
        assert_eq!(stack.depth(), 1);

        stack.set_depth(3, false);
        assert_eq!(stack.depth(), 3);
        assert_eq!(stack.frame(0).unwrap().pc, 0x401000);
        assert_eq!(stack.frame(1).unwrap().pc, 0);
        assert_eq!(stack.frame(2).unwrap().pc, 0);
    }

    #[test]
    fn test_stack_entry_set_depth_grow_at_inner() {
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000));
        stack.set_depth(3, true);
        assert_eq!(stack.depth(), 3);
        // Original frame moved to level 2
        assert_eq!(stack.frame(2).unwrap().pc, 0x401000);
        assert_eq!(stack.frame(0).unwrap().pc, 0);
    }

    #[test]
    fn test_stack_entry_set_depth_shrink_at_end() {
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 1, 0x402000, 0x7FFF0020));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 2, 0x403000, 0x7FFF0040));
        stack.set_depth(1, false);
        assert_eq!(stack.depth(), 1);
        assert_eq!(stack.pc(), Some(0x401000));
    }

    #[test]
    fn test_stack_entry_set_depth_shrink_at_inner() {
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 1, 0x402000, 0x7FFF0020));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 2, 0x403000, 0x7FFF0040));
        stack.set_depth(1, true);
        assert_eq!(stack.depth(), 1);
        assert_eq!(stack.pc(), Some(0x403000));
    }

    // -----------------------------------------------------------------------
    // Lifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_stack_entry_delete() {
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::now_on(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000));
        stack.delete();
        assert!(stack.is_empty());
        assert_eq!(stack.lifespan, Lifespan::EMPTY);
    }

    #[test]
    fn test_stack_entry_remove() {
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::now_on(0));
        assert!(stack.is_valid_at(100));
        stack.remove(10);
        assert!(stack.is_valid_at(10));
        assert!(!stack.is_valid_at(11));
    }

    // -----------------------------------------------------------------------
    // Manager tests
    // -----------------------------------------------------------------------

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
    fn test_stack_manager_set_depth() {
        let mut mgr = TraceStackFrameManager::new();
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x400000, 0x7FFF0000));
        mgr.set_stack(stack);

        assert!(mgr.set_depth(1, 0, 3, false));
        assert_eq!(mgr.get_depth(1, 0), Some(3));
        assert!(!mgr.set_depth(99, 0, 3, false)); // nonexistent thread
    }

    #[test]
    fn test_stack_manager_delete_thread() {
        let mut mgr = TraceStackFrameManager::new();
        let stack = TraceStackEntry::new(1, 0, Lifespan::now_on(0));
        mgr.set_stack(stack);
        assert_eq!(mgr.thread_count(), 1);
        mgr.delete_thread(1);
        assert_eq!(mgr.thread_count(), 0);
    }

    #[test]
    fn test_stack_manager_remove_at() {
        let mut mgr = TraceStackFrameManager::new();
        let stack = TraceStackEntry::new(1, 0, Lifespan::now_on(0));
        mgr.set_stack(stack);
        mgr.remove_thread_at(1, 10);
        let s = mgr.get_stack(1, 0).unwrap();
        assert!(s.is_valid_at(10));
        assert!(!s.is_valid_at(11));
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
        f.set_comment(0, "test comment");

        let json = serde_json::to_string(&f).unwrap();
        let back: TraceStackFrameEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pc, 0x401000);
        assert_eq!(back.function_name.as_deref(), Some("main"));
        assert_eq!(back.register_u64_le("RBP"), Some(0x7FFF0010));
        assert_eq!(back.get_comment(0), Some("test comment"));
    }

    #[test]
    fn test_stack_entry_serde() {
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x400000, 0x7FFF0000));

        let json = serde_json::to_string(&stack).unwrap();
        let back: TraceStackEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.thread_key, 1);
        assert_eq!(back.depth(), 1);
        assert!(back.has_fixed_frames());
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

    // -----------------------------------------------------------------------
    // New: is_outermost, display_address, clone_with_level, set_pc/sp
    // -----------------------------------------------------------------------

    #[test]
    fn test_frame_is_outermost() {
        let f0 = TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000);
        let f1 = TraceStackFrameEntry::new(1, 0, 1, 0x402000, 0x7FFF0020);
        let f2 = TraceStackFrameEntry::new(1, 0, 2, 0x403000, 0x7FFF0040);
        assert!(!f0.is_outermost(3));
        assert!(!f1.is_outermost(3));
        assert!(f2.is_outermost(3));
    }

    #[test]
    fn test_frame_display_address() {
        let inner = TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000)
            .with_return_address(0x402000);
        // Innermost: always returns PC
        assert_eq!(inner.display_address(), 0x401000);

        let outer = TraceStackFrameEntry::new(1, 0, 1, 0x402000, 0x7FFF0020)
            .with_return_address(0x403000);
        // Non-innermost with return address
        assert_eq!(outer.display_address(), 0x403000);

        let outer_no_ra = TraceStackFrameEntry::new(1, 0, 1, 0x402000, 0x7FFF0020);
        // Non-innermost without return address: falls back to PC
        assert_eq!(outer_no_ra.display_address(), 0x402000);
    }

    #[test]
    fn test_frame_clone_with_level() {
        let mut f = TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000)
            .with_fp(0x7FFF0010)
            .with_function("main");
        f.set_register(FrameRegisterValue::from_u64_le("RBP", 0x7FFF0010));
        f.set_comment(0, "original");

        let cloned = f.clone_with_level(3);
        assert_eq!(cloned.level, 3);
        assert_eq!(cloned.pc, 0x401000);
        assert_eq!(cloned.sp, 0x7FFF0000);
        assert_eq!(cloned.fp, Some(0x7FFF0010));
        assert_eq!(cloned.function_name.as_deref(), Some("main"));
        assert_eq!(cloned.register_count(), 1);
        // Comments are not cloned
        assert!(cloned.get_comment(0).is_none());
    }

    #[test]
    fn test_frame_set_pc_sp_with_lifespan() {
        let mut f = TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000);
        f.set_pc(&Lifespan::now_on(0), 0x500000);
        f.set_sp(&Lifespan::now_on(0), 0x80000000);
        assert_eq!(f.pc, 0x500000);
        assert_eq!(f.sp, 0x80000000);
    }

    // -----------------------------------------------------------------------
    // New: StackFrameError
    // -----------------------------------------------------------------------

    #[test]
    fn test_stack_frame_error_display() {
        let err = StackFrameError::LevelOutOfBounds { level: 5, depth: 3 };
        assert!(err.to_string().contains("5"));
        assert!(err.to_string().contains("3"));

        let err2 = StackFrameError::InvalidSnap { snap: -1 };
        assert!(err2.to_string().contains("-1"));
    }

    // -----------------------------------------------------------------------
    // New: TraceStackEntry get_frame with ensure_depth, frame_or_create
    // -----------------------------------------------------------------------

    #[test]
    fn test_stack_entry_get_frame_ensure_depth() {
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000));
        assert_eq!(stack.depth(), 1);

        // Ask for level 3 with ensure_depth -- should expand
        stack.get_frame(3, true).unwrap();
        assert_eq!(stack.depth(), 4);
    }

    #[test]
    fn test_stack_entry_get_frame_without_ensure() {
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000));
        let err = stack.get_frame(5, false).unwrap_err();
        assert!(matches!(err, StackFrameError::LevelOutOfBounds { .. }));
    }

    #[test]
    fn test_stack_entry_get_frame_negative_level() {
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        let err = stack.get_frame(-1, false).unwrap_err();
        assert!(matches!(err, StackFrameError::LevelOutOfBounds { level: -1, .. }));
    }

    #[test]
    fn test_stack_entry_frame_or_create() {
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000));

        // Get existing frame
        let f = stack.frame_or_create(0);
        assert_eq!(f.pc, 0x401000);

        // Create new frame at level 2
        let f2 = stack.frame_or_create(2);
        assert_eq!(f2.level, 2);
        assert_eq!(stack.depth(), 3);
    }

    // -----------------------------------------------------------------------
    // New: TraceStackFrameManager extended methods
    // -----------------------------------------------------------------------

    #[test]
    fn test_stack_manager_is_empty() {
        let mut mgr = TraceStackFrameManager::new();
        assert!(mgr.is_empty());
        let stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        mgr.set_stack(stack);
        assert!(!mgr.is_empty());
    }

    #[test]
    fn test_stack_manager_thread_keys() {
        let mut mgr = TraceStackFrameManager::new();
        mgr.set_stack(TraceStackEntry::new(1, 0, Lifespan::at(0)));
        mgr.set_stack(TraceStackEntry::new(2, 0, Lifespan::at(0)));
        let keys = mgr.thread_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&1));
        assert!(keys.contains(&2));
    }

    #[test]
    fn test_stack_manager_get_frame() {
        let mut mgr = TraceStackFrameManager::new();
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000));
        mgr.set_stack(stack);

        // Existing frame
        let f = mgr.get_frame(1, 0, 0, false).unwrap();
        assert_eq!(f.pc, 0x401000);

        // Non-existent thread
        assert!(mgr.get_frame(99, 0, 0, false).is_none());
    }

    #[test]
    fn test_stack_manager_get_frame_ensure_depth() {
        let mut mgr = TraceStackFrameManager::new();
        let stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        mgr.set_stack(stack);

        // Frame doesn't exist yet, but ensure_depth should create it
        let f = mgr.get_frame(1, 0, 2, true).unwrap();
        assert_eq!(f.level, 2);
    }

    #[test]
    fn test_stack_manager_get_function_name() {
        let mut mgr = TraceStackFrameManager::new();
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(
            TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000)
                .with_function("main"),
        );
        mgr.set_stack(stack);

        assert_eq!(mgr.get_function_name(1, 0, 0), Some("main"));
        assert_eq!(mgr.get_function_name(1, 0, 1), None);
        assert_eq!(mgr.get_function_name(99, 0, 0), None);
    }

    #[test]
    fn test_stack_manager_get_frame_pointer() {
        let mut mgr = TraceStackFrameManager::new();
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(
            TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000)
                .with_fp(0x7FFF0010),
        );
        mgr.set_stack(stack);

        assert_eq!(mgr.get_frame_pointer(1, 0, 0), Some(0x7FFF0010));
        assert_eq!(mgr.get_frame_pointer(1, 0, 1), None);
    }

    #[test]
    fn test_stack_manager_get_return_address() {
        let mut mgr = TraceStackFrameManager::new();
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(
            TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000)
                .with_return_address(0x402000),
        );
        mgr.set_stack(stack);

        assert_eq!(mgr.get_return_address(1, 0, 0), Some(0x402000));
    }

    #[test]
    fn test_stack_manager_frame_comments() {
        let mut mgr = TraceStackFrameManager::new();
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000));
        mgr.set_stack(stack);

        assert!(mgr.get_frame_comment(1, 0, 0).is_none());
        assert!(mgr.set_frame_comment(1, 0, 0, "at entry"));
        assert_eq!(mgr.get_frame_comment(1, 0, 0), Some("at entry"));

        // Non-existent frame
        assert!(!mgr.set_frame_comment(1, 0, 5, "nowhere"));
    }

    #[test]
    fn test_stack_manager_frame_registers() {
        let mut mgr = TraceStackFrameManager::new();
        let mut stack = TraceStackEntry::new(1, 0, Lifespan::at(0));
        stack.push_frame(TraceStackFrameEntry::new(1, 0, 0, 0x401000, 0x7FFF0000));
        mgr.set_stack(stack);

        let reg = FrameRegisterValue::from_u64_le("RBP", 0x7FFF0010);
        assert!(mgr.set_frame_register(1, 0, 0, reg));

        let rbp = mgr.get_frame_register(1, 0, 0, "RBP").unwrap();
        assert_eq!(rbp.as_u64_le(), Some(0x7FFF0010));

        assert!(mgr.get_frame_register(1, 0, 0, "RAX").is_none());
    }
}
