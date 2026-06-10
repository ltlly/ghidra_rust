//! TraceThread -- enhanced thread representation for the debug trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.thread.TraceThread` and
//! `ghidra.trace.database.thread.DBTraceThread`.
//!
//! This module provides a richer thread type than the basic `model::thread::TraceThread`,
//! with support for execution state history, register snapshots, and stack frames.
//!
//! New in this update: lifespan-aware name and comment management
//! (`set_name`, `name_at`, `set_comment`, `comment_at`), `delete()` for full
//! removal, breakpoint association tracking, thread priority and group,
//! and the `ThreadSnapshot` point-in-time summary.
//!
//! **Latest additions** (ported from `DBTraceThread` / `TraceThreadManager`):
//! - `ThreadChangeEvent` enum for structured change notification.
//! - `TraceChangeRecord` for typed change records with thread context.
//! - `ThreadManager` for CRUD operations on threads within a trace.
//! - `register_context` field for per-thread register context data.
//! - `display_name` for the UI-visible thread name (separate from object path).
//! - `is_valid_at` for multi-lifespan validity (object mode).
//! - `remove_tree` for cascading removal of child objects.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::model::TraceExecutionState;

// ---------------------------------------------------------------------------
// ThreadChangeEvent
// ---------------------------------------------------------------------------

/// The kind of change event that occurred on a thread.
///
/// Ported from Ghidra's `TraceEvents.THREAD_ADDED`, `THREAD_CHANGED`, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreadChangeEvent {
    /// A new thread was added.
    Added,
    /// The thread's lifespan changed (creation or destruction snap moved).
    LifespanChanged,
    /// The thread's properties changed (name, comment, etc.).
    Changed,
    /// The thread was deleted.
    Deleted,
}

impl ThreadChangeEvent {
    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Added => "THREAD_ADDED",
            Self::LifespanChanged => "THREAD_LIFESPAN_CHANGED",
            Self::Changed => "THREAD_CHANGED",
            Self::Deleted => "THREAD_DELETED",
        }
    }
}

impl std::fmt::Display for ThreadChangeEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// TraceChangeRecord
// ---------------------------------------------------------------------------

/// A typed change record carrying the thread key and event kind.
///
/// Ported from Ghidra's `TraceChangeRecord<TraceThread, ?>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceChangeRecord {
    /// The kind of change event.
    pub event: ThreadChangeEvent,
    /// The key of the thread that changed.
    pub thread_key: i64,
    /// The snap at which the change occurred, if applicable.
    pub snap: Option<i64>,
    /// An optional key name that was affected (e.g. "DisplayName", "Comment").
    pub affected_key: Option<String>,
}

impl TraceChangeRecord {
    /// Create a new change record.
    pub fn new(event: ThreadChangeEvent, thread_key: i64) -> Self {
        Self {
            event,
            thread_key,
            snap: None,
            affected_key: None,
        }
    }

    /// Attach a snap.
    pub fn with_snap(mut self, snap: i64) -> Self {
        self.snap = Some(snap);
        self
    }

    /// Attach an affected key name.
    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.affected_key = Some(key.into());
        self
    }
}

// ---------------------------------------------------------------------------
// RegisterSnapshot
// ---------------------------------------------------------------------------

/// A snapshot of register values at a particular snap.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterSnapshot {
    /// Register name -> byte value.
    pub values: BTreeMap<String, Vec<u8>>,
    /// The snap at which this snapshot was taken.
    pub snap: i64,
}

impl RegisterSnapshot {
    /// Create an empty snapshot.
    pub fn new(snap: i64) -> Self {
        Self {
            values: BTreeMap::new(),
            snap,
        }
    }

    /// Set a register value.
    pub fn set(&mut self, name: impl Into<String>, value: Vec<u8>) {
        self.values.insert(name.into(), value);
    }

    /// Get a register value by name.
    pub fn get(&self, name: &str) -> Option<&Vec<u8>> {
        self.values.get(name)
    }

    /// Interpret a register as a little-endian u64.
    pub fn get_u64_le(&self, name: &str) -> Option<u64> {
        self.values.get(name).and_then(|v| {
            if v.len() > 8 {
                return None;
            }
            let mut buf = [0u8; 8];
            buf[..v.len()].copy_from_slice(v);
            Some(u64::from_le_bytes(buf))
        })
    }

    /// The number of registers in this snapshot.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the snapshot is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

// ---------------------------------------------------------------------------
// StackFrameInfo
// ---------------------------------------------------------------------------

/// Information about a single stack frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrameInfo {
    /// The frame level (0 = innermost / current).
    pub level: u32,
    /// The program counter (current instruction or return address).
    pub pc: u64,
    /// The stack pointer for this frame.
    pub sp: u64,
    /// The frame pointer, if available.
    pub fp: Option<u64>,
    /// The function name, if resolved.
    pub function_name: Option<String>,
}

impl StackFrameInfo {
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

// ---------------------------------------------------------------------------
// ExecutionStateRecord
// ---------------------------------------------------------------------------

/// A record of an execution state at a particular snap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStateRecord {
    /// The execution state.
    pub state: TraceExecutionState,
    /// The snap at which this state was entered.
    pub snap: i64,
    /// An optional reason string (e.g., "breakpoint-hit", "signal 11").
    pub reason: Option<String>,
}

impl ExecutionStateRecord {
    /// Create a new state record.
    pub fn new(state: TraceExecutionState, snap: i64) -> Self {
        Self {
            state,
            snap,
            reason: None,
        }
    }

    /// Attach a reason.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

// ---------------------------------------------------------------------------
// NameEntry / CommentEntry
// ---------------------------------------------------------------------------

/// A lifespan-bound name entry, allowing names to change over time.
///
/// Mirrors the Java pattern where `setName(Lifespan, String)` can record
/// a name that applies for a specific span of snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameEntry {
    /// The lifespan during which this name applies.
    pub lifespan: Lifespan,
    /// The name value.
    pub name: String,
}

/// A lifespan-bound comment entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentEntry {
    /// The lifespan during which this comment applies.
    pub lifespan: Lifespan,
    /// The comment text.
    pub comment: String,
}

// ---------------------------------------------------------------------------
// ThreadSnapshot
// ---------------------------------------------------------------------------

/// A point-in-time summary of a thread's state.
///
/// Captures the thread's execution state, register values, and stack
/// at a particular snapshot for quick comparison and serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadSnapshot {
    /// The snap at which this summary was captured.
    pub snap: i64,
    /// The execution state at this snap.
    pub execution_state: TraceExecutionState,
    /// The program counter, if known.
    pub pc: Option<u64>,
    /// The stack pointer, if known.
    pub sp: Option<u64>,
    /// Register name -> byte value, if captured.
    pub registers: BTreeMap<String, Vec<u8>>,
    /// Stack frame count.
    pub frame_count: usize,
}

impl ThreadSnapshot {
    /// Create a new thread snapshot.
    pub fn new(snap: i64, execution_state: TraceExecutionState) -> Self {
        Self {
            snap,
            execution_state,
            pc: None,
            sp: None,
            registers: BTreeMap::new(),
            frame_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// TraceThread
// ---------------------------------------------------------------------------

/// An enhanced thread entry for the debug trace.
///
/// This extends the basic `model::thread::TraceThread` with register
/// snapshots, stack frames, and execution state history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceThread {
    /// Unique key identifying this thread.
    pub key: i64,
    /// The key of the owning process.
    pub process_key: i64,
    /// The object path (e.g., "Processes[0].Threads[1]").
    pub path: String,
    /// The OS-assigned thread ID.
    pub tid: Option<i64>,
    /// The thread name (object-path-derived "short name").
    pub name: String,
    /// The display name shown in the UI.
    ///
    /// In Ghidra's Java, this is stored as the `KEY_DISPLAY` attribute on
    /// the trace object. It may differ from the object path.
    pub display_name: Option<String>,
    /// User comment.
    pub comment: Option<String>,
    /// The lifespan during which this thread exists.
    pub lifespan: Lifespan,
    /// The current execution state.
    pub execution_state: TraceExecutionState,
    /// The snap at which the current execution state was set.
    pub execution_state_snap: i64,
    /// History of execution states (most recent last).
    state_history: Vec<ExecutionStateRecord>,
    /// Register snapshots indexed by snap.
    register_snapshots: BTreeMap<i64, RegisterSnapshot>,
    /// Stack frame snapshots indexed by snap.
    stack_snapshots: BTreeMap<i64, Vec<StackFrameInfo>>,
    /// Lifespan-bound name entries (most recent last).
    ///
    /// When non-empty, `name_at(snap)` returns the most recent name
    /// whose lifespan contains `snap`. Falls back to `name` if empty.
    name_history: Vec<NameEntry>,
    /// Lifespan-bound comment entries (most recent last).
    comment_history: Vec<CommentEntry>,
    /// Breakpoint keys associated with this thread.
    pub breakpoint_keys: Vec<i64>,
    /// Thread priority (OS-assigned), if known.
    pub priority: Option<i32>,
    /// Thread group name (e.g. "main", "signal"), if known.
    pub group: Option<String>,
    /// Whether this thread has been fully deleted (not just removed at a snap).
    pub deleted: bool,
    /// Per-thread register context data (register name -> value bytes).
    ///
    /// Ported from `DBTraceRegisterContextManager`. This stores context
    /// register values that are not part of a general register snapshot
    /// but rather define execution context (e.g., TMode for ARM Thumb).
    register_context: BTreeMap<String, Vec<u8>>,
}

impl TraceThread {
    /// Create a new thread.
    pub fn new(
        key: i64,
        path: impl Into<String>,
        name: impl Into<String>,
        snap: i64,
    ) -> Self {
        Self {
            key,
            process_key: 0,
            path: path.into(),
            tid: None,
            name: name.into(),
            display_name: None,
            comment: None,
            lifespan: Lifespan::now_on(snap),
            execution_state: TraceExecutionState::Unknown,
            execution_state_snap: snap,
            state_history: Vec::new(),
            register_snapshots: BTreeMap::new(),
            stack_snapshots: BTreeMap::new(),
            name_history: Vec::new(),
            comment_history: Vec::new(),
            breakpoint_keys: Vec::new(),
            priority: None,
            group: None,
            deleted: false,
            register_context: BTreeMap::new(),
        }
    }

    /// Set the TID.
    pub fn with_tid(mut self, tid: i64) -> Self {
        self.tid = Some(tid);
        self
    }

    /// Set a comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Whether this thread is valid at `snap`.
    pub fn is_valid(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }

    /// Whether the thread is alive for any part of the given span.
    pub fn is_alive(&self, span: &Lifespan) -> bool {
        self.lifespan.intersects(span)
    }

    /// End the thread's life at the given snap.
    pub fn remove(&mut self, snap: i64) {
        self.lifespan = self.lifespan.with_max(snap);
    }

    // -- Execution state --

    /// Set the execution state at a given snap.
    pub fn set_execution_state(
        &mut self,
        state: TraceExecutionState,
        snap: i64,
    ) {
        let record = ExecutionStateRecord::new(state, snap);
        self.execution_state = state;
        self.execution_state_snap = snap;
        self.state_history.push(record);
    }

    /// Set the execution state with a reason.
    pub fn set_execution_state_with_reason(
        &mut self,
        state: TraceExecutionState,
        snap: i64,
        reason: impl Into<String>,
    ) {
        let record = ExecutionStateRecord::new(state, snap).with_reason(reason);
        self.execution_state = state;
        self.execution_state_snap = snap;
        self.state_history.push(record);
    }

    /// The execution state history.
    pub fn state_history(&self) -> &[ExecutionStateRecord] {
        &self.state_history
    }

    /// The number of state transitions recorded.
    pub fn state_history_len(&self) -> usize {
        self.state_history.len()
    }

    /// Clear the execution state history.
    pub fn clear_state_history(&mut self) {
        self.state_history.clear();
    }

    // -- Register snapshots --

    /// Set a register snapshot at a given snap.
    pub fn set_register_snapshot(&mut self, snap: i64, snapshot: RegisterSnapshot) {
        self.register_snapshots.insert(snap, snapshot);
    }

    /// Get the register snapshot at or before `snap`.
    pub fn register_snapshot_at(&self, snap: i64) -> Option<&RegisterSnapshot> {
        self.register_snapshots
            .range(..=snap)
            .next_back()
            .map(|(_, v)| v)
    }

    /// Get the exact register snapshot at `snap`.
    pub fn register_snapshot_exact(&self, snap: i64) -> Option<&RegisterSnapshot> {
        self.register_snapshots.get(&snap)
    }

    /// All register snapshot snaps.
    pub fn register_snapshot_snaps(&self) -> Vec<i64> {
        self.register_snapshots.keys().copied().collect()
    }

    // -- Stack frames --

    /// Set stack frames at a given snap.
    pub fn set_stack_frames(&mut self, snap: i64, frames: Vec<StackFrameInfo>) {
        self.stack_snapshots.insert(snap, frames);
    }

    /// Get stack frames at or before `snap`.
    pub fn stack_frames_at(&self, snap: i64) -> Option<&Vec<StackFrameInfo>> {
        self.stack_snapshots
            .range(..=snap)
            .next_back()
            .map(|(_, v)| v)
    }

    /// Get the exact stack frames at `snap`.
    pub fn stack_frames_exact(&self, snap: i64) -> Option<&Vec<StackFrameInfo>> {
        self.stack_snapshots.get(&snap)
    }

    /// The number of stack frame snapshots.
    pub fn stack_snapshot_count(&self) -> usize {
        self.stack_snapshots.len()
    }

    /// Get the PC (program counter) from the innermost frame at `snap`.
    pub fn pc_at(&self, snap: i64) -> Option<u64> {
        self.stack_frames_at(snap).and_then(|frames| {
            frames.iter().find(|f| f.level == 0).map(|f| f.pc)
        })
    }

    /// Whether the thread is currently alive (has not been removed).
    ///
    /// This checks whether the lifespan has no upper bound (i.e., the thread
    /// has not been terminated).
    pub fn is_alive_now(&self) -> bool {
        self.lifespan.lmax() == Lifespan::MAX
    }

    // -- Lifespan-aware names --

    /// Set a name that applies for the given lifespan.
    ///
    /// Mirrors the Java `TraceThread.setName(Lifespan, String)`.
    pub fn set_name(&mut self, lifespan: Lifespan, name: impl Into<String>) {
        self.name_history.push(NameEntry {
            lifespan,
            name: name.into(),
        });
    }

    /// Set the name starting at the given snap (applies until changed).
    pub fn set_name_at(&mut self, snap: i64, name: impl Into<String>) {
        self.set_name(Lifespan::now_on(snap), name);
    }

    /// Get the thread name at a given snap.
    ///
    /// Returns the most recent name whose lifespan contains `snap`,
    /// falling back to the base `name` field.
    pub fn name_at(&self, snap: i64) -> &str {
        self.name_history
            .iter()
            .rev()
            .find(|entry| entry.lifespan.contains(snap))
            .map(|entry| entry.name.as_str())
            .unwrap_or(self.name.as_str())
    }

    /// The name history.
    pub fn name_history(&self) -> &[NameEntry] {
        &self.name_history
    }

    /// Clear name history and set the base name.
    pub fn reset_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
        self.name_history.clear();
    }

    // -- Lifespan-aware comments --

    /// Set a comment that applies for the given lifespan.
    pub fn set_comment(&mut self, lifespan: Lifespan, comment: impl Into<String>) {
        self.comment_history.push(CommentEntry {
            lifespan,
            comment: comment.into(),
        });
    }

    /// Set the comment starting at the given snap.
    pub fn set_comment_at(&mut self, snap: i64, comment: impl Into<String>) {
        self.set_comment(Lifespan::now_on(snap), comment);
    }

    /// Get the comment at a given snap.
    ///
    /// Returns the most recent comment whose lifespan contains `snap`,
    /// falling back to the base `comment` field.
    pub fn comment_at(&self, snap: i64) -> Option<&str> {
        self.comment_history
            .iter()
            .rev()
            .find(|entry| entry.lifespan.contains(snap))
            .map(|entry| entry.comment.as_str())
            .or(self.comment.as_deref())
    }

    /// The comment history.
    pub fn comment_history(&self) -> &[CommentEntry] {
        &self.comment_history
    }

    // -- Deletion --

    /// Mark this thread as fully deleted.
    ///
    /// Unlike `remove(snap)` which ends the lifespan at a snap, `delete()`
    /// marks the thread as completely removed from the trace.
    pub fn delete(&mut self) {
        self.deleted = true;
        self.lifespan = Lifespan::EMPTY;
    }

    /// Whether this thread has been fully deleted.
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    // -- Breakpoints --

    /// Associate a breakpoint with this thread.
    pub fn add_breakpoint(&mut self, bp_key: i64) {
        if !self.breakpoint_keys.contains(&bp_key) {
            self.breakpoint_keys.push(bp_key);
        }
    }

    /// Remove a breakpoint association.
    pub fn remove_breakpoint(&mut self, bp_key: i64) {
        self.breakpoint_keys.retain(|&k| k != bp_key);
    }

    /// Whether this thread has the given breakpoint.
    pub fn has_breakpoint(&self, bp_key: i64) -> bool {
        self.breakpoint_keys.contains(&bp_key)
    }

    // -- Priority / group --

    /// Set the thread priority.
    pub fn set_priority(&mut self, priority: i32) {
        self.priority = Some(priority);
    }

    /// Set the thread group.
    pub fn set_group(&mut self, group: impl Into<String>) {
        self.group = Some(group.into());
    }

    // -- ThreadSnapshot --

    /// Capture a point-in-time snapshot of this thread's state.
    pub fn snapshot_at(&self, snap: i64) -> ThreadSnapshot {
        let mut ts = ThreadSnapshot::new(snap, self.execution_state);

        // Capture PC and SP from stack frames.
        if let Some(frames) = self.stack_frames_at(snap) {
            ts.frame_count = frames.len();
            if let Some(innermost) = frames.iter().find(|f| f.level == 0) {
                ts.pc = Some(innermost.pc);
                ts.sp = Some(innermost.sp);
            }
        }

        // Capture registers from the latest register snapshot.
        if let Some(reg_snap) = self.register_snapshot_at(snap) {
            ts.registers = reg_snap.values.clone();
            // Also derive PC from RIP if no stack frame info.
            if ts.pc.is_none() {
                ts.pc = reg_snap.get_u64_le("RIP").or_else(|| reg_snap.get_u64_le("PC"));
            }
            if ts.sp.is_none() {
                ts.sp = reg_snap.get_u64_le("RSP").or_else(|| reg_snap.get_u64_le("SP"));
            }
        }

        ts
    }

    // -- Query helpers --

    /// The latest execution state transition, if any.
    pub fn latest_state_transition(&self) -> Option<&ExecutionStateRecord> {
        self.state_history.last()
    }

    /// The snap at which this thread was created.
    pub fn creation_snap(&self) -> i64 {
        self.lifespan.lmin()
    }

    /// The snap at which this thread was destroyed, if it has been.
    pub fn destruction_snap(&self) -> Option<i64> {
        if self.lifespan.lmax() == Lifespan::MAX {
            None
        } else {
            Some(self.lifespan.lmax())
        }
    }

    /// Get the SP (stack pointer) from the innermost frame at `snap`.
    pub fn sp_at(&self, snap: i64) -> Option<u64> {
        self.stack_frames_at(snap).and_then(|frames| {
            frames.iter().find(|f| f.level == 0).map(|f| f.sp)
        })
    }

    /// Get the function name from the innermost frame at `snap`.
    pub fn function_name_at(&self, snap: i64) -> Option<&str> {
        self.stack_frames_at(snap).and_then(|frames| {
            frames
                .iter()
                .find(|f| f.level == 0)
                .and_then(|f| f.function_name.as_deref())
        })
    }

    // -- Display name --

    /// Set the display name for this thread.
    ///
    /// In Ghidra's Java, this maps to `KEY_DISPLAY` on the trace object.
    pub fn set_display_name(&mut self, name: impl Into<String>) {
        self.display_name = Some(name.into());
    }

    /// Get the display name, falling back to the base `name`.
    pub fn display_name(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.name)
    }

    /// Get the display name at a specific snap.
    ///
    /// Checks lifespan-bound name history first, then display name, then base name.
    pub fn display_name_at(&self, snap: i64) -> &str {
        // First check name history
        if let Some(entry) = self
            .name_history
            .iter()
            .rev()
            .find(|e| e.lifespan.contains(snap))
        {
            return entry.name.as_str();
        }
        // Then display name, then base name
        self.display_name.as_deref().unwrap_or(&self.name)
    }

    // -- Register context --

    /// Set a context register value.
    ///
    /// Context registers define execution mode (e.g., ARM TMode) rather
    /// than holding general-purpose data.
    pub fn set_context_register(&mut self, name: impl Into<String>, value: Vec<u8>) {
        self.register_context.insert(name.into(), value);
    }

    /// Get a context register value.
    pub fn context_register(&self, name: &str) -> Option<&Vec<u8>> {
        self.register_context.get(name)
    }

    /// Remove a context register.
    pub fn remove_context_register(&mut self, name: &str) -> Option<Vec<u8>> {
        self.register_context.remove(name)
    }

    /// All context register names.
    pub fn context_register_names(&self) -> Vec<&str> {
        self.register_context.keys().map(|s| s.as_str()).collect()
    }

    /// The number of context registers.
    pub fn context_register_count(&self) -> usize {
        self.register_context.len()
    }

    // -- Multi-lifespan validity --

    /// Check if this thread is valid at the given snap, considering multiple lifespans.
    ///
    /// In object mode, a thread's life may be disjoint. This method checks
    /// the primary lifespan. For table mode, this is equivalent to `is_valid`.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        // Currently only checks primary lifespan.
        // In a full implementation, this would check canonical parent
        // presence in object mode.
        self.lifespan.contains(snap) && !self.deleted
    }

    // -- remove_tree --

    /// Remove this thread and all its children from the given snap onward.
    ///
    /// Ported from `DBTraceThread.remove(snap)` which calls
    /// `object.removeTree(Lifespan.nowOn(snap))`.
    pub fn remove_tree(&mut self, snap: i64) {
        self.remove(snap);
        // In a full implementation this would cascade to child objects
        // (registers, stack frames, etc.) via the object manager.
    }

    /// Delete this thread and all its children.
    ///
    /// Ported from `DBTraceThread.delete()` which calls
    /// `object.removeTree(Lifespan.ALL)`.
    pub fn delete_tree(&mut self) {
        self.delete();
        // In a full implementation this would cascade to child objects.
    }

    // -- Change record helpers --

    /// Create an `Added` change record for this thread.
    pub fn change_record_added(&self) -> TraceChangeRecord {
        TraceChangeRecord::new(ThreadChangeEvent::Added, self.key)
    }

    /// Create a `Changed` change record for this thread.
    pub fn change_record_changed(&self, affected_key: impl Into<String>) -> TraceChangeRecord {
        TraceChangeRecord::new(ThreadChangeEvent::Changed, self.key)
            .with_key(affected_key)
    }

    /// Create a `LifespanChanged` change record for this thread.
    pub fn change_record_lifespan_changed(&self) -> TraceChangeRecord {
        TraceChangeRecord::new(ThreadChangeEvent::LifespanChanged, self.key)
    }

    /// Create a `Deleted` change record for this thread.
    pub fn change_record_deleted(&self) -> TraceChangeRecord {
        TraceChangeRecord::new(ThreadChangeEvent::Deleted, self.key)
    }

    // -- Snapshot with context --

    /// Capture a point-in-time snapshot including context registers.
    pub fn snapshot_with_context_at(&self, snap: i64) -> ThreadSnapshot {
        let mut ts = self.snapshot_at(snap);
        // Merge context registers into the snapshot's register map
        for (name, value) in &self.register_context {
            ts.registers
                .entry(name.clone())
                .or_insert_with(|| value.clone());
        }
        ts
    }

    // -- Register snapshot management --

    /// Remove the register snapshot at the given snap.
    pub fn remove_register_snapshot(&mut self, snap: i64) -> Option<RegisterSnapshot> {
        self.register_snapshots.remove(&snap)
    }

    /// Remove the stack frame snapshot at the given snap.
    pub fn remove_stack_frames(&mut self, snap: i64) -> Option<Vec<StackFrameInfo>> {
        self.stack_snapshots.remove(&snap)
    }

    /// Clear all register snapshots.
    pub fn clear_register_snapshots(&mut self) {
        self.register_snapshots.clear();
    }

    /// Clear all stack frame snapshots.
    pub fn clear_stack_snapshots(&mut self) {
        self.stack_snapshots.clear();
    }

    /// Clear all history (state, name, comment, register, stack).
    pub fn clear_all_history(&mut self) {
        self.state_history.clear();
        self.name_history.clear();
        self.comment_history.clear();
        self.register_snapshots.clear();
        self.stack_snapshots.clear();
        self.register_context.clear();
    }
}

// ---------------------------------------------------------------------------
// ThreadManager
// ---------------------------------------------------------------------------

/// A manager for threads within a trace.
///
/// Ported from Ghidra's `TraceThreadManager` / `DBTraceThreadManager`.
/// Provides CRUD operations for threads with path-based lookup and
/// duplicate-name detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreadManager {
    /// Threads indexed by key.
    threads: BTreeMap<i64, TraceThread>,
    /// Next available thread key.
    next_key: i64,
    /// Change log: recent change records.
    change_log: Vec<TraceChangeRecord>,
}

impl ThreadManager {
    /// Create a new empty thread manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a thread with the given path and lifespan.
    ///
    /// Returns `Err` if a thread with the same path already exists at an
    /// overlapping snap (duplicate name detection).
    pub fn add_thread(
        &mut self,
        path: impl Into<String>,
        display: impl Into<String>,
        lifespan: Lifespan,
    ) -> Result<i64, String> {
        let path = path.into();
        let display = display.into();

        // Check for duplicate path at overlapping snaps
        for existing in self.threads.values() {
            if existing.path == path && existing.lifespan.intersects(&lifespan) {
                return Err(format!(
                    "Duplicate thread path '{}' at overlapping lifespan",
                    path
                ));
            }
        }

        let key = self.next_key;
        self.next_key += 1;
        let mut thread = TraceThread::new(key, path, display, lifespan.lmin());
        thread.lifespan = lifespan;
        self.threads.insert(key, thread);

        self.change_log
            .push(TraceChangeRecord::new(ThreadChangeEvent::Added, key));
        Ok(key)
    }

    /// Create a thread starting at the given snap (open-ended lifespan).
    pub fn create_thread(
        &mut self,
        path: impl Into<String>,
        display: impl Into<String>,
        creation_snap: i64,
    ) -> Result<i64, String> {
        self.add_thread(path, display, Lifespan::now_on(creation_snap))
    }

    /// Get a thread by key.
    pub fn get_thread(&self, key: i64) -> Option<&TraceThread> {
        self.threads.get(&key)
    }

    /// Get a mutable thread by key.
    pub fn get_thread_mut(&mut self, key: i64) -> Option<&mut TraceThread> {
        self.threads.get_mut(&key)
    }

    /// Get all threads, ordered by key (eldest first).
    pub fn all_threads(&self) -> impl Iterator<Item = &TraceThread> {
        self.threads.values()
    }

    /// Get all threads with the given path.
    pub fn threads_by_path(&self, path: &str) -> Vec<&TraceThread> {
        self.threads
            .values()
            .filter(|t| t.path == path)
            .collect()
    }

    /// Get the live thread at the given snap by path.
    pub fn get_live_thread_by_path(&self, snap: i64, path: &str) -> Option<&TraceThread> {
        self.threads
            .values()
            .find(|t| t.path == path && t.is_valid(snap))
    }

    /// Get live threads at the given snap.
    pub fn get_live_threads(&self, snap: i64) -> Vec<&TraceThread> {
        self.threads
            .values()
            .filter(|t| t.is_valid(snap))
            .collect()
    }

    /// Delete a thread by key. Returns the deleted thread, if any.
    pub fn delete_thread(&mut self, key: i64) -> Option<TraceThread> {
        let thread = self.threads.remove(&key);
        if thread.is_some() {
            self.change_log
                .push(TraceChangeRecord::new(ThreadChangeEvent::Deleted, key));
        }
        thread
    }

    /// The number of threads (including dead ones).
    pub fn len(&self) -> usize {
        self.threads.len()
    }

    /// Whether there are no threads.
    pub fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }

    /// The change log.
    pub fn change_log(&self) -> &[TraceChangeRecord] {
        &self.change_log
    }

    /// Clear the change log.
    pub fn clear_change_log(&mut self) {
        self.change_log.clear();
    }

    /// Emit a change record for a thread.
    pub fn emit_change(&mut self, record: TraceChangeRecord) {
        self.change_log.push(record);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_creation() {
        let t = TraceThread::new(1, "P.Threads[0]", "main", 0);
        assert_eq!(t.key, 1);
        assert_eq!(t.name, "main");
        assert!(t.is_valid(0));
        assert!(t.is_valid(100));
        assert!(!t.is_valid(-1));
    }

    #[test]
    fn test_thread_with_tid() {
        let t = TraceThread::new(1, "T", "main", 0).with_tid(42).with_comment("primary thread");
        assert_eq!(t.tid, Some(42));
        assert_eq!(t.comment.as_deref(), Some("primary thread"));
    }

    #[test]
    fn test_thread_remove() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        t.remove(10);
        assert!(t.is_valid(10));
        assert!(!t.is_valid(11));
    }

    #[test]
    fn test_thread_is_alive() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        assert!(t.is_alive(&Lifespan::span(0, 10)));
        t.remove(50);
        assert!(!t.is_alive(&Lifespan::span(100, 200)));
    }

    #[test]
    fn test_execution_state() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        assert_eq!(t.execution_state, TraceExecutionState::Unknown);

        t.set_execution_state(TraceExecutionState::Running, 1);
        assert_eq!(t.execution_state, TraceExecutionState::Running);
        assert_eq!(t.execution_state_snap, 1);

        t.set_execution_state_with_reason(TraceExecutionState::Stopped, 5, "breakpoint-hit");
        assert_eq!(t.execution_state, TraceExecutionState::Stopped);
        assert_eq!(t.state_history_len(), 2);

        let last = &t.state_history()[1];
        assert_eq!(last.state, TraceExecutionState::Stopped);
        assert_eq!(last.reason.as_deref(), Some("breakpoint-hit"));
    }

    #[test]
    fn test_clear_state_history() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        t.set_execution_state(TraceExecutionState::Running, 1);
        t.set_execution_state(TraceExecutionState::Stopped, 2);
        assert_eq!(t.state_history_len(), 2);
        t.clear_state_history();
        assert_eq!(t.state_history_len(), 0);
        // Current state should remain
        assert_eq!(t.execution_state, TraceExecutionState::Stopped);
    }

    #[test]
    fn test_register_snapshots() {
        let mut t = TraceThread::new(1, "T", "main", 0);

        let mut snap = RegisterSnapshot::new(0);
        snap.set("RIP", vec![0x00, 0x10, 0x40, 0, 0, 0, 0, 0]);
        snap.set("RSP", vec![0x00, 0xF0, 0xFF, 0x7F, 0, 0, 0, 0]);
        t.set_register_snapshot(0, snap);

        let mut snap2 = RegisterSnapshot::new(5);
        snap2.set("RIP", vec![0x10, 0x10, 0x40, 0, 0, 0, 0, 0]);
        t.set_register_snapshot(5, snap2);

        // Exact lookup
        let s0 = t.register_snapshot_exact(0).unwrap();
        assert_eq!(s0.len(), 2);
        assert_eq!(s0.get_u64_le("RIP"), Some(0x401000));

        // At-or-before lookup
        let s3 = t.register_snapshot_at(3).unwrap();
        assert_eq!(s3.snap, 0);

        let s5 = t.register_snapshot_at(5).unwrap();
        assert_eq!(s5.snap, 5);

        let s100 = t.register_snapshot_at(100).unwrap();
        assert_eq!(s100.snap, 5);

        assert_eq!(t.register_snapshot_snaps(), vec![0, 5]);
    }

    #[test]
    fn test_stack_frames() {
        let mut t = TraceThread::new(1, "T", "main", 0);

        let frames = vec![
            StackFrameInfo::new(0, 0x401000, 0x7FFF0000)
                .with_fp(0x7FFF0010)
                .with_function("main"),
            StackFrameInfo::new(1, 0x402000, 0x7FFF0020)
                .with_function("__libc_start_main"),
        ];
        t.set_stack_frames(0, frames);

        let f = t.stack_frames_at(0).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].level, 0);
        assert_eq!(f[0].function_name.as_deref(), Some("main"));
        assert_eq!(f[1].function_name.as_deref(), Some("__libc_start_main"));

        // PC lookup
        assert_eq!(t.pc_at(0), Some(0x401000));
        assert_eq!(t.pc_at(100), Some(0x401000)); // latest before 100
        assert!(t.pc_at(-1).is_none());
    }

    #[test]
    fn test_register_snapshot_basics() {
        let snap = RegisterSnapshot::new(5);
        assert!(snap.is_empty());
        assert_eq!(snap.len(), 0);
        assert!(snap.get("RAX").is_none());
    }

    #[test]
    fn test_register_snapshot_u64_le() {
        let mut snap = RegisterSnapshot::new(0);
        snap.set("RAX", vec![0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(snap.get_u64_le("RAX"), Some(0x42));

        // Too many bytes
        snap.set("WIDE", vec![0; 9]);
        assert_eq!(snap.get_u64_le("WIDE"), None);
    }

    #[test]
    fn test_stack_frame_info() {
        let f = StackFrameInfo::new(0, 0x401000, 0x7FFF0000)
            .with_fp(0x7FFF0010)
            .with_function("main");
        assert_eq!(f.level, 0);
        assert_eq!(f.pc, 0x401000);
        assert_eq!(f.sp, 0x7FFF0000);
        assert_eq!(f.fp, Some(0x7FFF0010));
        assert_eq!(f.function_name.as_deref(), Some("main"));
    }

    #[test]
    fn test_thread_serde() {
        let mut t = TraceThread::new(1, "P.T", "main", 0);
        t.set_execution_state(TraceExecutionState::Running, 1);
        let json = serde_json::to_string(&t).unwrap();
        let back: TraceThread = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, 1);
        assert_eq!(back.execution_state, TraceExecutionState::Running);
    }

    #[test]
    fn test_execution_state_record() {
        let r = ExecutionStateRecord::new(TraceExecutionState::Stopped, 5)
            .with_reason("signal 11");
        assert_eq!(r.state, TraceExecutionState::Stopped);
        assert_eq!(r.snap, 5);
        assert_eq!(r.reason.as_deref(), Some("signal 11"));
    }

    // -- New tests for lifespan-aware names --

    #[test]
    fn test_name_at() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        assert_eq!(t.name_at(0), "main");
        assert_eq!(t.name_at(100), "main");

        t.set_name_at(5, "worker");
        assert_eq!(t.name_at(0), "main");
        assert_eq!(t.name_at(5), "worker");
        assert_eq!(t.name_at(100), "worker");

        t.set_name_at(10, "idle");
        assert_eq!(t.name_at(5), "worker");
        assert_eq!(t.name_at(10), "idle");
        assert_eq!(t.name_at(100), "idle");
    }

    #[test]
    fn test_name_with_lifespan() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        t.set_name(Lifespan::span(5, 10), "temp_name");
        assert_eq!(t.name_at(0), "main");
        assert_eq!(t.name_at(5), "temp_name");
        assert_eq!(t.name_at(10), "temp_name");
        assert_eq!(t.name_at(11), "main"); // falls back to base name
    }

    #[test]
    fn test_reset_name() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        t.set_name_at(5, "worker");
        t.reset_name("new_main");
        assert_eq!(t.name, "new_main");
        assert_eq!(t.name_history().len(), 0);
        assert_eq!(t.name_at(5), "new_main");
    }

    // -- New tests for lifespan-aware comments --

    #[test]
    fn test_comment_at() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        assert!(t.comment_at(0).is_none());

        t.set_comment_at(5, "paused here");
        assert!(t.comment_at(0).is_none());
        assert_eq!(t.comment_at(5), Some("paused here"));
        assert_eq!(t.comment_at(100), Some("paused here"));
    }

    #[test]
    fn test_comment_with_lifespan() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        t.set_comment(Lifespan::span(5, 10), "temporary note");
        assert!(t.comment_at(0).is_none());
        assert_eq!(t.comment_at(5), Some("temporary note"));
        assert_eq!(t.comment_at(10), Some("temporary note"));
        assert!(t.comment_at(11).is_none());
    }

    // -- New tests for deletion --

    #[test]
    fn test_delete() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        assert!(!t.is_deleted());
        assert!(t.is_alive_now());
        t.delete();
        assert!(t.is_deleted());
        assert!(!t.is_alive_now());
        assert!(t.lifespan.is_empty());
    }

    // -- New tests for breakpoints --

    #[test]
    fn test_breakpoints() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        assert!(t.breakpoint_keys.is_empty());

        t.add_breakpoint(10);
        t.add_breakpoint(20);
        assert_eq!(t.breakpoint_keys.len(), 2);
        assert!(t.has_breakpoint(10));
        assert!(t.has_breakpoint(20));
        assert!(!t.has_breakpoint(30));

        // No duplicates
        t.add_breakpoint(10);
        assert_eq!(t.breakpoint_keys.len(), 2);

        t.remove_breakpoint(10);
        assert!(!t.has_breakpoint(10));
        assert_eq!(t.breakpoint_keys.len(), 1);
    }

    // -- New tests for priority/group --

    #[test]
    fn test_priority_and_group() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        assert!(t.priority.is_none());
        assert!(t.group.is_none());

        t.set_priority(10);
        t.set_group("main");
        assert_eq!(t.priority, Some(10));
        assert_eq!(t.group.as_deref(), Some("main"));
    }

    // -- New tests for ThreadSnapshot --

    #[test]
    fn test_thread_snapshot() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        t.set_execution_state(TraceExecutionState::Stopped, 5);

        let mut snap = RegisterSnapshot::new(5);
        snap.set("RIP", vec![0x00, 0x10, 0x40, 0, 0, 0, 0, 0]);
        snap.set("RSP", vec![0x00, 0xF0, 0xFF, 0x7F, 0, 0, 0, 0]);
        t.set_register_snapshot(5, snap);

        let frames = vec![
            StackFrameInfo::new(0, 0x401000, 0x7FFF0000).with_function("main"),
            StackFrameInfo::new(1, 0x402000, 0x7FFF0020).with_function("start"),
        ];
        t.set_stack_frames(5, frames);

        let ts = t.snapshot_at(5);
        assert_eq!(ts.snap, 5);
        assert_eq!(ts.execution_state, TraceExecutionState::Stopped);
        assert_eq!(ts.pc, Some(0x401000));
        assert_eq!(ts.sp, Some(0x7FFF0000));
        assert_eq!(ts.frame_count, 2);
        assert_eq!(ts.registers.len(), 2);
    }

    #[test]
    fn test_thread_snapshot_no_stack() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        let mut snap = RegisterSnapshot::new(0);
        snap.set("RIP", vec![0x00, 0x10, 0x40, 0, 0, 0, 0, 0]);
        t.set_register_snapshot(0, snap);

        let ts = t.snapshot_at(0);
        assert_eq!(ts.pc, Some(0x401000));
        assert_eq!(ts.frame_count, 0);
    }

    // -- New tests for query helpers --

    #[test]
    fn test_creation_and_destruction_snap() {
        let mut t = TraceThread::new(1, "T", "main", 5);
        assert_eq!(t.creation_snap(), 5);
        assert!(t.destruction_snap().is_none());

        t.remove(20);
        assert_eq!(t.destruction_snap(), Some(20));
    }

    #[test]
    fn test_latest_state_transition() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        assert!(t.latest_state_transition().is_none());

        t.set_execution_state(TraceExecutionState::Running, 1);
        let tr = t.latest_state_transition().unwrap();
        assert_eq!(tr.state, TraceExecutionState::Running);
    }

    #[test]
    fn test_sp_at() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        let frames = vec![
            StackFrameInfo::new(0, 0x401000, 0x7FFF0000),
            StackFrameInfo::new(1, 0x402000, 0x7FFF0020),
        ];
        t.set_stack_frames(0, frames);
        assert_eq!(t.sp_at(0), Some(0x7FFF0000));
        assert!(t.sp_at(-1).is_none());
    }

    #[test]
    fn test_function_name_at() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        let frames = vec![
            StackFrameInfo::new(0, 0x401000, 0x7FFF0000).with_function("main"),
            StackFrameInfo::new(1, 0x402000, 0x7FFF0020).with_function("start"),
        ];
        t.set_stack_frames(0, frames);
        assert_eq!(t.function_name_at(0), Some("main"));
        assert!(t.function_name_at(-1).is_none());
    }

    #[test]
    fn test_name_entry_serde() {
        let entry = NameEntry {
            lifespan: Lifespan::span(0, 10),
            name: "test".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: NameEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test");
        assert_eq!(back.lifespan, Lifespan::span(0, 10));
    }

    #[test]
    fn test_comment_entry_serde() {
        let entry = CommentEntry {
            lifespan: Lifespan::at(5),
            comment: "note".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: CommentEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.comment, "note");
    }

    #[test]
    fn test_thread_snapshot_serde() {
        let ts = ThreadSnapshot::new(5, TraceExecutionState::Stopped);
        let json = serde_json::to_string(&ts).unwrap();
        let back: ThreadSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.snap, 5);
        assert_eq!(back.execution_state, TraceExecutionState::Stopped);
    }

    // -- Display name tests --

    #[test]
    fn test_display_name() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        assert_eq!(t.display_name(), "main"); // falls back to name

        t.set_display_name("Main Thread");
        assert_eq!(t.display_name(), "Main Thread");
    }

    #[test]
    fn test_display_name_at() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        assert_eq!(t.display_name_at(0), "main");

        t.set_display_name("Worker");
        assert_eq!(t.display_name_at(0), "Worker");

        t.set_name_at(5, "Renamed");
        assert_eq!(t.display_name_at(0), "Worker"); // no name history at 0
        assert_eq!(t.display_name_at(5), "Renamed"); // name history takes precedence
    }

    // -- Register context tests --

    #[test]
    fn test_register_context() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        assert_eq!(t.context_register_count(), 0);

        t.set_context_register("TMode", vec![1]);
        t.set_context_register("CPSR", vec![0x10, 0x00, 0x00, 0x60]);

        assert_eq!(t.context_register_count(), 2);
        assert_eq!(t.context_register("TMode"), Some(&vec![1]));
        assert_eq!(t.context_register("CPSR").unwrap().len(), 4);
        assert!(t.context_register("missing").is_none());

        let names = t.context_register_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"TMode"));

        t.remove_context_register("TMode");
        assert_eq!(t.context_register_count(), 1);
        assert!(t.context_register("TMode").is_none());
    }

    // -- is_valid_at test --

    #[test]
    fn test_is_valid_at() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        assert!(t.is_valid_at(0));
        assert!(t.is_valid_at(100));
        assert!(!t.is_valid_at(-1));

        t.delete();
        assert!(!t.is_valid_at(0)); // deleted
    }

    // -- remove_tree / delete_tree --

    #[test]
    fn test_remove_tree() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        t.remove_tree(10);
        assert!(t.is_valid(10));
        assert!(!t.is_valid(11));
    }

    #[test]
    fn test_delete_tree() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        t.delete_tree();
        assert!(t.is_deleted());
        assert!(t.lifespan.is_empty());
    }

    // -- Change record tests --

    #[test]
    fn test_change_event() {
        assert_eq!(ThreadChangeEvent::Added.name(), "THREAD_ADDED");
        assert_eq!(ThreadChangeEvent::Deleted.to_string(), "THREAD_DELETED");
    }

    #[test]
    fn test_change_record() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        let rec = t.change_record_added();
        assert_eq!(rec.event, ThreadChangeEvent::Added);
        assert_eq!(rec.thread_key, 1);

        let rec = t.change_record_changed("DisplayName");
        assert_eq!(rec.event, ThreadChangeEvent::Changed);
        assert_eq!(rec.affected_key.as_deref(), Some("DisplayName"));

        let rec = t.change_record_lifespan_changed();
        assert_eq!(rec.event, ThreadChangeEvent::LifespanChanged);

        let rec = t.change_record_deleted();
        assert_eq!(rec.event, ThreadChangeEvent::Deleted);
    }

    #[test]
    fn test_change_record_serde() {
        let rec = TraceChangeRecord::new(ThreadChangeEvent::Added, 1)
            .with_snap(5)
            .with_key("test");
        let json = serde_json::to_string(&rec).unwrap();
        let back: TraceChangeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event, ThreadChangeEvent::Added);
        assert_eq!(back.thread_key, 1);
        assert_eq!(back.snap, Some(5));
        assert_eq!(back.affected_key.as_deref(), Some("test"));
    }

    // -- snapshot_with_context_at --

    #[test]
    fn test_snapshot_with_context() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        t.set_execution_state(TraceExecutionState::Stopped, 0);
        t.set_context_register("TMode", vec![1]);

        let mut reg_snap = RegisterSnapshot::new(0);
        reg_snap.set("RIP", vec![0x00, 0x10, 0x40, 0, 0, 0, 0, 0]);
        t.set_register_snapshot(0, reg_snap);

        let ts = t.snapshot_with_context_at(0);
        assert!(ts.registers.contains_key("RIP"));
        assert!(ts.registers.contains_key("TMode"));
    }

    // -- Register snapshot management --

    #[test]
    fn test_remove_register_snapshot() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        let snap = RegisterSnapshot::new(0);
        t.set_register_snapshot(0, snap);
        assert!(t.register_snapshot_exact(0).is_some());

        t.remove_register_snapshot(0);
        assert!(t.register_snapshot_exact(0).is_none());
    }

    #[test]
    fn test_clear_register_snapshots() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        t.set_register_snapshot(0, RegisterSnapshot::new(0));
        t.set_register_snapshot(5, RegisterSnapshot::new(5));
        assert_eq!(t.register_snapshot_snaps().len(), 2);

        t.clear_register_snapshots();
        assert_eq!(t.register_snapshot_snaps().len(), 0);
    }

    #[test]
    fn test_clear_stack_snapshots() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        t.set_stack_frames(0, vec![StackFrameInfo::new(0, 0x401000, 0x7FFF0000)]);
        assert_eq!(t.stack_snapshot_count(), 1);

        t.clear_stack_snapshots();
        assert_eq!(t.stack_snapshot_count(), 0);
    }

    #[test]
    fn test_clear_all_history() {
        let mut t = TraceThread::new(1, "T", "main", 0);
        t.set_execution_state(TraceExecutionState::Running, 1);
        t.set_name_at(5, "worker");
        t.set_comment_at(3, "note");
        t.set_register_snapshot(0, RegisterSnapshot::new(0));
        t.set_stack_frames(0, vec![]);
        t.set_context_register("TMode", vec![1]);

        t.clear_all_history();
        assert_eq!(t.state_history_len(), 0);
        assert_eq!(t.name_history().len(), 0);
        assert_eq!(t.comment_history().len(), 0);
        assert_eq!(t.register_snapshot_snaps().len(), 0);
        assert_eq!(t.stack_snapshot_count(), 0);
        assert_eq!(t.context_register_count(), 0);
    }

    // -- ThreadManager tests --

    #[test]
    fn test_thread_manager_add() {
        let mut mgr = ThreadManager::new();
        let key = mgr.create_thread("P.Threads[0]", "main", 0).unwrap();
        assert_eq!(key, 0);
        assert_eq!(mgr.len(), 1);

        let thread = mgr.get_thread(key).unwrap();
        assert_eq!(thread.name, "main");
    }

    #[test]
    fn test_thread_manager_duplicate() {
        let mut mgr = ThreadManager::new();
        mgr.create_thread("P.Threads[0]", "main", 0).unwrap();
        let result = mgr.create_thread("P.Threads[0]", "main2", 0);
        assert!(result.is_err()); // Duplicate path at overlapping lifespan
    }

    #[test]
    fn test_thread_manager_by_path() {
        let mut mgr = ThreadManager::new();
        mgr.create_thread("P.Threads[0]", "main", 0).unwrap();
        mgr.create_thread("P.Threads[1]", "worker", 0).unwrap();

        let found = mgr.threads_by_path("P.Threads[0]");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "main");
    }

    #[test]
    fn test_thread_manager_live() {
        let mut mgr = ThreadManager::new();
        let k1 = mgr.create_thread("P.Threads[0]", "main", 0).unwrap();
        let k2 = mgr.create_thread("P.Threads[1]", "worker", 5).unwrap();

        assert_eq!(mgr.get_live_threads(0).len(), 1);
        assert_eq!(mgr.get_live_threads(5).len(), 2);

        // Kill thread 1
        mgr.get_thread_mut(k1).unwrap().remove(3);
        assert_eq!(mgr.get_live_threads(5).len(), 1);

        // Live by path
        let t = mgr.get_live_thread_by_path(5, "P.Threads[1]");
        assert!(t.is_some());
        assert_eq!(t.unwrap().key, k2);
    }

    #[test]
    fn test_thread_manager_delete() {
        let mut mgr = ThreadManager::new();
        let k = mgr.create_thread("P.Threads[0]", "main", 0).unwrap();
        assert_eq!(mgr.len(), 1);

        let deleted = mgr.delete_thread(k);
        assert!(deleted.is_some());
        assert_eq!(deleted.unwrap().name, "main");
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn test_thread_manager_change_log() {
        let mut mgr = ThreadManager::new();
        mgr.create_thread("P.Threads[0]", "main", 0).unwrap();
        assert_eq!(mgr.change_log().len(), 1);
        assert_eq!(mgr.change_log()[0].event, ThreadChangeEvent::Added);

        mgr.delete_thread(0);
        assert_eq!(mgr.change_log().len(), 2);
        assert_eq!(mgr.change_log()[1].event, ThreadChangeEvent::Deleted);

        mgr.clear_change_log();
        assert_eq!(mgr.change_log().len(), 0);
    }

    #[test]
    fn test_thread_manager_emit_change() {
        let mut mgr = ThreadManager::new();
        let rec = TraceChangeRecord::new(ThreadChangeEvent::Changed, 42)
            .with_key("DisplayName");
        mgr.emit_change(rec);
        assert_eq!(mgr.change_log().len(), 1);
        assert_eq!(mgr.change_log()[0].thread_key, 42);
    }

    #[test]
    fn test_thread_manager_serde() {
        let mut mgr = ThreadManager::new();
        mgr.create_thread("P.Threads[0]", "main", 0).unwrap();
        let json = serde_json::to_string(&mgr).unwrap();
        let back: ThreadManager = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
    }
}
