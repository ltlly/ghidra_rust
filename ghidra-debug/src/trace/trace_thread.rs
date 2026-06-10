//! TraceThread -- enhanced thread representation for the debug trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.thread.TraceThread` and
//! `ghidra.trace.database.thread.DBTraceThread`.
//!
//! This module provides a richer thread type than the basic `model::thread::TraceThread`,
//! with support for execution state history, register snapshots, and stack frames.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::model::TraceExecutionState;

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
    /// The thread name.
    pub name: String,
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
            comment: None,
            lifespan: Lifespan::now_on(snap),
            execution_state: TraceExecutionState::Unknown,
            execution_state_snap: snap,
            state_history: Vec::new(),
            register_snapshots: BTreeMap::new(),
            stack_snapshots: BTreeMap::new(),
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
}
