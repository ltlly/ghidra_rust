//! LLDB thread representation.
//!
//! Models an LLDB thread (SBThread) within a process. Each thread has an
//! LLDB-internal index (used in thread listings), a TID (OS-assigned), an
//! execution state, a name, and a stack of frames.
//!
//! This corresponds to the Processes[N].Threads[M] node in the Ghidra
//! trace object tree and maps to `TraceThread` on the model side.
//!
//! Ported from Ghidra's `Debugger-agent-lldb` Python commands (`put_threads`,
//! `put_frames`, etc.) and the LLDB `SBThread` / `SBFrame` APIs.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::agents::{
    ExecutionState, RegisterValue, StackFrameInfo, ThreadInfo,
};

/// Execution state of an LLDB thread.
///
/// This extends the common `ExecutionState` with LLDB-specific states.
/// LLDB's Python API provides `SBThread.GetState()` which returns one
/// of the eState* values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LldbThreadState {
    /// Thread is running.
    Running,
    /// Thread is stopped (breakpoint, signal, step).
    Stopped,
    /// Thread has exited.
    Exited,
    /// Thread is suspended (LLDB-specific: thread is stopped but will
    /// not resume when the process continues).
    Suspended,
    /// Thread is not yet started or unknown.
    Inactive,
}

impl LldbThreadState {
    /// Convert to the common execution state.
    pub fn to_execution_state(&self) -> ExecutionState {
        match self {
            Self::Running => ExecutionState::Running,
            Self::Stopped | Self::Suspended => ExecutionState::Stopped,
            Self::Exited => ExecutionState::Exited,
            Self::Inactive => ExecutionState::NotStarted,
        }
    }

    /// Convert to the trace string representation.
    pub fn as_trace_str(&self) -> &'static str {
        match self {
            Self::Running => "RUNNING",
            Self::Stopped => "STOPPED",
            Self::Exited => "TERMINATED",
            Self::Suspended => "SUSPENDED",
            Self::Inactive => "INACTIVE",
        }
    }

    /// Parse from LLDB state booleans.
    ///
    /// LLDB Python API provides `SBThread.GetState()` which returns
    /// `eStateRunning`, `eStateStopped`, `eStateExited`, `eStateSuspended`.
    pub fn from_lldb_state(
        is_running: bool,
        is_stopped: bool,
        is_exited: bool,
        is_suspended: bool,
    ) -> Self {
        if is_exited {
            Self::Exited
        } else if is_running {
            Self::Running
        } else if is_suspended {
            Self::Suspended
        } else if is_stopped {
            Self::Stopped
        } else {
            Self::Inactive
        }
    }

    /// Parse from an LLDB state name string (e.g. "running", "stopped").
    pub fn from_lldb_state_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "running" => Self::Running,
            "stopped" => Self::Stopped,
            "exited" => Self::Exited,
            "suspended" => Self::Suspended,
            "invalid" | "unloaded" => Self::Inactive,
            _ => Self::Inactive,
        }
    }
}

/// An LLDB thread within a process.
///
/// Each thread in LLDB has an index (0-based, used in the SBTarget thread
/// list), a TID (OS-assigned, from `SBThread.GetThreadID()`), and
/// associated stack frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbThread {
    /// LLDB thread index (0-based in the process's thread list).
    pub index: u32,
    /// OS-level thread ID (from `SBThread.GetThreadID()`).
    pub tid: Option<i64>,
    /// Thread name, if known (from `SBThread.GetName()`).
    pub name: Option<String>,
    /// Current execution state.
    pub state: ExecutionState,
    /// Stack frames, keyed by level (0 = innermost).
    pub frames: BTreeMap<u32, LldbStackFrame>,
    /// Whether this thread has been synchronized to the trace.
    pub synced: bool,
    /// The process index this thread belongs to.
    pub process_index: u32,
    /// The stop reason for this thread, if any.
    pub stop_reason: Option<super::LldbStopReason>,
    /// Queue name (GCD/com.apple thread naming, from `SBThread.GetQueueName()`).
    pub queue_name: Option<String>,
}

impl LldbThread {
    /// Create a new thread.
    pub fn new(index: u32, process_index: u32) -> Self {
        Self {
            index,
            tid: None,
            name: None,
            state: ExecutionState::NotStarted,
            frames: BTreeMap::new(),
            synced: false,
            process_index,
            stop_reason: None,
            queue_name: None,
        }
    }

    /// Set the OS thread ID.
    pub fn with_tid(mut self, tid: i64) -> Self {
        self.tid = Some(tid);
        self
    }

    /// Set the thread name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the execution state.
    pub fn with_state(mut self, state: ExecutionState) -> Self {
        self.state = state;
        self
    }

    /// Set the stop reason.
    pub fn with_stop_reason(mut self, reason: super::LldbStopReason) -> Self {
        self.stop_reason = Some(reason);
        self
    }

    /// Set the queue name.
    pub fn with_queue_name(mut self, name: impl Into<String>) -> Self {
        self.queue_name = Some(name.into());
        self
    }

    /// Get the trace object path for this thread.
    pub fn trace_path(&self) -> String {
        format!(
            "Processes[{}].Threads[{}]",
            self.process_index, self.index
        )
    }

    /// Get the trace path for this thread's stack container.
    pub fn stack_path(&self) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack",
            self.process_index, self.index
        )
    }

    /// Add a stack frame to this thread.
    pub fn add_frame(&mut self, frame: LldbStackFrame) {
        self.frames.insert(frame.level, frame);
    }

    /// Remove a stack frame by level.
    pub fn remove_frame(&mut self, level: u32) -> Option<LldbStackFrame> {
        self.frames.remove(&level)
    }

    /// Clear all frames.
    pub fn clear_frames(&mut self) {
        self.frames.clear();
    }

    /// Get a frame by level.
    pub fn get_frame(&self, level: u32) -> Option<&LldbStackFrame> {
        self.frames.get(&level)
    }

    /// Get a mutable reference to a frame by level.
    pub fn get_frame_mut(&mut self, level: u32) -> Option<&mut LldbStackFrame> {
        self.frames.get_mut(&level)
    }

    /// Get the innermost frame (level 0).
    pub fn innermost_frame(&self) -> Option<&LldbStackFrame> {
        self.frames.get(&0)
    }

    /// Get the number of frames.
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Convert to a `ThreadInfo` for the common agent interface.
    pub fn to_thread_info(&self) -> ThreadInfo {
        ThreadInfo {
            id: self.tid.unwrap_or(self.index as i64) as u64,
            name: self.name.clone(),
            state: self.state,
        }
    }

    /// Build trace object key-value pairs for this thread.
    ///
    /// These are used to populate the `Processes[N].Threads[M]` node.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let mut values = vec![
            ("_state".to_string(), self.state.as_trace_str().to_string()),
        ];
        if let Some(ref name) = self.name {
            values.push(("_display".to_string(), name.clone()));
        }
        if let Some(tid) = self.tid {
            values.push(("TID".to_string(), tid.to_string()));
        }
        if let Some(ref queue) = self.queue_name {
            values.push(("Queue".to_string(), queue.clone()));
        }
        values
    }

    /// Build the short display string for this thread.
    ///
    /// Format: `[process.thread:tid]`
    pub fn build_short_display(&self, radix: u32) -> String {
        let tid = self.tid.unwrap_or(0);
        let tid_str = match radix {
            16 => format!("0x{:x}", tid),
            8 => format!("0{:o}", tid),
            _ => format!("{}", tid),
        };
        format!("[{}.{}:{}]", self.process_index, self.index, tid_str)
    }

    /// Mark this thread as synchronized.
    pub fn mark_synced(&mut self) {
        self.synced = true;
    }

    /// Mark the thread as exited.
    pub fn mark_exited(&mut self) {
        self.state = ExecutionState::Exited;
        self.frames.clear();
        self.stop_reason = None;
    }

    /// Whether the thread is alive (running or stopped).
    pub fn is_alive(&self) -> bool {
        matches!(
            self.state,
            ExecutionState::Running | ExecutionState::Stopped
        )
    }
}

/// A stack frame within an LLDB thread.
///
/// Each frame represents one level of the call stack. Frame 0 is the
/// currently executing function. Frame 1 is its caller, and so on.
/// This maps to the LLDB `SBFrame` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbStackFrame {
    /// Frame level (0 = innermost / currently executing).
    pub level: u32,
    /// Program counter (instruction pointer) address.
    pub pc: u64,
    /// Stack pointer address.
    pub sp: u64,
    /// Frame pointer address.
    pub fp: u64,
    /// Return address (where the caller will resume).
    pub return_address: u64,
    /// Function name, if known (from `SBFrame.GetFunctionName()`).
    pub function_name: Option<String>,
    /// Module name containing this frame's PC (from `SBFrame.GetModule()`).
    pub module_name: Option<String>,
    /// Symbol name, if known (from `SBFrame.GetSymbol().GetName()`).
    pub symbol_name: Option<String>,
    /// Register values for this frame.
    #[serde(skip)]
    pub registers: Vec<RegisterValue>,
}

impl LldbStackFrame {
    /// Create a new stack frame.
    pub fn new(level: u32, pc: u64) -> Self {
        Self {
            level,
            pc,
            sp: 0,
            fp: 0,
            return_address: 0,
            function_name: None,
            module_name: None,
            symbol_name: None,
            registers: Vec::new(),
        }
    }

    /// Set the stack pointer.
    pub fn with_sp(mut self, sp: u64) -> Self {
        self.sp = sp;
        self
    }

    /// Set the frame pointer.
    pub fn with_fp(mut self, fp: u64) -> Self {
        self.fp = fp;
        self
    }

    /// Set the return address.
    pub fn with_return_address(mut self, ra: u64) -> Self {
        self.return_address = ra;
        self
    }

    /// Set the function name.
    pub fn with_function(mut self, name: impl Into<String>) -> Self {
        self.function_name = Some(name.into());
        self
    }

    /// Set the module name.
    pub fn with_module(mut self, name: impl Into<String>) -> Self {
        self.module_name = Some(name.into());
        self
    }

    /// Set the symbol name.
    pub fn with_symbol(mut self, name: impl Into<String>) -> Self {
        self.symbol_name = Some(name.into());
        self
    }

    /// Get the trace path for this frame's registers.
    pub fn registers_trace_path(&self, process_index: u32, thread_index: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}].Registers",
            process_index, thread_index, self.level
        )
    }

    /// Convert to a `StackFrameInfo` for the common agent interface.
    pub fn to_stack_frame_info(&self) -> StackFrameInfo {
        StackFrameInfo {
            level: self.level,
            pc: self.pc,
            sp: self.sp,
            fp: self.fp,
            return_address: self.return_address,
            function_name: self.function_name.clone(),
        }
    }

    /// Build the display string for this frame.
    ///
    /// Format: `#level 0xpc function_name`
    pub fn build_display(&self) -> String {
        match &self.function_name {
            Some(name) => format!("#{} 0x{:x} {}", self.level, self.pc, name),
            None => format!("#{} 0x{:x}", self.level, self.pc),
        }
    }

    /// Set a register value. Replaces if same name exists.
    pub fn set_register(&mut self, reg: RegisterValue) {
        self.registers.retain(|r| r.name != reg.name);
        self.registers.push(reg);
    }

    /// Get a register value by name.
    pub fn get_register(&self, name: &str) -> Option<&RegisterValue> {
        self.registers.iter().find(|r| r.name == name)
    }

    /// Get all register names.
    pub fn register_names(&self) -> Vec<&str> {
        self.registers.iter().map(|r| r.name.as_str()).collect()
    }

    /// Clear all register values.
    pub fn clear_registers(&mut self) {
        self.registers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::lldb::LldbStopReason;

    #[test]
    fn test_thread_state() {
        assert_eq!(
            LldbThreadState::from_lldb_state(true, false, false, false),
            LldbThreadState::Running
        );
        assert_eq!(
            LldbThreadState::from_lldb_state(false, true, false, false),
            LldbThreadState::Stopped
        );
        assert_eq!(
            LldbThreadState::from_lldb_state(false, false, true, false),
            LldbThreadState::Exited
        );
        assert_eq!(
            LldbThreadState::from_lldb_state(false, false, false, true),
            LldbThreadState::Suspended
        );
        assert_eq!(
            LldbThreadState::from_lldb_state(false, false, false, false),
            LldbThreadState::Inactive
        );
    }

    #[test]
    fn test_thread_state_to_execution_state() {
        assert_eq!(
            LldbThreadState::Running.to_execution_state(),
            ExecutionState::Running
        );
        assert_eq!(
            LldbThreadState::Stopped.to_execution_state(),
            ExecutionState::Stopped
        );
        assert_eq!(
            LldbThreadState::Suspended.to_execution_state(),
            ExecutionState::Stopped
        );
    }

    #[test]
    fn test_thread_state_trace_str() {
        assert_eq!(LldbThreadState::Running.as_trace_str(), "RUNNING");
        assert_eq!(LldbThreadState::Stopped.as_trace_str(), "STOPPED");
        assert_eq!(LldbThreadState::Exited.as_trace_str(), "TERMINATED");
        assert_eq!(LldbThreadState::Suspended.as_trace_str(), "SUSPENDED");
        assert_eq!(LldbThreadState::Inactive.as_trace_str(), "INACTIVE");
    }

    #[test]
    fn test_thread_state_from_name() {
        assert_eq!(
            LldbThreadState::from_lldb_state_name("running"),
            LldbThreadState::Running
        );
        assert_eq!(
            LldbThreadState::from_lldb_state_name("Stopped"),
            LldbThreadState::Stopped
        );
        assert_eq!(
            LldbThreadState::from_lldb_state_name("suspended"),
            LldbThreadState::Suspended
        );
        assert_eq!(
            LldbThreadState::from_lldb_state_name("exited"),
            LldbThreadState::Exited
        );
        assert_eq!(
            LldbThreadState::from_lldb_state_name("invalid"),
            LldbThreadState::Inactive
        );
    }

    #[test]
    fn test_thread_new() {
        let t = LldbThread::new(1, 0);
        assert_eq!(t.index, 1);
        assert_eq!(t.tid, None);
        assert_eq!(t.name, None);
        assert_eq!(t.state, ExecutionState::NotStarted);
        assert!(t.frames.is_empty());
        assert_eq!(t.process_index, 0);
        assert!(t.stop_reason.is_none());
        assert!(t.queue_name.is_none());
    }

    #[test]
    fn test_thread_builder() {
        let t = LldbThread::new(1, 0)
            .with_tid(1234)
            .with_name("main")
            .with_state(ExecutionState::Running)
            .with_stop_reason(LldbStopReason::Breakpoint)
            .with_queue_name("com.apple.main-thread");
        assert_eq!(t.tid, Some(1234));
        assert_eq!(t.name, Some("main".to_string()));
        assert_eq!(t.state, ExecutionState::Running);
        assert_eq!(t.stop_reason, Some(LldbStopReason::Breakpoint));
        assert_eq!(t.queue_name.as_deref(), Some("com.apple.main-thread"));
    }

    #[test]
    fn test_thread_trace_path() {
        let t = LldbThread::new(2, 1);
        assert_eq!(t.trace_path(), "Processes[1].Threads[2]");
        assert_eq!(t.stack_path(), "Processes[1].Threads[2].Stack");
    }

    #[test]
    fn test_thread_frame_management() {
        let mut t = LldbThread::new(1, 0);
        t.add_frame(LldbStackFrame::new(0, 0x401000));
        t.add_frame(LldbStackFrame::new(1, 0x402000));
        assert_eq!(t.frame_count(), 2);
        assert!(t.innermost_frame().is_some());
        assert_eq!(t.innermost_frame().unwrap().pc, 0x401000);

        let removed = t.remove_frame(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().pc, 0x402000);
        assert_eq!(t.frame_count(), 1);

        t.clear_frames();
        assert_eq!(t.frame_count(), 0);
    }

    #[test]
    fn test_thread_to_thread_info() {
        let t = LldbThread::new(5, 0)
            .with_tid(42)
            .with_name("worker")
            .with_state(ExecutionState::Stopped);
        let info = t.to_thread_info();
        assert_eq!(info.id, 42);
        assert_eq!(info.name, Some("worker".to_string()));
        assert_eq!(info.state, ExecutionState::Stopped);
    }

    #[test]
    fn test_thread_to_thread_info_no_tid() {
        let t = LldbThread::new(3, 0).with_state(ExecutionState::Running);
        let info = t.to_thread_info();
        assert_eq!(info.id, 3); // Falls back to index
    }

    #[test]
    fn test_thread_build_trace_values() {
        let t = LldbThread::new(1, 0)
            .with_tid(42)
            .with_name("main")
            .with_state(ExecutionState::Stopped)
            .with_queue_name("com.apple.main-thread");
        let values = t.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "_state" && v == "STOPPED"));
        assert!(values.iter().any(|(k, v)| k == "_display" && v == "main"));
        assert!(values.iter().any(|(k, v)| k == "TID" && v == "42"));
        assert!(values.iter().any(|(k, v)| k == "Queue" && v == "com.apple.main-thread"));
    }

    #[test]
    fn test_thread_build_short_display() {
        let t = LldbThread::new(1, 0).with_tid(0x1234);
        assert_eq!(t.build_short_display(16), "[0.1:0x1234]");
        assert_eq!(t.build_short_display(10), "[0.1:4660]");
    }

    #[test]
    fn test_thread_exit() {
        let mut t = LldbThread::new(1, 0).with_state(ExecutionState::Running);
        t.add_frame(LldbStackFrame::new(0, 0x401000));
        t.stop_reason = Some(LldbStopReason::Breakpoint);
        assert!(t.is_alive());

        t.mark_exited();
        assert!(!t.is_alive());
        assert_eq!(t.state, ExecutionState::Exited);
        assert!(t.frames.is_empty());
        assert!(t.stop_reason.is_none());
    }

    #[test]
    fn test_thread_mark_synced() {
        let mut t = LldbThread::new(1, 0);
        assert!(!t.synced);
        t.mark_synced();
        assert!(t.synced);
    }

    #[test]
    fn test_stack_frame_new() {
        let f = LldbStackFrame::new(0, 0x401000);
        assert_eq!(f.level, 0);
        assert_eq!(f.pc, 0x401000);
        assert_eq!(f.sp, 0);
        assert!(f.function_name.is_none());
        assert!(f.module_name.is_none());
        assert!(f.symbol_name.is_none());
    }

    #[test]
    fn test_stack_frame_builder() {
        let f = LldbStackFrame::new(0, 0x401000)
            .with_sp(0x7fff00)
            .with_fp(0x7fff10)
            .with_return_address(0x401100)
            .with_function("main")
            .with_module("a.out")
            .with_symbol("main");
        assert_eq!(f.sp, 0x7fff00);
        assert_eq!(f.fp, 0x7fff10);
        assert_eq!(f.return_address, 0x401100);
        assert_eq!(f.function_name.as_deref(), Some("main"));
        assert_eq!(f.module_name.as_deref(), Some("a.out"));
        assert_eq!(f.symbol_name.as_deref(), Some("main"));
    }

    #[test]
    fn test_stack_frame_display() {
        let f = LldbStackFrame::new(0, 0x401000).with_function("main");
        assert_eq!(f.build_display(), "#0 0x401000 main");

        let f = LldbStackFrame::new(1, 0x402000);
        assert_eq!(f.build_display(), "#1 0x402000");
    }

    #[test]
    fn test_stack_frame_to_info() {
        let f = LldbStackFrame::new(0, 0x401000)
            .with_sp(0x7fff00)
            .with_function("main");
        let info = f.to_stack_frame_info();
        assert_eq!(info.level, 0);
        assert_eq!(info.pc, 0x401000);
        assert_eq!(info.sp, 0x7fff00);
        assert_eq!(info.function_name.as_deref(), Some("main"));
    }

    #[test]
    fn test_stack_frame_registers() {
        let mut f = LldbStackFrame::new(0, 0x401000);
        f.set_register(RegisterValue::from_u64("x0", 0x1234));
        f.set_register(RegisterValue::from_u64("x1", 0x5678));

        assert!(f.get_register("x0").is_some());
        assert_eq!(f.get_register("x0").unwrap().as_u64(), Some(0x1234));
        assert!(f.get_register("x2").is_none());

        let names = f.register_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"x0"));
        assert!(names.contains(&"x1"));

        f.clear_registers();
        assert!(f.register_names().is_empty());
    }

    #[test]
    fn test_stack_frame_registers_trace_path() {
        let f = LldbStackFrame::new(2, 0x401000);
        assert_eq!(
            f.registers_trace_path(1, 3),
            "Processes[1].Threads[3].Stack[2].Registers"
        );
    }
}
