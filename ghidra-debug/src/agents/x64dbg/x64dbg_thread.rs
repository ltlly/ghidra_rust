//! x64dbg thread representation.
//!
//! Models an x64dbg thread within a debuggee process. Each thread has a
//! thread ID (OS-assigned Windows TID), an execution state, a name,
//! and a stack of frames.
//!
//! This corresponds to the Processes[N].Threads[M] node in the Ghidra trace
//! object tree and maps to `TraceThread` on the model side.
//!
//! Ported from Ghidra's `Debugger-agent-x64dbg` Python commands
//! (`put_threads`, `put_frames`, etc.). x64dbg provides register dumps
//! via `RegDump` structures and stack frames via `_DEBUG_STACK_FRAME`
//! equivalents from the x64dbg_automate library.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::agents::{
    ExecutionState, RegisterValue, StackFrameInfo, ThreadInfo,
};

/// Execution state of an x64dbg thread.
///
/// Maps x64dbg execution status to the common thread state model.
/// x64dbg has a global execution status (not per-thread), so all threads
/// in a process share the same state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum X64DbgThreadState {
    /// Thread is running.
    Running,
    /// Thread is stopped (breakpoint, exception, step).
    Stopped,
    /// Thread has exited.
    Exited,
    /// Thread is not yet started or unknown.
    Inactive,
}

impl X64DbgThreadState {
    /// Convert to the common execution state.
    pub fn to_execution_state(&self) -> ExecutionState {
        match self {
            Self::Running => ExecutionState::Running,
            Self::Stopped => ExecutionState::Stopped,
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
            Self::Inactive => "INACTIVE",
        }
    }

    /// Parse from an x64dbg `X64DbgExecStatus` value.
    ///
    /// Maps the x64dbg execution status (idle, running, paused, breakpoint,
    /// step, exception) to a thread state.
    pub fn from_exec_status(status: super::X64DbgExecStatus) -> Self {
        match status {
            super::X64DbgExecStatus::Idle => Self::Inactive,
            super::X64DbgExecStatus::Running => Self::Running,
            super::X64DbgExecStatus::Paused
            | super::X64DbgExecStatus::Breakpoint
            | super::X64DbgExecStatus::Step
            | super::X64DbgExecStatus::Exception => Self::Stopped,
        }
    }
}

/// An x64dbg thread within a process.
///
/// Each thread in x64dbg has a Windows TID, an execution state, and
/// associated stack frames. Unlike GDB where threads have internal numbers,
/// x64dbg identifies threads by their OS-assigned TID directly.
///
/// x64dbg provides register dumps via `RegDump` structures (containing
/// all general-purpose registers, flags, segment registers, etc.) and
/// stack walk results for frame information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X64DbgThread {
    /// Windows thread ID (OS-assigned TID).
    pub tid: u64,
    /// Thread name, if known.
    pub name: Option<String>,
    /// Current execution state.
    pub state: ExecutionState,
    /// Stack frames, keyed by level (0 = innermost).
    pub frames: BTreeMap<u32, X64DbgStackFrame>,
    /// Whether this thread has been synchronized to the trace.
    pub synced: bool,
    /// The process number this thread belongs to.
    pub process_num: u32,
}

impl X64DbgThread {
    /// Create a new thread with the given TID.
    pub fn new(tid: u64) -> Self {
        Self {
            tid,
            name: None,
            state: ExecutionState::NotStarted,
            frames: BTreeMap::new(),
            synced: false,
            process_num: 0,
        }
    }

    /// Create a thread belonging to a specific process.
    pub fn in_process(tid: u64, process_num: u32) -> Self {
        Self {
            tid,
            process_num,
            ..Self::new(tid)
        }
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

    /// Get the trace object path for this thread.
    ///
    /// Uses `Processes[N].Threads[tid]` format where tid is the Windows TID.
    pub fn trace_path(&self) -> String {
        format!("Processes[{}].Threads[{}]", self.process_num, self.tid)
    }

    /// Get the trace path for this thread's stack container.
    pub fn stack_path(&self) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack",
            self.process_num, self.tid
        )
    }

    /// Add a stack frame to this thread.
    pub fn add_frame(&mut self, frame: X64DbgStackFrame) {
        self.frames.insert(frame.level, frame);
    }

    /// Remove a stack frame by level.
    pub fn remove_frame(&mut self, level: u32) -> Option<X64DbgStackFrame> {
        self.frames.remove(&level)
    }

    /// Clear all frames.
    pub fn clear_frames(&mut self) {
        self.frames.clear();
    }

    /// Get a frame by level.
    pub fn get_frame(&self, level: u32) -> Option<&X64DbgStackFrame> {
        self.frames.get(&level)
    }

    /// Get the innermost frame (level 0).
    pub fn innermost_frame(&self) -> Option<&X64DbgStackFrame> {
        self.frames.get(&0)
    }

    /// Get the number of frames.
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Convert to a `ThreadInfo` for the common agent interface.
    pub fn to_thread_info(&self) -> ThreadInfo {
        ThreadInfo {
            id: self.tid,
            name: self.name.clone(),
            state: self.state,
        }
    }

    /// Build trace object key-value pairs for this thread.
    ///
    /// These are used to populate the `Processes[N].Threads[tid]` node.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let mut values = vec![
            ("_state".to_string(), self.state.as_trace_str().to_string()),
        ];
        if let Some(ref name) = self.name {
            values.push(("_display".to_string(), name.clone()));
        }
        values
    }

    /// Build the short display string for this thread.
    ///
    /// Format: `[process.tid]`
    pub fn build_short_display(&self) -> String {
        match &self.name {
            Some(name) => format!("[{}.{}: {}]", self.process_num, self.tid, name),
            None => format!("[{}.{}]", self.process_num, self.tid),
        }
    }

    /// Mark this thread as synchronized.
    pub fn mark_synced(&mut self) {
        self.synced = true;
    }

    /// Mark the thread as exited.
    ///
    /// Clears all frames and sets the state to Exited.
    pub fn mark_exited(&mut self) {
        self.state = ExecutionState::Exited;
        self.frames.clear();
    }

    /// Whether the thread is alive (running or stopped).
    pub fn is_alive(&self) -> bool {
        matches!(
            self.state,
            ExecutionState::Running | ExecutionState::Stopped
        )
    }
}

/// A stack frame within an x64dbg thread.
///
/// Each frame represents one level of the call stack. Frame 0 is the
/// currently executing function. Frame 1 is its caller, and so on.
///
/// x64dbg provides stack walk results with instruction offset, stack
/// offset, frame offset, and return offset -- equivalent to the
/// `_DEBUG_STACK_FRAME` structure from the Windows debugging API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X64DbgStackFrame {
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
    /// Function name, if known.
    pub function_name: Option<String>,
    /// Register values for this frame.
    #[serde(skip)]
    pub registers: Vec<RegisterValue>,
}

impl X64DbgStackFrame {
    /// Create a new stack frame.
    pub fn new(level: u32, pc: u64) -> Self {
        Self {
            level,
            pc,
            sp: 0,
            fp: 0,
            return_address: 0,
            function_name: None,
            registers: Vec::new(),
        }
    }

    /// Create from stack walk offsets (equivalent to _DEBUG_STACK_FRAME).
    pub fn from_stack_walk(
        level: u32,
        instruction_offset: u64,
        stack_offset: u64,
        frame_offset: u64,
        return_offset: u64,
    ) -> Self {
        Self {
            level,
            pc: instruction_offset,
            sp: stack_offset,
            fp: frame_offset,
            return_address: return_offset,
            function_name: None,
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

    /// Get the trace path for this frame's registers.
    pub fn registers_trace_path(&self, process_num: u32, tid: u64) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}].Registers",
            process_num, tid, self.level
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

    /// Get a register value by name (case-insensitive).
    pub fn get_register(&self, name: &str) -> Option<&RegisterValue> {
        let lower = name.to_lowercase();
        self.registers.iter().find(|r| r.name.to_lowercase() == lower)
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

    #[test]
    fn test_thread_state_from_exec_status() {
        assert_eq!(
            X64DbgThreadState::from_exec_status(super::super::X64DbgExecStatus::Idle),
            X64DbgThreadState::Inactive
        );
        assert_eq!(
            X64DbgThreadState::from_exec_status(super::super::X64DbgExecStatus::Running),
            X64DbgThreadState::Running
        );
        assert_eq!(
            X64DbgThreadState::from_exec_status(super::super::X64DbgExecStatus::Paused),
            X64DbgThreadState::Stopped
        );
        assert_eq!(
            X64DbgThreadState::from_exec_status(super::super::X64DbgExecStatus::Breakpoint),
            X64DbgThreadState::Stopped
        );
        assert_eq!(
            X64DbgThreadState::from_exec_status(super::super::X64DbgExecStatus::Step),
            X64DbgThreadState::Stopped
        );
        assert_eq!(
            X64DbgThreadState::from_exec_status(super::super::X64DbgExecStatus::Exception),
            X64DbgThreadState::Stopped
        );
    }

    #[test]
    fn test_thread_state_to_execution_state() {
        assert_eq!(
            X64DbgThreadState::Running.to_execution_state(),
            ExecutionState::Running
        );
        assert_eq!(
            X64DbgThreadState::Stopped.to_execution_state(),
            ExecutionState::Stopped
        );
        assert_eq!(
            X64DbgThreadState::Exited.to_execution_state(),
            ExecutionState::Exited
        );
        assert_eq!(
            X64DbgThreadState::Inactive.to_execution_state(),
            ExecutionState::NotStarted
        );
    }

    #[test]
    fn test_thread_state_trace_str() {
        assert_eq!(X64DbgThreadState::Running.as_trace_str(), "RUNNING");
        assert_eq!(X64DbgThreadState::Stopped.as_trace_str(), "STOPPED");
        assert_eq!(X64DbgThreadState::Exited.as_trace_str(), "TERMINATED");
        assert_eq!(X64DbgThreadState::Inactive.as_trace_str(), "INACTIVE");
    }

    #[test]
    fn test_thread_new() {
        let t = X64DbgThread::new(0x1234);
        assert_eq!(t.tid, 0x1234);
        assert_eq!(t.name, None);
        assert_eq!(t.state, ExecutionState::NotStarted);
        assert!(t.frames.is_empty());
        assert_eq!(t.process_num, 0);
    }

    #[test]
    fn test_thread_in_process() {
        let t = X64DbgThread::in_process(0x1234, 1);
        assert_eq!(t.tid, 0x1234);
        assert_eq!(t.process_num, 1);
    }

    #[test]
    fn test_thread_builder() {
        let t = X64DbgThread::new(0x1234)
            .with_name("main")
            .with_state(ExecutionState::Running);
        assert_eq!(t.tid, 0x1234);
        assert_eq!(t.name, Some("main".to_string()));
        assert_eq!(t.state, ExecutionState::Running);
    }

    #[test]
    fn test_thread_trace_path() {
        let t = X64DbgThread::in_process(0x1234, 1);
        assert_eq!(t.trace_path(), "Processes[1].Threads[4660]");
        assert_eq!(t.stack_path(), "Processes[1].Threads[4660].Stack");
    }

    #[test]
    fn test_thread_frame_management() {
        let mut t = X64DbgThread::new(100);
        t.add_frame(X64DbgStackFrame::new(0, 0x401000));
        t.add_frame(X64DbgStackFrame::new(1, 0x402000));
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
        let t = X64DbgThread::new(0x5678)
            .with_name("worker")
            .with_state(ExecutionState::Stopped);
        let info = t.to_thread_info();
        assert_eq!(info.id, 0x5678);
        assert_eq!(info.name, Some("worker".to_string()));
        assert_eq!(info.state, ExecutionState::Stopped);
    }

    #[test]
    fn test_thread_build_trace_values() {
        let t = X64DbgThread::new(100)
            .with_name("main")
            .with_state(ExecutionState::Stopped);
        let values = t.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "_state" && v == "STOPPED"));
        assert!(values.iter().any(|(k, v)| k == "_display" && v == "main"));
    }

    #[test]
    fn test_thread_build_short_display() {
        let t = X64DbgThread::in_process(0x1234, 0).with_name("main");
        assert_eq!(t.build_short_display(), "[0.4660: main]");

        let t = X64DbgThread::in_process(0x1234, 0);
        assert_eq!(t.build_short_display(), "[0.4660]");
    }

    #[test]
    fn test_thread_exit() {
        let mut t = X64DbgThread::new(100).with_state(ExecutionState::Running);
        t.add_frame(X64DbgStackFrame::new(0, 0x401000));
        assert!(t.is_alive());

        t.mark_exited();
        assert!(!t.is_alive());
        assert_eq!(t.state, ExecutionState::Exited);
        assert!(t.frames.is_empty());
    }

    #[test]
    fn test_stack_frame_new() {
        let f = X64DbgStackFrame::new(0, 0x401000);
        assert_eq!(f.level, 0);
        assert_eq!(f.pc, 0x401000);
        assert_eq!(f.sp, 0);
        assert!(f.function_name.is_none());
    }

    #[test]
    fn test_stack_frame_from_stack_walk() {
        let f = X64DbgStackFrame::from_stack_walk(
            0,
            0x7ff612345678, // instruction_offset
            0x00abcdef,     // stack_offset
            0x00abcdef00,   // frame_offset
            0x7ff61234abcd, // return_offset
        );
        assert_eq!(f.pc, 0x7ff612345678);
        assert_eq!(f.sp, 0x00abcdef);
        assert_eq!(f.fp, 0x00abcdef00);
        assert_eq!(f.return_address, 0x7ff61234abcd);
    }

    #[test]
    fn test_stack_frame_builder() {
        let f = X64DbgStackFrame::new(0, 0x401000)
            .with_sp(0x7fff00)
            .with_fp(0x7fff10)
            .with_return_address(0x401100)
            .with_function("main");
        assert_eq!(f.sp, 0x7fff00);
        assert_eq!(f.fp, 0x7fff10);
        assert_eq!(f.return_address, 0x401100);
        assert_eq!(f.function_name.as_deref(), Some("main"));
    }

    #[test]
    fn test_stack_frame_display() {
        let f = X64DbgStackFrame::new(0, 0x401000).with_function("main");
        assert_eq!(f.build_display(), "#0 0x401000 main");

        let f = X64DbgStackFrame::new(1, 0x402000);
        assert_eq!(f.build_display(), "#1 0x402000");
    }

    #[test]
    fn test_stack_frame_to_info() {
        let f = X64DbgStackFrame::new(0, 0x401000)
            .with_sp(0x7fff00)
            .with_function("main");
        let info = f.to_stack_frame_info();
        assert_eq!(info.level, 0);
        assert_eq!(info.pc, 0x401000);
        assert_eq!(info.sp, 0x7fff00);
        assert_eq!(info.function_name.as_deref(), Some("main"));
    }

    #[test]
    fn test_stack_frame_registers_case_insensitive() {
        let mut f = X64DbgStackFrame::new(0, 0x401000);
        f.set_register(RegisterValue::from_u64("RAX", 0x1234));
        f.set_register(RegisterValue::from_u64("rbx", 0x5678));

        // Case-insensitive lookup
        assert!(f.get_register("rax").is_some());
        assert!(f.get_register("RAX").is_some());
        assert!(f.get_register("Rax").is_some());
        assert_eq!(f.get_register("rax").unwrap().as_u64(), Some(0x1234));
        assert!(f.get_register("rcx").is_none());

        let names = f.register_names();
        assert_eq!(names.len(), 2);

        f.clear_registers();
        assert!(f.register_names().is_empty());
    }

    #[test]
    fn test_stack_frame_registers_trace_path() {
        let f = X64DbgStackFrame::new(2, 0x401000);
        assert_eq!(
            f.registers_trace_path(1, 0x1234),
            "Processes[1].Threads[4660].Stack[2].Registers"
        );
    }
}
