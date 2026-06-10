//! GDB thread representation.
//!
//! Models a GDB thread within an inferior. Each thread has a thread
//! number (GDB-internal), a TID (OS-assigned), an execution state,
//! a name, and a stack of frames.
//!
//! This corresponds to the Inferiors[N].Threads[M] node in the Ghidra
//! trace object tree and maps to `TraceThread` on the model side.
//!
//! Ported from Ghidra's `Debugger-agent-gdb` Python commands (`put_threads`,
//! `put_frames`, `convert_state`, `convert_tid`, etc.).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::agents::{
    ExecutionState, RegisterValue, StackFrameInfo, ThreadInfo,
};

/// Execution state of a GDB thread.
///
/// This extends the common `ExecutionState` with GDB-specific states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GdbThreadState {
    /// Thread is running.
    Running,
    /// Thread is stopped (breakpoint, signal, step).
    Stopped,
    /// Thread has exited.
    Exited,
    /// Thread is not yet started or unknown.
    Inactive,
}

impl GdbThreadState {
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

    /// Parse from GDB thread state booleans.
    ///
    /// GDB Python API provides `is_running()`, `is_stopped()`, `is_exited()`.
    pub fn from_gdb_state(is_running: bool, is_stopped: bool, is_exited: bool) -> Self {
        if is_exited {
            Self::Exited
        } else if is_running {
            Self::Running
        } else if is_stopped {
            Self::Stopped
        } else {
            Self::Inactive
        }
    }
}

/// A GDB thread within an inferior.
///
/// Each thread in GDB has a GDB-internal number (used in thread listings),
/// an OS-level TID (the `ptid` tuple's thread ID component), and
/// associated stack frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdbThread {
    /// GDB thread number (1-based, internal to GDB).
    pub num: u32,
    /// OS-level thread ID (from `ptid`).
    pub tid: Option<i64>,
    /// Thread name, if known.
    pub name: Option<String>,
    /// Current execution state.
    pub state: ExecutionState,
    /// Stack frames, keyed by level (0 = innermost).
    pub frames: BTreeMap<u32, GdbStackFrame>,
    /// Whether this thread has been synchronized to the trace.
    pub synced: bool,
    /// The inferior number this thread belongs to.
    pub inferior_num: u32,
}

impl GdbThread {
    /// Create a new thread.
    pub fn new(num: u32) -> Self {
        Self {
            num,
            tid: None,
            name: None,
            state: ExecutionState::NotStarted,
            frames: BTreeMap::new(),
            synced: false,
            inferior_num: 1,
        }
    }

    /// Create a thread belonging to a specific inferior.
    pub fn in_inferior(num: u32, inferior_num: u32) -> Self {
        Self {
            num,
            inferior_num,
            ..Self::new(num)
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

    /// Get the trace object path for this thread.
    pub fn trace_path(&self) -> String {
        format!("Inferiors[{}].Threads[{}]", self.inferior_num, self.num)
    }

    /// Get the trace path for this thread's stack container.
    pub fn stack_path(&self) -> String {
        format!(
            "Inferiors[{}].Threads[{}].Stack",
            self.inferior_num, self.num
        )
    }

    /// Convert a GDB `ptid` tuple (pid, lwp, tid) to a single TID.
    ///
    /// In GDB's Python API, `thread.ptid` is a tuple `(pid, lwp, tid)`.
    /// If `lwp` is 0, the `tid` is used; otherwise `lwp` is used.
    /// This matches the `convert_tid` function in the Python agent.
    pub fn convert_ptid(_pid: i64, lwp: i64, tid: i64) -> i64 {
        if lwp == 0 {
            tid
        } else {
            lwp
        }
    }

    /// Add a stack frame to this thread.
    pub fn add_frame(&mut self, frame: GdbStackFrame) {
        self.frames.insert(frame.level, frame);
    }

    /// Remove a stack frame by level.
    pub fn remove_frame(&mut self, level: u32) -> Option<GdbStackFrame> {
        self.frames.remove(&level)
    }

    /// Clear all frames.
    pub fn clear_frames(&mut self) {
        self.frames.clear();
    }

    /// Get a frame by level.
    pub fn get_frame(&self, level: u32) -> Option<&GdbStackFrame> {
        self.frames.get(&level)
    }

    /// Get the innermost frame (level 0).
    pub fn innermost_frame(&self) -> Option<&GdbStackFrame> {
        self.frames.get(&0)
    }

    /// Get the number of frames.
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Convert to a `ThreadInfo` for the common agent interface.
    pub fn to_thread_info(&self) -> ThreadInfo {
        ThreadInfo {
            id: self.num as u64,
            name: self.name.clone(),
            state: self.state,
        }
    }

    /// Build trace object key-value pairs for this thread.
    ///
    /// These are used to populate the `Inferiors[N].Threads[M]` node.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let mut values = vec![
            ("State".to_string(), self.state.as_trace_str().to_string()),
        ];
        if let Some(ref name) = self.name {
            values.push(("Name".to_string(), name.clone()));
        }
        if let Some(tid) = self.tid {
            values.push(("TID".to_string(), tid.to_string()));
        }
        values
    }

    /// Build the short display string for this thread.
    ///
    /// Format: `[inferior.thread:tid]`
    pub fn build_short_display(&self, radix: u32) -> String {
        let tid = self.tid.unwrap_or(0);
        let tid_str = match radix {
            16 => format!("0x{:x}", tid),
            8 => format!("0{:o}", tid),
            _ => format!("{}", tid),
        };
        format!("[{}.{}:{}]", self.inferior_num, self.num, tid_str)
    }

    /// Mark this thread as synchronized.
    pub fn mark_synced(&mut self) {
        self.synced = true;
    }

    /// Mark the thread as exited.
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

/// A stack frame within a GDB thread.
///
/// Each frame represents one level of the call stack. Frame 0 is the
/// currently executing function. Frame 1 is its caller, and so on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdbStackFrame {
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

impl GdbStackFrame {
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
    pub fn registers_trace_path(&self, inferior_num: u32, thread_num: u32) -> String {
        format!(
            "Inferiors[{}].Threads[{}].Stack[{}].Registers",
            inferior_num, thread_num, self.level
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

    #[test]
    fn test_gdb_thread_state() {
        assert_eq!(
            GdbThreadState::from_gdb_state(true, false, false),
            GdbThreadState::Running
        );
        assert_eq!(
            GdbThreadState::from_gdb_state(false, true, false),
            GdbThreadState::Stopped
        );
        assert_eq!(
            GdbThreadState::from_gdb_state(false, false, true),
            GdbThreadState::Exited
        );
        assert_eq!(
            GdbThreadState::from_gdb_state(false, false, false),
            GdbThreadState::Inactive
        );
    }

    #[test]
    fn test_gdb_thread_state_to_execution_state() {
        assert_eq!(
            GdbThreadState::Running.to_execution_state(),
            ExecutionState::Running
        );
        assert_eq!(
            GdbThreadState::Stopped.to_execution_state(),
            ExecutionState::Stopped
        );
    }

    #[test]
    fn test_gdb_thread_state_trace_str() {
        assert_eq!(GdbThreadState::Running.as_trace_str(), "RUNNING");
        assert_eq!(GdbThreadState::Stopped.as_trace_str(), "STOPPED");
        assert_eq!(GdbThreadState::Exited.as_trace_str(), "TERMINATED");
        assert_eq!(GdbThreadState::Inactive.as_trace_str(), "INACTIVE");
    }

    #[test]
    fn test_thread_new() {
        let t = GdbThread::new(1);
        assert_eq!(t.num, 1);
        assert_eq!(t.tid, None);
        assert_eq!(t.name, None);
        assert_eq!(t.state, ExecutionState::NotStarted);
        assert!(t.frames.is_empty());
        assert_eq!(t.inferior_num, 1);
    }

    #[test]
    fn test_thread_in_inferior() {
        let t = GdbThread::in_inferior(2, 3);
        assert_eq!(t.num, 2);
        assert_eq!(t.inferior_num, 3);
    }

    #[test]
    fn test_thread_builder() {
        let t = GdbThread::new(1)
            .with_tid(1234)
            .with_name("main")
            .with_state(ExecutionState::Running);
        assert_eq!(t.tid, Some(1234));
        assert_eq!(t.name, Some("main".to_string()));
        assert_eq!(t.state, ExecutionState::Running);
    }

    #[test]
    fn test_thread_trace_path() {
        let t = GdbThread::in_inferior(2, 1);
        assert_eq!(t.trace_path(), "Inferiors[1].Threads[2]");
        assert_eq!(t.stack_path(), "Inferiors[1].Threads[2].Stack");
    }

    #[test]
    fn test_convert_ptid() {
        assert_eq!(GdbThread::convert_ptid(100, 0, 200), 200);
        assert_eq!(GdbThread::convert_ptid(100, 300, 200), 300);
        assert_eq!(GdbThread::convert_ptid(100, 0, 0), 0);
    }

    #[test]
    fn test_thread_frame_management() {
        let mut t = GdbThread::new(1);
        t.add_frame(GdbStackFrame::new(0, 0x401000));
        t.add_frame(GdbStackFrame::new(1, 0x402000));
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
        let t = GdbThread::new(5)
            .with_name("worker")
            .with_state(ExecutionState::Stopped);
        let info = t.to_thread_info();
        assert_eq!(info.id, 5);
        assert_eq!(info.name, Some("worker".to_string()));
        assert_eq!(info.state, ExecutionState::Stopped);
    }

    #[test]
    fn test_thread_build_trace_values() {
        let t = GdbThread::new(1)
            .with_tid(42)
            .with_name("main")
            .with_state(ExecutionState::Stopped);
        let values = t.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "State" && v == "STOPPED"));
        assert!(values.iter().any(|(k, v)| k == "Name" && v == "main"));
        assert!(values.iter().any(|(k, v)| k == "TID" && v == "42"));
    }

    #[test]
    fn test_thread_build_short_display() {
        let t = GdbThread::in_inferior(1, 1).with_tid(0x1234);
        assert_eq!(t.build_short_display(16), "[1.1:0x1234]");
        assert_eq!(t.build_short_display(10), "[1.1:4660]");
    }

    #[test]
    fn test_thread_exit() {
        let mut t = GdbThread::new(1).with_state(ExecutionState::Running);
        t.add_frame(GdbStackFrame::new(0, 0x401000));
        assert!(t.is_alive());

        t.mark_exited();
        assert!(!t.is_alive());
        assert_eq!(t.state, ExecutionState::Exited);
        assert!(t.frames.is_empty());
    }

    #[test]
    fn test_stack_frame_new() {
        let f = GdbStackFrame::new(0, 0x401000);
        assert_eq!(f.level, 0);
        assert_eq!(f.pc, 0x401000);
        assert_eq!(f.sp, 0);
        assert!(f.function_name.is_none());
    }

    #[test]
    fn test_stack_frame_builder() {
        let f = GdbStackFrame::new(0, 0x401000)
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
        let f = GdbStackFrame::new(0, 0x401000).with_function("main");
        assert_eq!(f.build_display(), "#0 0x401000 main");

        let f = GdbStackFrame::new(1, 0x402000);
        assert_eq!(f.build_display(), "#1 0x402000");
    }

    #[test]
    fn test_stack_frame_to_info() {
        let f = GdbStackFrame::new(0, 0x401000)
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
        let mut f = GdbStackFrame::new(0, 0x401000);
        f.set_register(RegisterValue::from_u64("rax", 0x1234));
        f.set_register(RegisterValue::from_u64("rbx", 0x5678));

        assert!(f.get_register("rax").is_some());
        assert_eq!(f.get_register("rax").unwrap().as_u64(), Some(0x1234));
        assert!(f.get_register("rcx").is_none());

        let names = f.register_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"rax"));
        assert!(names.contains(&"rbx"));

        f.clear_registers();
        assert!(f.register_names().is_empty());
    }

    #[test]
    fn test_stack_frame_registers_trace_path() {
        let f = GdbStackFrame::new(2, 0x401000);
        assert_eq!(
            f.registers_trace_path(1, 3),
            "Inferiors[1].Threads[3].Stack[2].Registers"
        );
    }
}
