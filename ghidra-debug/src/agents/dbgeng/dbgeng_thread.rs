//! Dbgeng thread representation.
//!
//! Models a Windows Debugging Engine thread within a process. Each thread
//! has a thread number (dbgeng-internal), a TID (OS-assigned), an execution
//! state, a name, and a stack of frames.
//!
//! This corresponds to the Processes[N].Threads[M] node in the Ghidra trace
//! object tree and maps to `TraceThread` on the model side.
//!
//! Ported from Ghidra's `Debugger-agent-dbgeng` Python commands
//! (`put_threads`, `put_frames`, etc.). Dbgeng provides the
//! `_DEBUG_STACK_FRAME` structure with instruction offset, stack offset,
//! frame offset, and return offset for each frame.
//!
//! ## Additional features ported from Python agent
//! - TEB (Thread Environment Block) address tracking
//! - Short display format with configurable radix (`[proc.thread:tid]`)
//! - Thread list/snapshot support matching Python `put_threads`
//! - Register group model with case-insensitive dbgeng register names
//! - Frame `_DEBUG_STACK_FRAME` offset details for the trace tree

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::agents::{
    ExecutionState, RegisterValue, StackFrameInfo, ThreadInfo,
};

/// Execution state of a dbgeng thread.
///
/// This extends the common `ExecutionState` with dbgeng-specific states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DbgEngThreadState {
    /// Thread is running.
    Running,
    /// Thread is stopped (breakpoint, exception, step).
    Stopped,
    /// Thread has exited.
    Exited,
    /// Thread is not yet started or unknown.
    Inactive,
}

impl DbgEngThreadState {
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

    /// Parse from dbgeng execution status.
    ///
    /// The dbgeng `GetExecutionStatus()` returns one of several constants.
    /// This maps the status code to a thread state.
    pub fn from_execution_status(status: u32) -> Self {
        // DEBUG_STATUS values from dbgeng.h
        const DEBUG_STATUS_NO_CHANGE: u32 = 0;
        const DEBUG_STATUS_GO: u32 = 1;
        const DEBUG_STATUS_GO_HANDLED: u32 = 2;
        const DEBUG_STATUS_GO_NOT_HANDLED: u32 = 3;
        const DEBUG_STATUS_STEP_OVER: u32 = 4;
        const DEBUG_STATUS_STEP_INTO: u32 = 5;
        const DEBUG_STATUS_BREAK: u32 = 6;
        const DEBUG_STATUS_NO_DEBUGGEE: u32 = 7;
        const DEBUG_STATUS_STEP_BRANCH: u32 = 8;
        const DEBUG_STATUS_IGNORE_EVENT: u32 = 9;
        const DEBUG_STATUS_RESTART_REQUESTED: u32 = 10;

        match status {
            DEBUG_STATUS_GO
            | DEBUG_STATUS_GO_HANDLED
            | DEBUG_STATUS_GO_NOT_HANDLED
            | DEBUG_STATUS_STEP_OVER
            | DEBUG_STATUS_STEP_INTO
            | DEBUG_STATUS_STEP_BRANCH
            | DEBUG_STATUS_IGNORE_EVENT
            | DEBUG_STATUS_RESTART_REQUESTED => Self::Running,
            DEBUG_STATUS_BREAK => Self::Stopped,
            DEBUG_STATUS_NO_DEBUGGEE => Self::Exited,
            DEBUG_STATUS_NO_CHANGE | _ => Self::Inactive,
        }
    }
}

/// A dbgeng thread within a process.
///
/// Each thread in dbgeng has an internal thread number, an OS-level TID,
/// and associated stack frames. The dbgeng `_DEBUG_STACK_FRAME` provides
/// instruction offset, stack offset, frame offset, and return offset for
/// each frame in the call stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbgEngThread {
    /// Thread number in the trace hierarchy (0-based).
    pub num: u32,
    /// OS-level thread ID (Windows TID).
    pub tid: Option<u64>,
    /// Thread name, if known.
    pub name: Option<String>,
    /// Current execution state.
    pub state: ExecutionState,
    /// Stack frames, keyed by level (0 = innermost).
    pub frames: BTreeMap<u32, DbgEngStackFrame>,
    /// Whether this thread has been synchronized to the trace.
    pub synced: bool,
    /// The process number this thread belongs to.
    pub process_num: u32,
    /// Thread Environment Block address, if known.
    pub teb: Option<u64>,
}

impl DbgEngThread {
    /// Create a new thread.
    pub fn new(num: u32) -> Self {
        Self {
            num,
            tid: None,
            name: None,
            state: ExecutionState::NotStarted,
            frames: BTreeMap::new(),
            synced: false,
            process_num: 0,
            teb: None,
        }
    }

    /// Create a thread belonging to a specific process.
    pub fn in_process(num: u32, process_num: u32) -> Self {
        Self {
            num,
            process_num,
            ..Self::new(num)
        }
    }

    /// Set the OS thread ID.
    pub fn with_tid(mut self, tid: u64) -> Self {
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

    /// Set the TEB address.
    pub fn with_teb(mut self, teb: u64) -> Self {
        self.teb = Some(teb);
        self
    }

    /// Get the trace object path for this thread.
    pub fn trace_path(&self) -> String {
        format!("Processes[{}].Threads[{}]", self.process_num, self.num)
    }

    /// Get the trace path for this thread's stack container.
    pub fn stack_path(&self) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack",
            self.process_num, self.num
        )
    }

    /// Add a stack frame to this thread.
    pub fn add_frame(&mut self, frame: DbgEngStackFrame) {
        self.frames.insert(frame.level, frame);
    }

    /// Remove a stack frame by level.
    pub fn remove_frame(&mut self, level: u32) -> Option<DbgEngStackFrame> {
        self.frames.remove(&level)
    }

    /// Clear all frames.
    pub fn clear_frames(&mut self) {
        self.frames.clear();
    }

    /// Get a frame by level.
    pub fn get_frame(&self, level: u32) -> Option<&DbgEngStackFrame> {
        self.frames.get(&level)
    }

    /// Get the innermost frame (level 0).
    pub fn innermost_frame(&self) -> Option<&DbgEngStackFrame> {
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
    /// These are used to populate the `Processes[N].Threads[M]` node.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let mut values = vec![
            ("_state".to_string(), self.state.as_trace_str().to_string()),
        ];
        if let Some(ref name) = self.name {
            values.push(("_display".to_string(), name.clone()));
        }
        if let Some(tid) = self.tid {
            values.push(("TID".to_string(), format!("0x{:x}", tid)));
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
        format!("[{}.{}:{}]", self.process_num, self.num, tid_str)
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

    /// Build trace object key-value pairs including TEB.
    ///
    /// Extended version matching the Python agent's `put_threads`.
    pub fn build_trace_values_extended(&self, radix: u32, is_kernel: bool) -> Vec<(String, String)> {
        let mut values = vec![
            ("State".to_string(), self.state.as_trace_str().to_string()),
            ("TID".to_string(), format!("{}", self.tid.unwrap_or(0))),
            (
                "_short_display".to_string(),
                self.build_short_display(radix),
            ),
        ];
        let display = self.build_display_extended(radix, is_kernel);
        values.push(("_display".to_string(), display));
        if let Some(teb) = self.teb {
            values.push(("TEB".to_string(), format!("0x{:x}", teb)));
        }
        if let Some(ref name) = self.name {
            values.push(("Name".to_string(), name.clone()));
        }
        values
    }

    /// Build the extended display string matching the Python agent.
    ///
    /// Format for kernel: `'{tnum:x} {tid:x}'`
    /// Format for user: `'{tnum:x} {pid:x}:{tid:x} {name}'`
    pub fn build_display_extended(&self, radix: u32, is_kernel: bool) -> String {
        let pid = self.process_num;
        let tid = self.tid.unwrap_or(0);
        let tid_str = match radix {
            16 => format!("{:x}", tid),
            8 => format!("{:o}", tid),
            _ => format!("{}", tid),
        };
        let pid_str = match radix {
            16 => format!("{:x}", pid),
            8 => format!("{:o}", pid),
            _ => format!("{}", pid),
        };
        if is_kernel {
            format!("[{}:{}]", self.num, tid_str)
        } else {
            match &self.name {
                Some(n) if !n.is_empty() => {
                    format!("{} {}:{} {}", self.num, pid_str, tid_str, n)
                }
                _ => {
                    format!("{} {}:{}", self.num, pid_str, tid_str)
                }
            }
        }
    }

    /// Get the innermost PC (program counter), if any frame exists.
    pub fn pc(&self) -> Option<u64> {
        self.innermost_frame().map(|f| f.pc)
    }

    /// Get the innermost SP (stack pointer), if any frame exists.
    pub fn sp(&self) -> Option<u64> {
        self.innermost_frame().map(|f| f.sp)
    }

    /// Get all frames sorted by level (innermost first).
    pub fn sorted_frames(&self) -> Vec<&DbgEngStackFrame> {
        let mut frames: Vec<&DbgEngStackFrame> = self.frames.values().collect();
        frames.sort_by_key(|f| f.level);
        frames
    }

    /// Build the stack container path for this thread.
    pub fn stack_frames_path(&self) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack.Frames",
            self.process_num, self.num
        )
    }

    /// Build the registers path for this thread.
    pub fn registers_path(&self) -> String {
        format!(
            "Processes[{}].Threads[{}].Registers",
            self.process_num, self.num
        )
    }

    /// Build the user registers path for this thread.
    pub fn user_registers_path(&self) -> String {
        format!(
            "Processes[{}].Threads[{}].Registers.User",
            self.process_num, self.num
        )
    }
}

/// A stack frame within a dbgeng thread.
///
/// Each frame represents one level of the call stack. Frame 0 is the
/// currently executing function. Frame 1 is its caller, and so on.
///
/// Dbgeng provides the `_DEBUG_STACK_FRAME` structure which includes:
/// - Instruction offset (IP / program counter)
/// - Stack offset (SP)
/// - Frame offset (FP)
/// - Return offset (return address)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbgEngStackFrame {
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

impl DbgEngStackFrame {
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

    /// Create from a `_DEBUG_STACK_FRAME` structure's offsets.
    pub fn from_debug_stack_frame(
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
    pub fn registers_trace_path(&self, process_num: u32, thread_num: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}].Registers",
            process_num, thread_num, self.level
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

    /// Get a register value by name (case-insensitive for dbgeng).
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

    /// Build the trace object key-value pairs for this frame.
    ///
    /// Matches the Python agent's `put_frames` output with all four offsets.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let mut values = vec![(
            "_display".to_string(),
            format!("#{} 0x{:08x}", self.level, self.pc),
        )];
        values.push((
            "Instruction Offset".to_string(),
            format!("0x{:x}", self.pc),
        ));
        values.push((
            "Stack Offset".to_string(),
            format!("0x{:x}", self.sp),
        ));
        values.push((
            "Return Offset".to_string(),
            format!("0x{:x}", self.return_address),
        ));
        values.push((
            "Frame Offset".to_string(),
            format!("0x{:x}", self.fp),
        ));
        values
    }

    /// Build the trace path for this frame.
    pub fn trace_path(&self, process_num: u32, thread_num: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack.Frames[{}]",
            process_num, thread_num, self.level
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_state_from_execution_status() {
        assert_eq!(
            DbgEngThreadState::from_execution_status(1), // DEBUG_STATUS_GO
            DbgEngThreadState::Running
        );
        assert_eq!(
            DbgEngThreadState::from_execution_status(4), // DEBUG_STATUS_STEP_OVER
            DbgEngThreadState::Running
        );
        assert_eq!(
            DbgEngThreadState::from_execution_status(6), // DEBUG_STATUS_BREAK
            DbgEngThreadState::Stopped
        );
        assert_eq!(
            DbgEngThreadState::from_execution_status(7), // DEBUG_STATUS_NO_DEBUGGEE
            DbgEngThreadState::Exited
        );
        assert_eq!(
            DbgEngThreadState::from_execution_status(0), // DEBUG_STATUS_NO_CHANGE
            DbgEngThreadState::Inactive
        );
    }

    #[test]
    fn test_thread_state_to_execution_state() {
        assert_eq!(
            DbgEngThreadState::Running.to_execution_state(),
            ExecutionState::Running
        );
        assert_eq!(
            DbgEngThreadState::Stopped.to_execution_state(),
            ExecutionState::Stopped
        );
    }

    #[test]
    fn test_thread_state_trace_str() {
        assert_eq!(DbgEngThreadState::Running.as_trace_str(), "RUNNING");
        assert_eq!(DbgEngThreadState::Stopped.as_trace_str(), "STOPPED");
        assert_eq!(DbgEngThreadState::Exited.as_trace_str(), "TERMINATED");
        assert_eq!(DbgEngThreadState::Inactive.as_trace_str(), "INACTIVE");
    }

    #[test]
    fn test_thread_new() {
        let t = DbgEngThread::new(0);
        assert_eq!(t.num, 0);
        assert_eq!(t.tid, None);
        assert_eq!(t.name, None);
        assert_eq!(t.state, ExecutionState::NotStarted);
        assert!(t.frames.is_empty());
        assert_eq!(t.process_num, 0);
        assert!(t.teb.is_none());
    }

    #[test]
    fn test_thread_in_process() {
        let t = DbgEngThread::in_process(2, 1);
        assert_eq!(t.num, 2);
        assert_eq!(t.process_num, 1);
    }

    #[test]
    fn test_thread_builder() {
        let t = DbgEngThread::new(1)
            .with_tid(0x1234)
            .with_name("main")
            .with_state(ExecutionState::Running);
        assert_eq!(t.tid, Some(0x1234));
        assert_eq!(t.name, Some("main".to_string()));
        assert_eq!(t.state, ExecutionState::Running);
    }

    #[test]
    fn test_thread_trace_path() {
        let t = DbgEngThread::in_process(2, 1);
        assert_eq!(t.trace_path(), "Processes[1].Threads[2]");
        assert_eq!(t.stack_path(), "Processes[1].Threads[2].Stack");
    }

    #[test]
    fn test_thread_frame_management() {
        let mut t = DbgEngThread::new(1);
        t.add_frame(DbgEngStackFrame::new(0, 0x401000));
        t.add_frame(DbgEngStackFrame::new(1, 0x402000));
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
        let t = DbgEngThread::new(5)
            .with_name("worker")
            .with_state(ExecutionState::Stopped);
        let info = t.to_thread_info();
        assert_eq!(info.id, 5);
        assert_eq!(info.name, Some("worker".to_string()));
        assert_eq!(info.state, ExecutionState::Stopped);
    }

    #[test]
    fn test_thread_build_trace_values() {
        let t = DbgEngThread::new(1)
            .with_tid(42)
            .with_name("main")
            .with_state(ExecutionState::Stopped);
        let values = t.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "_state" && v == "STOPPED"));
        assert!(values.iter().any(|(k, v)| k == "_display" && v == "main"));
        assert!(values.iter().any(|(k, v)| k == "TID" && v == "0x2a"));
    }

    #[test]
    fn test_thread_build_short_display() {
        let t = DbgEngThread::in_process(1, 0).with_tid(0x1234);
        assert_eq!(t.build_short_display(16), "[0.1:0x1234]");
        assert_eq!(t.build_short_display(10), "[0.1:4660]");
    }

    #[test]
    fn test_thread_exit() {
        let mut t = DbgEngThread::new(1).with_state(ExecutionState::Running);
        t.add_frame(DbgEngStackFrame::new(0, 0x401000));
        assert!(t.is_alive());

        t.mark_exited();
        assert!(!t.is_alive());
        assert_eq!(t.state, ExecutionState::Exited);
        assert!(t.frames.is_empty());
    }

    #[test]
    fn test_stack_frame_new() {
        let f = DbgEngStackFrame::new(0, 0x401000);
        assert_eq!(f.level, 0);
        assert_eq!(f.pc, 0x401000);
        assert_eq!(f.sp, 0);
        assert!(f.function_name.is_none());
    }

    #[test]
    fn test_stack_frame_from_debug_stack_frame() {
        let f = DbgEngStackFrame::from_debug_stack_frame(
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
        let f = DbgEngStackFrame::new(0, 0x401000)
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
        let f = DbgEngStackFrame::new(0, 0x401000).with_function("main");
        assert_eq!(f.build_display(), "#0 0x401000 main");

        let f = DbgEngStackFrame::new(1, 0x402000);
        assert_eq!(f.build_display(), "#1 0x402000");
    }

    #[test]
    fn test_stack_frame_to_info() {
        let f = DbgEngStackFrame::new(0, 0x401000)
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
        let mut f = DbgEngStackFrame::new(0, 0x401000);
        f.set_register(RegisterValue::from_u64("RAX", 0x1234));
        f.set_register(RegisterValue::from_u64("rbx", 0x5678));

        // Case-insensitive lookup for dbgeng
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
        let f = DbgEngStackFrame::new(2, 0x401000);
        assert_eq!(
            f.registers_trace_path(1, 3),
            "Processes[1].Threads[3].Stack[2].Registers"
        );
    }

    #[test]
    fn test_thread_teb() {
        let t = DbgEngThread::new(1).with_teb(0x7ffde000);
        assert_eq!(t.teb, Some(0x7ffde000));
    }

    #[test]
    fn test_thread_build_trace_values_extended() {
        let t = DbgEngThread::new(1)
            .with_tid(0x1234)
            .with_name("main")
            .with_state(ExecutionState::Stopped)
            .with_teb(0x7ffde000);
        let values = t.build_trace_values_extended(16, false);
        assert!(values.iter().any(|(k, v)| k == "State" && v == "STOPPED"));
        assert!(values.iter().any(|(k, v)| k == "TID" && v == "4660"));
        assert!(values.iter().any(|(k, v)| k == "TEB" && v == "0x7ffde000"));
        assert!(values.iter().any(|(k, v)| k == "Name" && v == "main"));
    }

    #[test]
    fn test_thread_build_display_extended_user() {
        let t = DbgEngThread::in_process(1, 0)
            .with_tid(0x1234)
            .with_name("main");
        let disp = t.build_display_extended(16, false);
        assert!(disp.contains("1234"));
        assert!(disp.contains("main"));
    }

    #[test]
    fn test_thread_build_display_extended_kernel() {
        let t = DbgEngThread::in_process(1, 0).with_tid(0x1234);
        let disp = t.build_display_extended(16, true);
        assert!(disp.contains("1234"));
    }

    #[test]
    fn test_thread_pc_sp() {
        let mut t = DbgEngThread::new(1);
        assert!(t.pc().is_none());
        assert!(t.sp().is_none());

        t.add_frame(
            DbgEngStackFrame::new(0, 0x401000)
                .with_sp(0x7fff00)
                .with_fp(0x7fff10)
                .with_return_address(0x402000),
        );
        assert_eq!(t.pc(), Some(0x401000));
        assert_eq!(t.sp(), Some(0x7fff00));
    }

    #[test]
    fn test_thread_sorted_frames() {
        let mut t = DbgEngThread::new(1);
        t.add_frame(DbgEngStackFrame::new(2, 0x403000));
        t.add_frame(DbgEngStackFrame::new(0, 0x401000));
        t.add_frame(DbgEngStackFrame::new(1, 0x402000));
        let sorted = t.sorted_frames();
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[0].level, 0);
        assert_eq!(sorted[1].level, 1);
        assert_eq!(sorted[2].level, 2);
    }

    #[test]
    fn test_thread_stack_frames_path() {
        let t = DbgEngThread::in_process(2, 1);
        assert_eq!(
            t.stack_frames_path(),
            "Processes[1].Threads[2].Stack.Frames"
        );
    }

    #[test]
    fn test_thread_registers_path() {
        let t = DbgEngThread::in_process(2, 1);
        assert_eq!(
            t.registers_path(),
            "Processes[1].Threads[2].Registers"
        );
        assert_eq!(
            t.user_registers_path(),
            "Processes[1].Threads[2].Registers.User"
        );
    }

    #[test]
    fn test_stack_frame_build_trace_values() {
        let f = DbgEngStackFrame::new(0, 0x401000)
            .with_sp(0x7fff00)
            .with_fp(0x7fff10)
            .with_return_address(0x402000);
        let values = f.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "Instruction Offset" && v == "0x401000"));
        assert!(values.iter().any(|(k, v)| k == "Stack Offset" && v == "0x7fff00"));
        assert!(values.iter().any(|(k, v)| k == "Return Offset" && v == "0x402000"));
        assert!(values.iter().any(|(k, v)| k == "Frame Offset" && v == "0x7fff10"));
    }

    #[test]
    fn test_stack_frame_trace_path() {
        let f = DbgEngStackFrame::new(3, 0x401000);
        assert_eq!(
            f.trace_path(1, 2),
            "Processes[1].Threads[2].Stack.Frames[3]"
        );
    }
}
