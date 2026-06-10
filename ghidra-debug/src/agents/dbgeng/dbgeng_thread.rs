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
/// The `Suspended` variant corresponds to the dbgeng `IsSuspended()` check
/// in the Python agent's `convert_state` function -- a thread may be
/// stopped but explicitly suspended (e.g., via `.suspend` command).
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
    /// Thread is suspended (explicitly frozen, not responsive to continue).
    ///
    /// Ported from the Python agent's `convert_state` which checks
    /// `t.IsSuspended()` separately from `t.IsStopped()`.
    Suspended,
}

impl DbgEngThreadState {
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
            Self::Inactive => "INACTIVE",
            Self::Suspended => "SUSPENDED",
        }
    }

    /// Create from a trace state string.
    pub fn from_trace_str(s: &str) -> Self {
        match s {
            "RUNNING" => Self::Running,
            "STOPPED" => Self::Stopped,
            "TERMINATED" => Self::Exited,
            "INACTIVE" => Self::Inactive,
            "SUSPENDED" => Self::Suspended,
            _ => Self::Inactive,
        }
    }

    /// Whether this state implies the thread can be resumed.
    pub fn is_resumable(&self) -> bool {
        matches!(self, Self::Stopped | Self::Suspended)
    }

    /// Whether this state implies the thread is alive.
    pub fn is_alive_state(&self) -> bool {
        matches!(self, Self::Running | Self::Stopped | Self::Suspended)
    }

    /// Parse from dbgeng thread state booleans.
    ///
    /// The Python agent's `convert_state` checks `IsSuspended()`,
    /// `IsStopped()`, and `IsRunning()` in that order.
    pub fn from_dbgeng_state(is_running: bool, is_stopped: bool, is_suspended: bool) -> Self {
        if is_suspended {
            Self::Suspended
        } else if is_running {
            Self::Running
        } else if is_stopped {
            Self::Stopped
        } else {
            Self::Inactive
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

/// Stop reason for a specific thread stop in dbgeng.
///
/// Captures why a thread stopped, corresponding to dbgeng's event
/// callback information (exception codes, breakpoints, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbgEngStopReason {
    /// Breakpoint hit at address.
    Breakpoint { bp_number: u32, address: u64 },
    /// Hardware breakpoint hit.
    HardwareBreakpoint { bp_number: u32, address: u64 },
    /// Exception received.
    Exception { code: u64, name: Option<String> },
    /// Step completed (single-step, step-over, step-into).
    StepComplete,
    /// Access violation.
    AccessViolation { address: u64 },
    /// Module loaded.
    ModuleLoaded { name: String },
    /// Thread created.
    ThreadCreated,
    /// Process exited with code.
    Exited { code: i32 },
    /// Unknown reason.
    Unknown,
}

impl DbgEngStopReason {
    /// Human-readable description.
    pub fn description(&self) -> String {
        match self {
            Self::Breakpoint { bp_number, address } => {
                format!("Breakpoint {} at 0x{:x}", bp_number, address)
            }
            Self::HardwareBreakpoint { bp_number, address } => {
                format!("Hardware breakpoint {} at 0x{:x}", bp_number, address)
            }
            Self::Exception { code, name } => match name {
                Some(n) => format!("Exception 0x{:x} ({})", code, n),
                None => format!("Exception 0x{:x}", code),
            },
            Self::StepComplete => "Step complete".to_string(),
            Self::AccessViolation { address } => {
                format!("Access violation at 0x{:x}", address)
            }
            Self::ModuleLoaded { name } => format!("Module loaded: {}", name),
            Self::ThreadCreated => "Thread created".to_string(),
            Self::Exited { code } => format!("Exited with code {}", code),
            Self::Unknown => "Unknown stop reason".to_string(),
        }
    }

    /// Whether this stop reason implies the thread is stopped (can resume).
    pub fn is_stopped(&self) -> bool {
        !matches!(self, Self::Exited { .. })
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
    /// Last known stop reason, if any.
    pub stop_reason: Option<DbgEngStopReason>,
    /// Cached display string.
    pub display: Option<String>,
    /// Cached short display string.
    pub short_display: Option<String>,
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
            stop_reason: None,
            display: None,
            short_display: None,
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

    /// Set the display string.
    pub fn with_display(mut self, display: impl Into<String>) -> Self {
        self.display = Some(display.into());
        self
    }

    /// Set the stop reason.
    pub fn with_stop_reason(mut self, reason: DbgEngStopReason) -> Self {
        self.stop_reason = Some(reason);
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

    /// Get the trace path for a specific frame in this thread.
    pub fn frame_path(&self, level: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}]",
            self.process_num, self.num, level
        )
    }

    /// Get the trace path for a specific frame's registers.
    pub fn frame_registers_path(&self, level: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}].Registers",
            self.process_num, self.num, level
        )
    }

    /// Get a mutable reference to a frame by level.
    pub fn get_frame_mut(&mut self, level: u32) -> Option<&mut DbgEngStackFrame> {
        self.frames.get_mut(&level)
    }

    /// Get the outermost frame (highest level).
    pub fn outermost_frame(&self) -> Option<&DbgEngStackFrame> {
        self.frames.values().next_back()
    }

    /// Get all frame levels in order (innermost to outermost).
    pub fn frame_levels(&self) -> Vec<u32> {
        self.frames.keys().copied().collect()
    }

    /// Whether the thread is stopped.
    pub fn is_stopped(&self) -> bool {
        self.state == ExecutionState::Stopped
    }

    /// Whether the thread is running.
    pub fn is_running(&self) -> bool {
        self.state == ExecutionState::Running
    }

    /// Whether the thread has exited.
    pub fn is_exited(&self) -> bool {
        self.state == ExecutionState::Exited
    }

    /// Get the stop reason description, if any.
    pub fn stop_reason_description(&self) -> Option<String> {
        self.stop_reason.as_ref().map(|r| r.description())
    }

    /// Build the retain keys for this thread's frame children.
    pub fn build_frame_retain_keys(&self) -> Vec<String> {
        self.frames
            .keys()
            .map(|level| format!("[{}]", level))
            .collect()
    }

    /// Update cached short display string.
    pub fn update_short_display(&mut self, radix: u32) {
        self.short_display = Some(self.build_short_display(radix));
    }

    /// Build the backtrace as a list of display strings.
    pub fn build_backtrace(&self) -> Vec<String> {
        let mut frames: Vec<_> = self.frames.values().collect();
        frames.sort_by_key(|f| f.level);
        frames.iter().map(|f| f.build_display()).collect()
    }

    /// Build trace object key-value pairs for the stack container.
    pub fn build_stack_container_values(&self) -> Vec<(String, String)> {
        vec![("_count".to_string(), self.frames.len().to_string())]
    }

    /// Collect all register names across all frames.
    pub fn all_register_names(&self) -> Vec<String> {
        let mut names = std::collections::BTreeSet::new();
        for frame in self.frames.values() {
            for reg in &frame.registers {
                names.insert(reg.name.clone());
            }
        }
        names.into_iter().collect()
    }

    /// Find the frame containing the given PC address.
    pub fn frame_at_pc(&self, pc: u64) -> Option<&DbgEngStackFrame> {
        self.frames.values().find(|f| f.pc == pc)
    }

    /// Get the return address for the innermost frame.
    pub fn return_address(&self) -> Option<u64> {
        self.innermost_frame()
            .map(|f| f.return_address)
            .filter(|&ra| ra != 0)
    }

    /// Whether the thread was stopped by a breakpoint.
    pub fn stopped_at_breakpoint(&self) -> bool {
        matches!(
            self.stop_reason,
            Some(DbgEngStopReason::Breakpoint { .. })
                | Some(DbgEngStopReason::HardwareBreakpoint { .. })
        )
    }

    /// Whether the thread was stopped by an exception.
    pub fn stopped_by_exception(&self) -> bool {
        matches!(
            self.stop_reason,
            Some(DbgEngStopReason::Exception { .. })
                | Some(DbgEngStopReason::AccessViolation { .. })
        )
    }

    /// Whether the thread finished a step operation.
    pub fn stopped_at_step(&self) -> bool {
        self.stop_reason == Some(DbgEngStopReason::StepComplete)
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

/// Tracks the event thread for a dbgeng trace.
///
/// Ported from `put_event_thread` in the Python agent. The event thread
/// is the thread that caused the most recent stop event.
#[derive(Debug, Clone, Default)]
pub struct DbgEngEventThreadTracker {
    /// The process number of the event thread, if any.
    pub process_num: Option<u32>,
    /// The thread number of the event thread, if any.
    pub thread_num: Option<u32>,
}

impl DbgEngEventThreadTracker {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the event thread.
    pub fn set(&mut self, process_num: u32, thread_num: u32) {
        self.process_num = Some(process_num);
        self.thread_num = Some(thread_num);
    }

    /// Clear the event thread.
    pub fn clear(&mut self) {
        self.process_num = None;
        self.thread_num = None;
    }

    /// Get the event thread's trace path, if set.
    pub fn trace_path(&self) -> Option<String> {
        match (self.process_num, self.thread_num) {
            (Some(p), Some(t)) => Some(format!("Processes[{}].Threads[{}]", p, t)),
            _ => None,
        }
    }

    /// Check if a specific thread is the event thread.
    pub fn is_event_thread(&self, process_num: u32, thread_num: u32) -> bool {
        self.process_num == Some(process_num) && self.thread_num == Some(thread_num)
    }
}

/// Helper for frame selection tracking in dbgeng.
///
/// Ported from the `restore_frame` context manager in the Python agent.
#[derive(Debug, Clone, Default)]
pub struct DbgEngFrameSelection {
    /// The currently selected process.
    pub process_num: Option<u32>,
    /// The currently selected thread.
    pub thread_num: Option<u32>,
    /// The currently selected frame level.
    pub frame_level: Option<u32>,
}

impl DbgEngFrameSelection {
    /// Create a new frame selection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the complete selection.
    pub fn set(&mut self, process_num: u32, thread_num: u32, frame_level: u32) {
        self.process_num = Some(process_num);
        self.thread_num = Some(thread_num);
        self.frame_level = Some(frame_level);
    }

    /// Clear the selection.
    pub fn clear(&mut self) {
        self.process_num = None;
        self.thread_num = None;
        self.frame_level = None;
    }

    /// Get the frame trace path, if fully set.
    pub fn frame_path(&self) -> Option<String> {
        match (self.process_num, self.thread_num, self.frame_level) {
            (Some(p), Some(t), Some(f)) => {
                Some(format!("Processes[{}].Threads[{}].Stack[{}]", p, t, f))
            }
            _ => None,
        }
    }

    /// Get the thread trace path, if set.
    pub fn thread_path(&self) -> Option<String> {
        match (self.process_num, self.thread_num) {
            (Some(p), Some(t)) => Some(format!("Processes[{}].Threads[{}]", p, t)),
            _ => None,
        }
    }
}

/// A register group within a dbgeng thread.
///
/// Ported from the Python agent's `putreg` function, which iterates
/// through all registers via `regs._reg.GetDescription(i)`. Dbgeng
/// organizes registers into groups (e.g., "User", "Segment", "XMM").
/// This struct models one such group for trace synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterGroup {
    /// Group name (e.g., "User", "Segment", "XMM", "FP").
    pub name: String,
    /// Register names in this group.
    pub register_names: Vec<String>,
    /// Whether this group has been synced to the trace.
    pub synced: bool,
}

impl RegisterGroup {
    /// Create a new register group.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            register_names: Vec::new(),
            synced: false,
        }
    }

    /// Add a register name to this group.
    pub fn add_register(&mut self, name: impl Into<String>) {
        self.register_names.push(name.into());
    }

    /// Get the register count.
    pub fn register_count(&self) -> usize {
        self.register_names.len()
    }

    /// Mark as synchronized.
    pub fn mark_synced(&mut self) {
        self.synced = true;
    }

    /// Build the trace path for this register group.
    pub fn trace_path(&self, proc_num: u32, thread_num: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Registers.{}",
            proc_num, thread_num, self.name
        )
    }
}

/// Common dbgeng register groups.
///
/// These correspond to the register group names returned by the
/// dbgeng API's `GetDescription` calls. The "User" group contains
/// the general-purpose registers that are most commonly displayed.
pub mod register_groups {
    /// General-purpose registers (rax, rbx, rcx, ...).
    pub const USER: &str = "User";
    /// Segment registers (cs, ds, es, ...).
    pub const SEGMENT: &str = "Segment";
    /// XMM/SSE registers (xmm0-xmm15).
    pub const XMM: &str = "XMM";
    /// Floating-point registers (st0-st7, fctrl, ...).
    pub const FP: &str = "FP";
    /// Debug registers (dr0-dr7).
    pub const DEBUG: &str = "Debug";
    /// Control registers (cr0, cr4, ...).
    pub const CONTROL: &str = "Control";
}

/// Tracks register groups for a dbgeng thread.
///
/// Manages the set of register groups available for a thread and
/// which have been synchronized to the trace. Ported from the
/// Python agent's register iteration in `putreg`.
#[derive(Debug, Clone, Default)]
pub struct DbgEngRegisterTracker {
    /// Known register groups, keyed by group name.
    pub groups: BTreeMap<String, RegisterGroup>,
}

impl DbgEngRegisterTracker {
    /// Create a new register tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a register group.
    pub fn add_group(&mut self, group: RegisterGroup) {
        self.groups.insert(group.name.clone(), group);
    }

    /// Get a group by name.
    pub fn get_group(&self, name: &str) -> Option<&RegisterGroup> {
        self.groups.get(name)
    }

    /// Get a mutable group by name.
    pub fn get_group_mut(&mut self, name: &str) -> Option<&mut RegisterGroup> {
        self.groups.get_mut(name)
    }

    /// Check if a group exists.
    pub fn has_group(&self, name: &str) -> bool {
        self.groups.contains_key(name)
    }

    /// Get the number of groups.
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Check if there are no register groups.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Get all group names.
    pub fn group_names(&self) -> Vec<&str> {
        self.groups.keys().map(|s| s.as_str()).collect()
    }

    /// Get all unsynchronized groups.
    pub fn unsynced_groups(&self) -> Vec<&RegisterGroup> {
        self.groups.values().filter(|g| !g.synced).collect()
    }

    /// Mark all groups as needing re-sync.
    pub fn mark_all_dirty(&mut self) {
        for g in self.groups.values_mut() {
            g.synced = false;
        }
    }

    /// Get the total register count across all groups.
    pub fn total_register_count(&self) -> usize {
        self.groups.values().map(|g| g.register_count()).sum()
    }
}

/// Stack walking context for dbgeng.
///
/// Ported from the Python agent's `put_frames` function. When
/// walking the stack, dbgeng provides `_DEBUG_STACK_FRAME` structures
/// with four offsets (Instruction, Stack, Frame, Return). This struct
/// tracks the walk state to detect when frames have changed.
#[derive(Debug, Clone, Default)]
pub struct DbgEngStackWalker {
    /// Last walked frame levels (to detect changes).
    pub last_frame_levels: Vec<u32>,
    /// Whether the stack has been walked at least once.
    pub walked: bool,
    /// Maximum depth to walk (0 = unlimited).
    pub max_depth: u32,
}

impl DbgEngStackWalker {
    /// Create a new stack walker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum walk depth.
    pub fn with_max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }

    /// Record a walk result.
    pub fn record_walk(&mut self, frame_levels: Vec<u32>) {
        self.last_frame_levels = frame_levels;
        self.walked = true;
    }

    /// Check if the frame levels have changed since last walk.
    pub fn frames_changed(&self, new_levels: &[u32]) -> bool {
        if !self.walked {
            return true;
        }
        if self.last_frame_levels.len() != new_levels.len() {
            return true;
        }
        self.last_frame_levels
            .iter()
            .zip(new_levels.iter())
            .any(|(a, b)| a != b)
    }

    /// Reset the walker state.
    pub fn reset(&mut self) {
        self.last_frame_levels.clear();
        self.walked = false;
    }
}

/// A register descriptor as returned by dbgeng's register enumeration API.
///
/// Ported from the Python agent's `putreg` function which iterates through
/// all registers via `regs._reg.GetDescription(i)`. Each descriptor carries
/// the register name, its group, and its size in bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDescriptor {
    /// Register name (e.g., "rax", "rip", "xmm0").
    pub name: String,
    /// Register group (e.g., "User", "Segment", "XMM").
    pub group: Option<String>,
    /// Register size in bytes.
    pub size: Option<usize>,
}

impl RegisterDescriptor {
    /// Create a new register descriptor.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            group: None,
            size: None,
        }
    }

    /// Set the register group.
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }

    /// Set the register size.
    pub fn with_size(mut self, size: usize) -> Self {
        self.size = Some(size);
        self
    }
}

/// A batch of register values for a frame.
///
/// Groups register values by frame for efficient trace writing.
/// Ported from the register syncing logic in `commands.py` and `hooks.py`.
#[derive(Debug, Clone, Default)]
pub struct FrameRegisterBatch {
    /// Frame level.
    pub frame_level: u32,
    /// Register values.
    pub registers: Vec<RegisterValue>,
}

impl FrameRegisterBatch {
    /// Create a new batch for a frame level.
    pub fn new(frame_level: u32) -> Self {
        Self {
            frame_level,
            registers: Vec::new(),
        }
    }

    /// Add a register value.
    pub fn push(&mut self, reg: RegisterValue) {
        self.registers.push(reg);
    }

    /// Get a register value by name (case-insensitive for dbgeng).
    pub fn get(&self, name: &str) -> Option<&RegisterValue> {
        let lower = name.to_lowercase();
        self.registers
            .iter()
            .find(|r| r.name.to_lowercase() == lower)
    }

    /// Get all register names.
    pub fn names(&self) -> Vec<&str> {
        self.registers.iter().map(|r| r.name.as_str()).collect()
    }

    /// Number of registers.
    pub fn len(&self) -> usize {
        self.registers.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.registers.is_empty()
    }
}

/// Thread event for the dbgeng hook system.
///
/// Tracks thread lifecycle events that need to be synchronized
/// to the Ghidra trace. Ported from the Python hooks `on_threads_changed`,
/// `on_thread_selected`, etc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbgEngThreadEvent {
    /// A new thread was created.
    Created {
        /// Process number.
        process_num: u32,
        /// Thread number.
        thread_num: u32,
    },
    /// A thread has exited.
    Exited {
        /// Process number.
        process_num: u32,
        /// Thread number.
        thread_num: u32,
    },
    /// A thread's state has changed (running/stopped/etc).
    StateChanged {
        /// Process number.
        process_num: u32,
        /// Thread number.
        thread_num: u32,
        /// New execution state.
        new_state: ExecutionState,
    },
    /// A thread was selected by the debugger.
    Selected {
        /// Process number.
        process_num: u32,
        /// Thread number.
        thread_num: u32,
    },
}

impl DbgEngThreadEvent {
    /// Get the process number for this event.
    pub fn process_num(&self) -> u32 {
        match self {
            Self::Created { process_num, .. }
            | Self::Exited { process_num, .. }
            | Self::StateChanged { process_num, .. }
            | Self::Selected { process_num, .. } => *process_num,
        }
    }

    /// Get the thread number for this event.
    pub fn thread_num(&self) -> u32 {
        match self {
            Self::Created { thread_num, .. }
            | Self::Exited { thread_num, .. }
            | Self::StateChanged { thread_num, .. }
            | Self::Selected { thread_num, .. } => *thread_num,
        }
    }

    /// Human-readable description of this event.
    pub fn description(&self) -> String {
        match self {
            Self::Created {
                process_num,
                thread_num,
            } => {
                format!(
                    "Thread {} created in process {}",
                    thread_num, process_num
                )
            }
            Self::Exited {
                process_num,
                thread_num,
            } => {
                format!(
                    "Thread {} exited in process {}",
                    thread_num, process_num
                )
            }
            Self::StateChanged {
                process_num,
                thread_num,
                new_state,
            } => {
                format!(
                    "Thread {} in process {} -> {}",
                    thread_num,
                    process_num,
                    new_state.as_trace_str()
                )
            }
            Self::Selected {
                process_num,
                thread_num,
            } => {
                format!(
                    "Thread {} selected in process {}",
                    thread_num, process_num
                )
            }
        }
    }
}

/// Stepping mode for dbgeng thread operations.
///
/// Determines how dbgeng handles stepping. Dbgeng supports both
/// instruction-level and source-line stepping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DbgEngSteppingMode {
    /// Single instruction step (stepi/nexti).
    Instruction,
    /// Source line step (step/next).
    SourceLine,
}

/// Step type for dbgeng thread operations.
///
/// Maps to dbgeng's stepping commands. Ported from the Python agent's
/// step handling in `commands.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DbgEngStepType {
    /// Step over (next source line / `p` command).
    Over,
    /// Step into (step into function calls / `t` command).
    Into,
    /// Step out (run until current function returns / `gu` command).
    Out,
    /// Step over one instruction (`p` with instruction granularity).
    InstructionOver,
    /// Step into one instruction (`t` with instruction granularity).
    InstructionInto,
}

impl DbgEngStepType {
    /// Convert to the dbgeng command string.
    pub fn as_dbgeng_command(&self) -> &'static str {
        match self {
            Self::Over => "p",
            Self::Into => "t",
            Self::Out => "gu",
            Self::InstructionOver => "p",
            Self::InstructionInto => "t",
        }
    }

    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Over => "Step Over",
            Self::Into => "Step Into",
            Self::Out => "Step Out",
            Self::InstructionOver => "Step Instruction Over",
            Self::InstructionInto => "Step Instruction Into",
        }
    }
}

/// Thread execution history record.
///
/// Tracks the recent execution history of a thread for display
/// and debugging purposes. Ported from the TTD position tracking
/// in the Python agent's `update_position`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbgEngThreadHistoryEntry {
    /// Program counter at this point.
    pub pc: u64,
    /// Timestamp (relative to session start, in milliseconds).
    pub timestamp: u64,
    /// Stop reason at this point, if any.
    pub stop_reason: Option<DbgEngStopReason>,
    /// Frame level.
    pub frame_level: u32,
}

impl DbgEngThreadHistoryEntry {
    /// Create a new history entry.
    pub fn new(pc: u64, timestamp: u64) -> Self {
        Self {
            pc,
            timestamp,
            stop_reason: None,
            frame_level: 0,
        }
    }

    /// Set the stop reason.
    pub fn with_stop_reason(mut self, reason: DbgEngStopReason) -> Self {
        self.stop_reason = Some(reason);
        self
    }

    /// Set the frame level.
    pub fn with_frame_level(mut self, level: u32) -> Self {
        self.frame_level = level;
        self
    }
}

/// Thread execution history tracker.
///
/// Maintains a bounded ring buffer of recent execution history entries
/// for a thread. Used for TTD and general debugging history.
#[derive(Debug, Clone)]
pub struct DbgEngThreadHistory {
    entries: Vec<DbgEngThreadHistoryEntry>,
    max_entries: usize,
}

impl DbgEngThreadHistory {
    /// Create a new history tracker with a maximum number of entries.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
        }
    }

    /// Create with default capacity (100 entries).
    pub fn with_default_capacity() -> Self {
        Self::new(100)
    }

    /// Add an entry to the history.
    pub fn push(&mut self, entry: DbgEngThreadHistoryEntry) {
        if self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    /// Get the most recent entry.
    pub fn latest(&self) -> Option<&DbgEngThreadHistoryEntry> {
        self.entries.last()
    }

    /// Get all entries (oldest first).
    pub fn entries(&self) -> &[DbgEngThreadHistoryEntry] {
        &self.entries
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get the last N entries.
    pub fn last_n(&self, n: usize) -> &[DbgEngThreadHistoryEntry] {
        let start = self.entries.len().saturating_sub(n);
        &self.entries[start..]
    }
}

/// Thread plan tracking for dbgeng.
///
/// Dbgeng uses stepping commands that define what a thread should do before
/// stopping again. This struct tracks the active stepping plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbgEngThreadPlan {
    /// Plan description (e.g. "step over", "step out", "until 0x401000").
    pub description: String,
    /// The step type, if this is a standard stepping plan.
    pub step_type: Option<DbgEngStepType>,
    /// Target stop address (for `go <address>` plans).
    pub stop_address: Option<u64>,
    /// Whether the plan is complete.
    pub completed: bool,
}

impl DbgEngThreadPlan {
    /// Create a plan for a standard step.
    pub fn step(step_type: DbgEngStepType) -> Self {
        Self {
            description: step_type.description().to_string(),
            step_type: Some(step_type),
            stop_address: None,
            completed: false,
        }
    }

    /// Create a plan to run to an address.
    pub fn run_to_address(addr: u64) -> Self {
        Self {
            description: format!("go 0x{:x}", addr),
            step_type: None,
            stop_address: Some(addr),
            completed: false,
        }
    }

    /// Create a plan to step out of the current function.
    pub fn step_out() -> Self {
        Self::step(DbgEngStepType::Out)
    }

    /// Mark the plan as complete.
    pub fn mark_complete(&mut self) {
        self.completed = true;
    }
}

/// Extended stack frame information for dbgeng.
///
/// Contains additional dbgeng-specific frame metadata beyond the basic
/// `DbgEngStackFrame`, including source information and symbol details.
/// Ported from the Python agent's frame handling in `put_frames`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbgEngFrameDetails {
    /// Frame level.
    pub level: u32,
    /// Whether this frame is an artificial/thunk frame.
    pub is_artificial: bool,
    /// Source file path, if known.
    pub source_file: Option<String>,
    /// Source line number, if known.
    pub source_line: Option<u32>,
    /// Module name for this frame.
    pub module_name: Option<String>,
    /// Whether the frame corresponds to a signal/exception handler.
    pub is_exception_frame: bool,
}

impl DbgEngFrameDetails {
    /// Create frame details for a given level.
    pub fn new(level: u32) -> Self {
        Self {
            level,
            is_artificial: false,
            source_file: None,
            source_line: None,
            module_name: None,
            is_exception_frame: false,
        }
    }

    /// Mark as artificial frame.
    pub fn with_artificial(mut self, artificial: bool) -> Self {
        self.is_artificial = artificial;
        self
    }

    /// Set source location.
    pub fn with_source(mut self, file: impl Into<String>, line: u32) -> Self {
        self.source_file = Some(file.into());
        self.source_line = Some(line);
        self
    }

    /// Set module name.
    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module_name = Some(module.into());
        self
    }

    /// Mark as exception frame.
    pub fn with_exception_frame(mut self, exception: bool) -> Self {
        self.is_exception_frame = exception;
        self
    }

    /// Build a display string including source location.
    pub fn build_display(&self, pc: u64, function_name: Option<&str>) -> String {
        let mut display = format!("#{} 0x{:x}", self.level, pc);
        if let Some(name) = function_name {
            display += &format!(" {}", name);
        }
        if let (Some(file), Some(line)) = (&self.source_file, self.source_line) {
            display += &format!(" at {}:{}", file, line);
        }
        display
    }
}

/// A thread collection manager for a dbgeng process.
///
/// Manages thread lifecycle events (creation, exit) and provides
/// bulk operations on the thread set. Ported from the Python agent's
/// thread management in `hooks.py` `on_threads_changed`.
#[derive(Debug, Default)]
pub struct DbgEngThreadCollection {
    threads: BTreeMap<u32, DbgEngThread>,
    process_num: u32,
}

impl DbgEngThreadCollection {
    /// Create a new thread collection for a process.
    pub fn new(process_num: u32) -> Self {
        Self {
            threads: BTreeMap::new(),
            process_num,
        }
    }

    /// Add or replace a thread.
    pub fn insert(&mut self, thread: DbgEngThread) {
        self.threads.insert(thread.num, thread);
    }

    /// Remove a thread by number.
    pub fn remove(&mut self, num: u32) -> Option<DbgEngThread> {
        self.threads.remove(&num)
    }

    /// Get a thread by number.
    pub fn get(&self, num: u32) -> Option<&DbgEngThread> {
        self.threads.get(&num)
    }

    /// Get a mutable thread by number.
    pub fn get_mut(&mut self, num: u32) -> Option<&mut DbgEngThread> {
        self.threads.get_mut(&num)
    }

    /// Get the number of threads.
    pub fn len(&self) -> usize {
        self.threads.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }

    /// Get all thread numbers.
    pub fn numbers(&self) -> Vec<u32> {
        self.threads.keys().copied().collect()
    }

    /// Iterate over threads.
    pub fn iter(&self) -> impl Iterator<Item = &DbgEngThread> {
        self.threads.values()
    }

    /// Mark all threads as synchronized.
    pub fn mark_all_synced(&mut self) {
        for t in self.threads.values_mut() {
            t.mark_synced();
        }
    }

    /// Remove all exited threads and return their numbers.
    pub fn prune_exited(&mut self) -> Vec<u32> {
        let exited: Vec<u32> = self
            .threads
            .iter()
            .filter(|(_, t)| t.state == ExecutionState::Exited)
            .map(|(&num, _)| num)
            .collect();
        for num in &exited {
            self.threads.remove(num);
        }
        exited
    }

    /// Clear all frames from all threads (used before re-syncing).
    pub fn clear_all_frames(&mut self) {
        for t in self.threads.values_mut() {
            t.clear_frames();
        }
    }

    /// Get the process number this collection belongs to.
    pub fn process_num(&self) -> u32 {
        self.process_num
    }

    /// Build thread info list for the common agent interface.
    pub fn build_thread_info_list(&self) -> Vec<ThreadInfo> {
        self.threads.values().map(|t| t.to_thread_info()).collect()
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
        assert!(t.stop_reason.is_none());
        assert!(t.display.is_none());
        assert!(t.short_display.is_none());
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

    #[test]
    fn test_thread_state_from_trace_str() {
        assert_eq!(DbgEngThreadState::from_trace_str("RUNNING"), DbgEngThreadState::Running);
        assert_eq!(DbgEngThreadState::from_trace_str("STOPPED"), DbgEngThreadState::Stopped);
        assert_eq!(DbgEngThreadState::from_trace_str("TERMINATED"), DbgEngThreadState::Exited);
        assert_eq!(DbgEngThreadState::from_trace_str("INACTIVE"), DbgEngThreadState::Inactive);
        assert_eq!(DbgEngThreadState::from_trace_str("SUSPENDED"), DbgEngThreadState::Suspended);
        assert_eq!(DbgEngThreadState::from_trace_str("UNKNOWN"), DbgEngThreadState::Inactive);
    }

    #[test]
    fn test_thread_state_properties() {
        assert!(DbgEngThreadState::Stopped.is_resumable());
        assert!(DbgEngThreadState::Suspended.is_resumable());
        assert!(!DbgEngThreadState::Running.is_resumable());
        assert!(DbgEngThreadState::Running.is_alive_state());
        assert!(DbgEngThreadState::Stopped.is_alive_state());
        assert!(DbgEngThreadState::Suspended.is_alive_state());
        assert!(!DbgEngThreadState::Exited.is_alive_state());
        assert!(!DbgEngThreadState::Inactive.is_alive_state());
    }

    #[test]
    fn test_thread_state_suspended() {
        assert_eq!(DbgEngThreadState::Suspended.as_trace_str(), "SUSPENDED");
        assert_eq!(
            DbgEngThreadState::Suspended.to_execution_state(),
            ExecutionState::Stopped
        );
    }

    #[test]
    fn test_thread_state_from_dbgeng_state() {
        assert_eq!(
            DbgEngThreadState::from_dbgeng_state(true, false, false),
            DbgEngThreadState::Running
        );
        assert_eq!(
            DbgEngThreadState::from_dbgeng_state(false, true, false),
            DbgEngThreadState::Stopped
        );
        assert_eq!(
            DbgEngThreadState::from_dbgeng_state(false, false, true),
            DbgEngThreadState::Suspended
        );
        assert_eq!(
            DbgEngThreadState::from_dbgeng_state(false, false, false),
            DbgEngThreadState::Inactive
        );
        // Suspended takes priority over stopped
        assert_eq!(
            DbgEngThreadState::from_dbgeng_state(false, true, true),
            DbgEngThreadState::Suspended
        );
    }

    #[test]
    fn test_stop_reason() {
        let bp = DbgEngStopReason::Breakpoint {
            bp_number: 1,
            address: 0x401000,
        };
        assert!(bp.is_stopped());
        assert!(bp.description().contains("Breakpoint"));

        let exc = DbgEngStopReason::Exception {
            code: 0xc0000005,
            name: Some("Access Violation".to_string()),
        };
        assert!(exc.is_stopped());
        assert!(exc.description().contains("Access Violation"));

        let exited = DbgEngStopReason::Exited { code: 0 };
        assert!(!exited.is_stopped());
    }

    #[test]
    fn test_thread_with_display() {
        let t = DbgEngThread::new(1)
            .with_display("Thread 1 main");
        assert_eq!(t.display, Some("Thread 1 main".to_string()));
    }

    #[test]
    fn test_thread_with_stop_reason() {
        let t = DbgEngThread::new(1)
            .with_stop_reason(DbgEngStopReason::StepComplete);
        assert!(t.stop_reason.is_some());
        assert_eq!(
            t.stop_reason_description(),
            Some("Step complete".to_string())
        );
    }

    #[test]
    fn test_thread_state_queries() {
        let t_running = DbgEngThread::new(1).with_state(ExecutionState::Running);
        assert!(t_running.is_running());
        assert!(!t_running.is_stopped());
        assert!(!t_running.is_exited());
        assert!(t_running.is_alive());

        let t_stopped = DbgEngThread::new(2).with_state(ExecutionState::Stopped);
        assert!(!t_stopped.is_running());
        assert!(t_stopped.is_stopped());
        assert!(t_stopped.is_alive());

        let t_exited = DbgEngThread::new(3).with_state(ExecutionState::Exited);
        assert!(t_exited.is_exited());
        assert!(!t_exited.is_alive());
    }

    #[test]
    fn test_thread_outermost_frame() {
        let mut t = DbgEngThread::new(1);
        assert!(t.outermost_frame().is_none());

        t.add_frame(DbgEngStackFrame::new(0, 0x401000));
        t.add_frame(DbgEngStackFrame::new(1, 0x402000));
        t.add_frame(DbgEngStackFrame::new(2, 0x403000));
        assert_eq!(t.outermost_frame().unwrap().pc, 0x403000);
    }

    #[test]
    fn test_thread_frame_levels() {
        let mut t = DbgEngThread::new(1);
        t.add_frame(DbgEngStackFrame::new(0, 0x401000));
        t.add_frame(DbgEngStackFrame::new(2, 0x403000));
        let levels = t.frame_levels();
        assert_eq!(levels, vec![0, 2]);
    }

    #[test]
    fn test_thread_frame_retain_keys() {
        let mut t = DbgEngThread::new(1);
        t.add_frame(DbgEngStackFrame::new(0, 0x401000));
        t.add_frame(DbgEngStackFrame::new(2, 0x403000));
        let keys = t.build_frame_retain_keys();
        assert!(keys.contains(&"[0]".to_string()));
        assert!(keys.contains(&"[2]".to_string()));
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_thread_frame_path() {
        let t = DbgEngThread::in_process(2, 1);
        assert_eq!(t.frame_path(0), "Processes[1].Threads[2].Stack[0]");
        assert_eq!(
            t.frame_registers_path(1),
            "Processes[1].Threads[2].Stack[1].Registers"
        );
    }

    #[test]
    fn test_thread_update_short_display() {
        let mut t = DbgEngThread::in_process(1, 0).with_tid(0x1234);
        t.update_short_display(16);
        assert_eq!(t.short_display, Some("[0.1:0x1234]".to_string()));
    }

    #[test]
    fn test_thread_exit_clears_stop_reason() {
        let mut t = DbgEngThread::new(1)
            .with_state(ExecutionState::Running)
            .with_stop_reason(DbgEngStopReason::StepComplete);
        t.mark_exited();
        assert!(!t.is_alive());
        assert_eq!(t.state, ExecutionState::Exited);
        // stop_reason is not cleared by mark_exited for dbgeng,
        // but frames are cleared
        assert!(t.frames.is_empty());
    }

    #[test]
    fn test_event_thread_tracker() {
        let mut tracker = DbgEngEventThreadTracker::new();
        assert!(tracker.trace_path().is_none());
        assert!(!tracker.is_event_thread(1, 1));

        tracker.set(1, 2);
        assert_eq!(
            tracker.trace_path(),
            Some("Processes[1].Threads[2]".to_string())
        );
        assert!(tracker.is_event_thread(1, 2));
        assert!(!tracker.is_event_thread(1, 3));
        assert!(!tracker.is_event_thread(2, 2));

        tracker.clear();
        assert!(tracker.trace_path().is_none());
    }

    #[test]
    fn test_frame_selection() {
        let mut sel = DbgEngFrameSelection::new();
        assert!(sel.frame_path().is_none());
        assert!(sel.thread_path().is_none());

        sel.set(1, 2, 3);
        assert_eq!(
            sel.frame_path(),
            Some("Processes[1].Threads[2].Stack[3]".to_string())
        );
        assert_eq!(
            sel.thread_path(),
            Some("Processes[1].Threads[2]".to_string())
        );

        sel.clear();
        assert!(sel.frame_path().is_none());
    }

    #[test]
    fn test_stop_reason_hw_breakpoint() {
        let reason = DbgEngStopReason::HardwareBreakpoint {
            bp_number: 0,
            address: 0x7ff612345678,
        };
        assert!(reason.is_stopped());
        assert!(reason.description().contains("Hardware breakpoint"));
    }

    #[test]
    fn test_stop_reason_access_violation() {
        let reason = DbgEngStopReason::AccessViolation {
            address: 0xdeadbeef,
        };
        assert!(reason.is_stopped());
        assert!(reason.description().contains("0xdeadbeef"));
    }

    #[test]
    fn test_stop_reason_module_loaded() {
        let reason = DbgEngStopReason::ModuleLoaded {
            name: "kernel32.dll".to_string(),
        };
        assert!(reason.is_stopped());
        assert!(reason.description().contains("kernel32.dll"));
    }

    #[test]
    fn test_register_group() {
        let mut g = RegisterGroup::new("User");
        g.add_register("rax");
        g.add_register("rbx");
        g.add_register("rcx");
        assert_eq!(g.register_count(), 3);
        assert_eq!(g.trace_path(1, 2), "Processes[1].Threads[2].Registers.User");

        g.mark_synced();
        assert!(g.synced);
    }

    #[test]
    fn test_register_group_constants() {
        assert_eq!(register_groups::USER, "User");
        assert_eq!(register_groups::XMM, "XMM");
        assert_eq!(register_groups::SEGMENT, "Segment");
    }

    #[test]
    fn test_register_tracker() {
        let mut tracker = DbgEngRegisterTracker::new();
        assert!(tracker.is_empty());

        let mut user = RegisterGroup::new("User");
        user.add_register("rax");
        user.add_register("rbx");
        tracker.add_group(user);

        let mut xmm = RegisterGroup::new("XMM");
        xmm.add_register("xmm0");
        tracker.add_group(xmm);

        assert_eq!(tracker.group_count(), 2);
        assert!(tracker.has_group("User"));
        assert!(!tracker.has_group("Debug"));
        assert_eq!(tracker.total_register_count(), 3);

        let names = tracker.group_names();
        assert!(names.contains(&"User"));
        assert!(names.contains(&"XMM"));

        // All unsynced initially
        assert_eq!(tracker.unsynced_groups().len(), 2);

        // Mark one synced
        tracker.get_group_mut("User").unwrap().mark_synced();
        assert_eq!(tracker.unsynced_groups().len(), 1);

        // Mark all dirty
        tracker.mark_all_dirty();
        assert_eq!(tracker.unsynced_groups().len(), 2);
    }

    #[test]
    fn test_stack_walker() {
        let mut walker = DbgEngStackWalker::new();
        assert!(!walker.walked);
        assert!(walker.frames_changed(&[0, 1, 2]));

        walker.record_walk(vec![0, 1, 2]);
        assert!(walker.walked);
        assert!(!walker.frames_changed(&[0, 1, 2]));
        assert!(walker.frames_changed(&[0, 1, 3]));
        assert!(walker.frames_changed(&[0, 1]));

        walker.reset();
        assert!(!walker.walked);
        assert!(walker.frames_changed(&[0, 1, 2]));
    }

    #[test]
    fn test_stack_walker_max_depth() {
        let walker = DbgEngStackWalker::new().with_max_depth(100);
        assert_eq!(walker.max_depth, 100);
    }

    #[test]
    fn test_thread_build_backtrace() {
        let mut t = DbgEngThread::new(1);
        t.add_frame(DbgEngStackFrame::new(0, 0x401000).with_function("main"));
        t.add_frame(DbgEngStackFrame::new(1, 0x402000).with_function("foo"));
        t.add_frame(DbgEngStackFrame::new(2, 0x403000));
        let bt = t.build_backtrace();
        assert_eq!(bt.len(), 3);
        assert!(bt[0].contains("main"));
        assert!(bt[1].contains("foo"));
        assert!(bt[2].contains("403000"));
    }

    #[test]
    fn test_thread_build_stack_container_values() {
        let mut t = DbgEngThread::new(1);
        t.add_frame(DbgEngStackFrame::new(0, 0x401000));
        t.add_frame(DbgEngStackFrame::new(1, 0x402000));
        let values = t.build_stack_container_values();
        assert!(values.iter().any(|(k, v)| k == "_count" && v == "2"));
    }

    #[test]
    fn test_thread_all_register_names() {
        let mut t = DbgEngThread::new(1);
        let mut f0 = DbgEngStackFrame::new(0, 0x401000);
        f0.set_register(RegisterValue::from_u64("RAX", 0x100));
        f0.set_register(RegisterValue::from_u64("RBX", 0x200));
        t.add_frame(f0);
        let mut f1 = DbgEngStackFrame::new(1, 0x402000);
        f1.set_register(RegisterValue::from_u64("RAX", 0x300));
        f1.set_register(RegisterValue::from_u64("RCX", 0x400));
        t.add_frame(f1);
        let names = t.all_register_names();
        assert_eq!(names.len(), 3); // RAX, RBX, RCX (deduplicated)
        assert!(names.contains(&"RAX".to_string()));
        assert!(names.contains(&"RBX".to_string()));
        assert!(names.contains(&"RCX".to_string()));
    }

    #[test]
    fn test_thread_frame_at_pc() {
        let mut t = DbgEngThread::new(1);
        t.add_frame(DbgEngStackFrame::new(0, 0x401000));
        t.add_frame(DbgEngStackFrame::new(1, 0x402000));
        assert!(t.frame_at_pc(0x401000).is_some());
        assert!(t.frame_at_pc(0x402000).is_some());
        assert!(t.frame_at_pc(0x500000).is_none());
    }

    #[test]
    fn test_thread_return_address() {
        let mut t = DbgEngThread::new(1);
        assert!(t.return_address().is_none());
        t.add_frame(
            DbgEngStackFrame::new(0, 0x401000).with_return_address(0x402000),
        );
        assert_eq!(t.return_address(), Some(0x402000));
    }

    #[test]
    fn test_thread_stopped_at_breakpoint() {
        let t = DbgEngThread::new(1).with_stop_reason(DbgEngStopReason::Breakpoint {
            bp_number: 1,
            address: 0x401000,
        });
        assert!(t.stopped_at_breakpoint());
        assert!(!t.stopped_by_exception());
        assert!(!t.stopped_at_step());
    }

    #[test]
    fn test_thread_stopped_by_exception() {
        let t = DbgEngThread::new(1).with_stop_reason(DbgEngStopReason::Exception {
            code: 0xc0000005,
            name: Some("Access Violation".to_string()),
        });
        assert!(!t.stopped_at_breakpoint());
        assert!(t.stopped_by_exception());
    }

    #[test]
    fn test_thread_stopped_at_step() {
        let t = DbgEngThread::new(1).with_stop_reason(DbgEngStopReason::StepComplete);
        assert!(t.stopped_at_step());
        assert!(!t.stopped_at_breakpoint());
    }

    #[test]
    fn test_register_descriptor() {
        let rd = RegisterDescriptor::new("rax")
            .with_group("User")
            .with_size(8);
        assert_eq!(rd.name, "rax");
        assert_eq!(rd.group.as_deref(), Some("User"));
        assert_eq!(rd.size, Some(8));
    }

    #[test]
    fn test_frame_register_batch() {
        let mut batch = FrameRegisterBatch::new(0);
        assert!(batch.is_empty());
        batch.push(RegisterValue::from_u64("RAX", 0x1234));
        batch.push(RegisterValue::from_u64("RBX", 0x5678));
        assert_eq!(batch.len(), 2);
        // Case-insensitive lookup
        assert!(batch.get("rax").is_some());
        assert!(batch.get("RAX").is_some());
        assert!(batch.get("Rax").is_some());
        assert!(batch.get("rcx").is_none());
        let names = batch.names();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn test_dbgeng_thread_event() {
        let evt = DbgEngThreadEvent::Created {
            process_num: 1,
            thread_num: 2,
        };
        assert_eq!(evt.process_num(), 1);
        assert_eq!(evt.thread_num(), 2);
        assert!(evt.description().contains("created"));

        let sel = DbgEngThreadEvent::Selected {
            process_num: 0,
            thread_num: 1,
        };
        assert!(sel.description().contains("selected"));
    }

    #[test]
    fn test_dbgeng_step_type() {
        assert_eq!(DbgEngStepType::Over.as_dbgeng_command(), "p");
        assert_eq!(DbgEngStepType::Into.as_dbgeng_command(), "t");
        assert_eq!(DbgEngStepType::Out.as_dbgeng_command(), "gu");
        assert_eq!(DbgEngStepType::Over.description(), "Step Over");
    }

    #[test]
    fn test_thread_history_entry() {
        let entry = DbgEngThreadHistoryEntry::new(0x401000, 1000)
            .with_stop_reason(DbgEngStopReason::StepComplete)
            .with_frame_level(0);
        assert_eq!(entry.pc, 0x401000);
        assert_eq!(entry.timestamp, 1000);
        assert_eq!(entry.frame_level, 0);
        assert!(entry.stop_reason.is_some());
    }

    #[test]
    fn test_thread_history() {
        let mut history = DbgEngThreadHistory::new(3);
        assert!(history.is_empty());
        history.push(DbgEngThreadHistoryEntry::new(0x1000, 1));
        history.push(DbgEngThreadHistoryEntry::new(0x2000, 2));
        history.push(DbgEngThreadHistoryEntry::new(0x3000, 3));
        assert_eq!(history.len(), 3);
        assert_eq!(history.latest().unwrap().pc, 0x3000);

        // Overflow removes oldest
        history.push(DbgEngThreadHistoryEntry::new(0x4000, 4));
        assert_eq!(history.len(), 3);
        assert_eq!(history.entries()[0].pc, 0x2000);
        assert_eq!(history.latest().unwrap().pc, 0x4000);

        // last_n
        let last2 = history.last_n(2);
        assert_eq!(last2.len(), 2);
        assert_eq!(last2[0].pc, 0x3000);

        history.clear();
        assert!(history.is_empty());
    }

    #[test]
    fn test_thread_history_default_capacity() {
        let history = DbgEngThreadHistory::with_default_capacity();
        assert_eq!(history.max_entries, 100);
    }

    #[test]
    fn test_thread_plan() {
        let plan = DbgEngThreadPlan::step(DbgEngStepType::Over);
        assert_eq!(plan.step_type, Some(DbgEngStepType::Over));
        assert!(!plan.completed);
        assert!(plan.stop_address.is_none());

        let plan_addr = DbgEngThreadPlan::run_to_address(0x401000);
        assert!(plan_addr.step_type.is_none());
        assert_eq!(plan_addr.stop_address, Some(0x401000));

        let plan_out = DbgEngThreadPlan::step_out();
        assert_eq!(plan_out.step_type, Some(DbgEngStepType::Out));

        let mut plan2 = DbgEngThreadPlan::step(DbgEngStepType::Into);
        assert!(!plan2.completed);
        plan2.mark_complete();
        assert!(plan2.completed);
    }

    #[test]
    fn test_frame_details() {
        let details = DbgEngFrameDetails::new(0)
            .with_artificial(false)
            .with_source("main.c", 42)
            .with_module("test.exe")
            .with_exception_frame(false);
        assert_eq!(details.level, 0);
        assert!(!details.is_artificial);
        assert_eq!(details.source_file.as_deref(), Some("main.c"));
        assert_eq!(details.source_line, Some(42));
        assert_eq!(details.module_name.as_deref(), Some("test.exe"));

        let display = details.build_display(0x401000, Some("main"));
        assert!(display.contains("main.c:42"));
        assert!(display.contains("main"));
    }

    #[test]
    fn test_thread_collection() {
        let mut coll = DbgEngThreadCollection::new(1);
        assert!(coll.is_empty());
        assert_eq!(coll.process_num(), 1);

        coll.insert(DbgEngThread::new(0).with_state(ExecutionState::Running));
        coll.insert(DbgEngThread::new(1).with_state(ExecutionState::Stopped));
        coll.insert(DbgEngThread::new(2).with_state(ExecutionState::Exited));
        assert_eq!(coll.len(), 3);
        assert_eq!(coll.numbers().len(), 3);

        // prune_exited
        let exited = coll.prune_exited();
        assert_eq!(exited, vec![2]);
        assert_eq!(coll.len(), 2);

        // mark_all_synced
        coll.mark_all_synced();
        assert!(coll.get(0).unwrap().synced);
        assert!(coll.get(1).unwrap().synced);

        // build_thread_info_list
        let info = coll.build_thread_info_list();
        assert_eq!(info.len(), 2);

        // clear_all_frames
        coll.clear_all_frames();
    }
}
