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

    /// Create from a trace state string.
    pub fn from_trace_str(s: &str) -> Self {
        match s {
            "RUNNING" => Self::Running,
            "STOPPED" => Self::Stopped,
            "TERMINATED" => Self::Exited,
            "SUSPENDED" => Self::Suspended,
            "INACTIVE" => Self::Inactive,
            _ => Self::Inactive,
        }
    }

    /// Whether this state implies the thread can be resumed.
    pub fn is_resumable(&self) -> bool {
        matches!(self, Self::Stopped)
    }

    /// Whether this state implies the thread is alive.
    pub fn is_alive(&self) -> bool {
        matches!(self, Self::Running | Self::Stopped | Self::Suspended)
    }
}

/// Detailed stop reason for a specific thread stop.
///
/// Captures why a thread stopped with more detail than the simple
/// `LldbStopReason` enum. This mirrors `SBThread.GetStopReasonData()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LldbDetailedStopReason {
    /// Breakpoint hit at address.
    Breakpoint {
        bp_id: u32,
        bp_location_id: u32,
        address: u64,
    },
    /// Watchpoint triggered.
    Watchpoint {
        wp_id: u32,
        address: u64,
    },
    /// Signal received.
    Signal {
        name: String,
        number: i32,
    },
    /// Step completed (plan complete).
    StepComplete,
    /// Function finished (return).
    FunctionFinished {
        return_value: Option<u64>,
    },
    /// Exec (execve).
    Exec,
    /// Exited with code.
    Exited {
        code: i32,
    },
    /// Exited by signal.
    ExitedSignal {
        signal: String,
    },
    /// Thread exiting.
    ThreadExiting,
    /// Instrumentation.
    Instrumentation,
    /// Processor trace.
    ProcessorTrace,
    /// Fork.
    Fork,
    /// VFork.
    VFork,
    /// Unknown reason.
    Unknown,
}

impl LldbDetailedStopReason {
    /// Human-readable description.
    pub fn description(&self) -> String {
        match self {
            Self::Breakpoint { bp_id, address, .. } => {
                format!("Breakpoint {} at 0x{:x}", bp_id, address)
            }
            Self::Watchpoint { wp_id, .. } => format!("Watchpoint {}", wp_id),
            Self::Signal { name, number } => format!("Signal {} ({})", name, number),
            Self::StepComplete => "Step complete".to_string(),
            Self::FunctionFinished { .. } => "Function finished".to_string(),
            Self::Exec => "Exec".to_string(),
            Self::Exited { code } => format!("Exited with code {}", code),
            Self::ExitedSignal { signal } => format!("Exited with signal {}", signal),
            Self::ThreadExiting => "Thread exiting".to_string(),
            Self::Instrumentation => "Instrumentation".to_string(),
            Self::ProcessorTrace => "Processor trace".to_string(),
            Self::Fork => "Fork".to_string(),
            Self::VFork => "VFork".to_string(),
            Self::Unknown => "Unknown stop reason".to_string(),
        }
    }

    /// Whether this stop reason implies the thread is stopped (can resume).
    pub fn is_stopped(&self) -> bool {
        !matches!(self, Self::Exited { .. } | Self::ExitedSignal { .. })
    }

    /// Convert to the simple `LldbStopReason`.
    pub fn to_simple(&self) -> super::LldbStopReason {
        match self {
            Self::Breakpoint { .. } => super::LldbStopReason::Breakpoint,
            Self::Watchpoint { .. } => super::LldbStopReason::Watchpoint,
            Self::Signal { .. } => super::LldbStopReason::Signal,
            Self::StepComplete => super::LldbStopReason::PlanComplete,
            Self::Exec => super::LldbStopReason::Exec,
            Self::ThreadExiting => super::LldbStopReason::ThreadExiting,
            Self::Instrumentation => super::LldbStopReason::Instrumentation,
            Self::ProcessorTrace => super::LldbStopReason::ProcessorTrace,
            Self::Fork => super::LldbStopReason::Fork,
            Self::VFork => super::LldbStopReason::VFork,
            _ => super::LldbStopReason::Unknown,
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
    /// Detailed stop reason with breakpoint/signal specifics.
    pub detailed_stop_reason: Option<LldbDetailedStopReason>,
    /// Queue name (GCD/com.apple thread naming, from `SBThread.GetQueueName()`).
    pub queue_name: Option<String>,
    /// Cached display string.
    pub display: Option<String>,
    /// Cached short display string.
    pub short_display: Option<String>,
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
            detailed_stop_reason: None,
            queue_name: None,
            display: None,
            short_display: None,
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

    /// Set the detailed stop reason.
    pub fn with_detailed_stop_reason(mut self, reason: LldbDetailedStopReason) -> Self {
        self.detailed_stop_reason = Some(reason);
        self
    }

    /// Set the display string.
    pub fn with_display(mut self, display: impl Into<String>) -> Self {
        self.display = Some(display.into());
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

    /// Get the trace path for a specific frame in this thread.
    pub fn frame_path(&self, level: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}]",
            self.process_index, self.index, level
        )
    }

    /// Get the trace path for a specific frame's registers.
    pub fn frame_registers_path(&self, level: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}].Registers",
            self.process_index, self.index, level
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

    /// Whether this thread is suspended.
    ///
    /// In LLDB, a suspended thread will not resume when the process
    /// continues -- it is effectively paused independently.
    pub fn is_suspended(&self) -> bool {
        self.state == ExecutionState::Stopped && self.stop_reason == Some(super::LldbStopReason::Unknown)
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

    /// Get the detailed stop reason description, if any.
    pub fn detailed_stop_reason_description(&self) -> Option<String> {
        self.detailed_stop_reason.as_ref().map(|r| r.description())
    }

    /// Update cached short display string.
    pub fn update_short_display(&mut self, radix: u32) {
        self.short_display = Some(self.build_short_display(radix));
    }

    /// Build the retain keys for this thread's frame children.
    pub fn build_frame_retain_keys(&self) -> Vec<String> {
        self.frames
            .keys()
            .map(|level| format!("[{}]", level))
            .collect()
    }

    /// Get all frames sorted by level (innermost first).
    pub fn frames_sorted(&self) -> Vec<&LldbStackFrame> {
        let mut frames: Vec<_> = self.frames.values().collect();
        frames.sort_by_key(|f| f.level);
        frames
    }

    /// Get the outermost frame (highest level).
    pub fn outermost_frame(&self) -> Option<&LldbStackFrame> {
        self.frames.values().max_by_key(|f| f.level)
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
    pub fn frame_at_pc(&self, pc: u64) -> Option<&LldbStackFrame> {
        self.frames.values().find(|f| f.pc == pc)
    }

    /// Get the return address for the innermost frame.
    pub fn return_address(&self) -> Option<u64> {
        self.innermost_frame().map(|f| f.return_address).filter(|&ra| ra != 0)
    }

    /// Whether the thread was stopped by a breakpoint.
    pub fn stopped_at_breakpoint(&self) -> bool {
        self.stop_reason == Some(super::LldbStopReason::Breakpoint)
    }

    /// Whether the thread was stopped by a signal.
    pub fn stopped_by_signal(&self) -> bool {
        self.stop_reason == Some(super::LldbStopReason::Signal)
    }

    /// Whether the thread finished a step operation.
    pub fn stopped_at_step(&self) -> bool {
        self.stop_reason == Some(super::LldbStopReason::PlanComplete)
    }

    /// Whether the thread finished a function call (returned).
    ///
    /// Checks the detailed stop reason for `FunctionFinished`.
    pub fn stopped_at_function_return(&self) -> bool {
        matches!(
            self.detailed_stop_reason,
            Some(LldbDetailedStopReason::FunctionFinished { .. })
        )
    }
}

/// Thread event for the LLDB hook system.
///
/// Tracks thread lifecycle events that need to be synchronized
/// to the Ghidra trace. Ported from the Python agent's thread
/// event handling in `hooks.py`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LldbThreadEvent {
    /// A new thread was created.
    Created {
        /// Process index.
        process_index: u32,
        /// Thread index.
        thread_index: u32,
    },
    /// A thread has exited.
    Exited {
        /// Process index.
        process_index: u32,
        /// Thread index.
        thread_index: u32,
    },
    /// A thread's state has changed (running/stopped/etc).
    StateChanged {
        /// Process index.
        process_index: u32,
        /// Thread index.
        thread_index: u32,
        /// New execution state.
        new_state: ExecutionState,
    },
    /// A thread was selected by the user.
    Selected {
        /// Process index.
        process_index: u32,
        /// Thread index.
        thread_index: u32,
    },
}

impl LldbThreadEvent {
    /// Get the process index for this event.
    pub fn process_index(&self) -> u32 {
        match self {
            Self::Created { process_index, .. }
            | Self::Exited { process_index, .. }
            | Self::StateChanged { process_index, .. }
            | Self::Selected { process_index, .. } => *process_index,
        }
    }

    /// Get the thread index for this event.
    pub fn thread_index(&self) -> u32 {
        match self {
            Self::Created { thread_index, .. }
            | Self::Exited { thread_index, .. }
            | Self::StateChanged { thread_index, .. }
            | Self::Selected { thread_index, .. } => *thread_index,
        }
    }

    /// Human-readable description of this event.
    pub fn description(&self) -> String {
        match self {
            Self::Created { process_index, thread_index } => {
                format!("Thread {} created in process {}", thread_index, process_index)
            }
            Self::Exited { process_index, thread_index } => {
                format!("Thread {} exited in process {}", thread_index, process_index)
            }
            Self::StateChanged {
                process_index,
                thread_index,
                new_state,
            } => {
                format!(
                    "Thread {} in process {} -> {}",
                    thread_index,
                    process_index,
                    new_state.as_trace_str()
                )
            }
            Self::Selected { process_index, thread_index } => {
                format!("Thread {} selected in process {}", thread_index, process_index)
            }
        }
    }
}

/// A batch of register values for a frame.
///
/// Groups register values by frame for efficient trace writing.
/// Ported from the register syncing logic in `commands.py` and `hooks.py`.
#[derive(Debug, Clone, Default)]
pub struct LldbFrameRegisterBatch {
    /// Frame level.
    pub frame_level: u32,
    /// Register values.
    pub registers: Vec<RegisterValue>,
}

impl LldbFrameRegisterBatch {
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

    /// Get a register value by name.
    pub fn get(&self, name: &str) -> Option<&RegisterValue> {
        self.registers.iter().find(|r| r.name == name)
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

/// Stepping type for LLDB thread operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LldbStepType {
    /// Step over (next instruction / source line).
    Over,
    /// Step into (step instruction / into function calls).
    Into,
    /// Step out (run until current function returns).
    Out,
    /// Single-step one instruction.
    Instruction,
}

impl LldbStepType {
    /// Convert to the LLDB Python command prefix.
    pub fn as_lldb_command(&self) -> &'static str {
        match self {
            Self::Over => "thread step-over",
            Self::Into => "thread step-in",
            Self::Out => "thread step-out",
            Self::Instruction => "thread step-inst",
        }
    }

    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Over => "Step Over",
            Self::Into => "Step Into",
            Self::Out => "Step Out",
            Self::Instruction => "Step Instruction",
        }
    }
}

/// Thread plan tracking for LLDB.
///
/// LLDB uses "thread plans" to manage stepping operations. A plan
/// describes what a thread should do before stopping again. This struct
/// mirrors the SBThread plan state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbThreadPlan {
    /// Plan description (e.g. "step over", "step until 0x401000").
    pub description: String,
    /// The step type, if this is a standard stepping plan.
    pub step_type: Option<LldbStepType>,
    /// Target stop address (for "run to address" plans).
    pub stop_address: Option<u64>,
    /// Whether the plan is complete.
    pub completed: bool,
}

impl LldbThreadPlan {
    /// Create a plan for a standard step.
    pub fn step(step_type: LldbStepType) -> Self {
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
            description: format!("run to 0x{:x}", addr),
            step_type: None,
            stop_address: Some(addr),
            completed: false,
        }
    }

    /// Create a plan to step out of the current function.
    pub fn step_out() -> Self {
        Self::step(LldbStepType::Out)
    }

    /// Mark the plan as complete.
    pub fn mark_complete(&mut self) {
        self.completed = true;
    }
}

/// Extended stack frame information for LLDB.
///
/// Contains additional LLDB-specific frame metadata beyond the basic
/// `LldbStackFrame`, including unwinding information and language info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbFrameDetails {
    /// Frame level.
    pub level: u32,
    /// Whether this frame is an artificial/thunk frame.
    pub is_artificial: bool,
    /// Source file path, if known.
    pub source_file: Option<String>,
    /// Source line number, if known.
    pub source_line: Option<u32>,
    /// Language of the function (e.g. "c", "c++", "rust", "swift").
    pub language: Option<String>,
    /// Whether the frame corresponds to a signal handler.
    pub is_signal_frame: bool,
    /// Whether this is an inline frame.
    ///
    /// LLDB can unwind inline frames when debug info is available.
    /// This corresponds to `SBFrame.IsInlined()`.
    pub is_inline: bool,
    /// Compiler-specific frame flags.
    pub flags: u32,
}

impl LldbFrameDetails {
    /// Create frame details for a given level.
    pub fn new(level: u32) -> Self {
        Self {
            level,
            is_artificial: false,
            source_file: None,
            source_line: None,
            language: None,
            is_signal_frame: false,
            is_inline: false,
            flags: 0,
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

    /// Set language.
    pub fn with_language(mut self, lang: impl Into<String>) -> Self {
        self.language = Some(lang.into());
        self
    }

    /// Mark as signal frame.
    pub fn with_signal_frame(mut self, signal: bool) -> Self {
        self.is_signal_frame = signal;
        self
    }

    /// Mark as inline frame.
    pub fn with_inline(mut self, inline: bool) -> Self {
        self.is_inline = inline;
        self
    }

    /// Build a display string including source location.
    pub fn build_display(&self, pc: u64, function_name: Option<&str>) -> String {
        let mut display = format!("#{} 0x{:x}", self.level, pc);
        if self.is_inline {
            display += " [inlined]";
        }
        if let Some(name) = function_name {
            display += &format!(" {}", name);
        }
        if let (Some(file), Some(line)) = (&self.source_file, self.source_line) {
            display += &format!(" at {}:{}", file, line);
        }
        display
    }
}

/// A thread collection manager for an LLDB process.
///
/// Manages thread lifecycle events (creation, exit) and provides
/// bulk operations on the thread set.
#[derive(Debug, Default)]
pub struct LldbThreadCollection {
    threads: BTreeMap<u32, LldbThread>,
    process_index: u32,
}

impl LldbThreadCollection {
    /// Create a new thread collection for a process.
    pub fn new(process_index: u32) -> Self {
        Self {
            threads: BTreeMap::new(),
            process_index,
        }
    }

    /// Add or replace a thread.
    pub fn insert(&mut self, thread: LldbThread) {
        self.threads.insert(thread.index, thread);
    }

    /// Remove a thread by index.
    pub fn remove(&mut self, index: u32) -> Option<LldbThread> {
        self.threads.remove(&index)
    }

    /// Get a thread by index.
    pub fn get(&self, index: u32) -> Option<&LldbThread> {
        self.threads.get(&index)
    }

    /// Get a mutable thread by index.
    pub fn get_mut(&mut self, index: u32) -> Option<&mut LldbThread> {
        self.threads.get_mut(&index)
    }

    /// Get the number of threads.
    pub fn len(&self) -> usize {
        self.threads.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }

    /// Get all thread indices.
    pub fn indices(&self) -> Vec<u32> {
        self.threads.keys().copied().collect()
    }

    /// Iterate over threads.
    pub fn iter(&self) -> impl Iterator<Item = &LldbThread> {
        self.threads.values()
    }

    /// Mark all threads as synchronized.
    pub fn mark_all_synced(&mut self) {
        for t in self.threads.values_mut() {
            t.mark_synced();
        }
    }

    /// Remove all exited threads and return their indices.
    pub fn prune_exited(&mut self) -> Vec<u32> {
        let exited: Vec<u32> = self
            .threads
            .iter()
            .filter(|(_, t)| t.state == ExecutionState::Exited)
            .map(|(&idx, _)| idx)
            .collect();
        for idx in &exited {
            self.threads.remove(idx);
        }
        exited
    }

    /// Clear all frames from all threads (used before re-syncing).
    pub fn clear_all_frames(&mut self) {
        for t in self.threads.values_mut() {
            t.clear_frames();
        }
    }

    /// Get the process index this collection belongs to.
    pub fn process_index(&self) -> u32 {
        self.process_index
    }

    /// Build thread info list for the common agent interface.
    pub fn build_thread_info_list(&self) -> Vec<ThreadInfo> {
        self.threads.values().map(|t| t.to_thread_info()).collect()
    }
}

/// Tracks the event thread for a trace.
///
/// Ported from `put_event_thread` in `commands.py`. The event thread
/// is the thread that caused the most recent stop event.
#[derive(Debug, Clone, Default)]
pub struct LldbEventThreadTracker {
    /// The process index of the event thread, if any.
    pub process_index: Option<u32>,
    /// The thread index of the event thread, if any.
    pub thread_index: Option<u32>,
}

impl LldbEventThreadTracker {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the event thread.
    pub fn set(&mut self, process_index: u32, thread_index: u32) {
        self.process_index = Some(process_index);
        self.thread_index = Some(thread_index);
    }

    /// Clear the event thread.
    pub fn clear(&mut self) {
        self.process_index = None;
        self.thread_index = None;
    }

    /// Get the event thread's trace path, if set.
    pub fn trace_path(&self) -> Option<String> {
        match (self.process_index, self.thread_index) {
            (Some(proc_idx), Some(t_idx)) => {
                Some(format!("Processes[{}].Threads[{}]", proc_idx, t_idx))
            }
            _ => None,
        }
    }

    /// Check if a specific thread is the event thread.
    pub fn is_event_thread(&self, process_index: u32, thread_index: u32) -> bool {
        self.process_index == Some(process_index) && self.thread_index == Some(thread_index)
    }
}

/// Helper for frame selection tracking.
///
/// Ported from the `restore_frame` context manager in `commands.py`.
#[derive(Debug, Clone, Default)]
pub struct LldbFrameSelection {
    /// The currently selected process.
    pub process_index: Option<u32>,
    /// The currently selected thread.
    pub thread_index: Option<u32>,
    /// The currently selected frame level.
    pub frame_level: Option<u32>,
}

impl LldbFrameSelection {
    /// Create a new frame selection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the complete selection.
    pub fn set(&mut self, process_index: u32, thread_index: u32, frame_level: u32) {
        self.process_index = Some(process_index);
        self.thread_index = Some(thread_index);
        self.frame_level = Some(frame_level);
    }

    /// Clear the selection.
    pub fn clear(&mut self) {
        self.process_index = None;
        self.thread_index = None;
        self.frame_level = None;
    }

    /// Get the frame trace path, if fully set.
    pub fn frame_path(&self) -> Option<String> {
        match (self.process_index, self.thread_index, self.frame_level) {
            (Some(p), Some(t), Some(f)) => {
                Some(format!("Processes[{}].Threads[{}].Stack[{}]", p, t, f))
            }
            _ => None,
        }
    }

    /// Get the thread trace path, if set.
    pub fn thread_path(&self) -> Option<String> {
        match (self.process_index, self.thread_index) {
            (Some(p), Some(t)) => Some(format!("Processes[{}].Threads[{}]", p, t)),
            _ => None,
        }
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
    /// Register banks (groups) for this frame.
    ///
    /// In LLDB, registers are organized into banks such as
    /// "General Purpose Registers", "Floating Point Registers", etc.
    /// This is populated from `SBFrame.GetRegisters()`.
    ///
    /// Ported from the `putreg` function's bank iteration in `commands.py`.
    #[serde(skip)]
    pub register_banks: Vec<LldbRegisterGroup>,
}

/// A register group (bank) within a stack frame.
///
/// In LLDB, `SBFrame.GetRegisters()` returns a list of register groups
/// (e.g., "General Purpose Registers", "Floating Point Registers").
/// Each group contains register values that can be read/written together.
///
/// Ported from the `putreg` function in `commands.py` which iterates
/// `banks.GetFirstValueByName(DEFAULT_REGISTER_BANK)`.
#[derive(Debug, Clone)]
pub struct LldbRegisterGroup {
    /// Group/bank name (e.g., "General Purpose Registers").
    pub name: String,
    /// Register values in this group.
    pub registers: Vec<RegisterValue>,
    /// Whether this is the primary register group.
    pub is_primary: bool,
}

impl LldbRegisterGroup {
    /// Create a new register group.
    pub fn new(name: impl Into<String>) -> Self {
        let name_str = name.into();
        let auto_primary = name_str == "General Purpose Registers";
        Self {
            name: name_str,
            registers: Vec::new(),
            is_primary: auto_primary,
        }
    }

    /// Set whether this is the primary group.
    pub fn with_primary(mut self, primary: bool) -> Self {
        self.is_primary = primary;
        self
    }

    /// Add a register value to this group.
    pub fn add_register(&mut self, reg: RegisterValue) {
        self.registers.retain(|r| r.name != reg.name);
        self.registers.push(reg);
    }

    /// Get a register by name.
    pub fn get_register(&self, name: &str) -> Option<&RegisterValue> {
        self.registers.iter().find(|r| r.name == name)
    }

    /// Get all register names in this group.
    pub fn register_names(&self) -> Vec<&str> {
        self.registers.iter().map(|r| r.name.as_str()).collect()
    }

    /// Number of registers in this group.
    pub fn len(&self) -> usize {
        self.registers.len()
    }

    /// Check if this group is empty.
    pub fn is_empty(&self) -> bool {
        self.registers.is_empty()
    }

    /// Clear all registers in this group.
    pub fn clear(&mut self) {
        self.registers.clear();
    }
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
            register_banks: Vec::new(),
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

    /// Build the retain keys for register names.
    pub fn build_register_retain_keys(&self) -> Vec<String> {
        self.registers
            .iter()
            .map(|r| r.name.clone())
            .collect()
    }

    /// Add a register bank (group) to this frame.
    ///
    /// Ported from the bank iteration in `putreg` in `commands.py`.
    pub fn add_register_bank(&mut self, bank: LldbRegisterGroup) {
        self.register_banks.retain(|b| b.name != bank.name);
        self.register_banks.push(bank);
    }

    /// Get a register bank by name.
    pub fn get_register_bank(&self, name: &str) -> Option<&LldbRegisterGroup> {
        self.register_banks.iter().find(|b| b.name == name)
    }

    /// Get a mutable register bank by name.
    pub fn get_register_bank_mut(&mut self, name: &str) -> Option<&mut LldbRegisterGroup> {
        self.register_banks.iter_mut().find(|b| b.name == name)
    }

    /// Get the primary register bank (General Purpose Registers).
    ///
    /// This is the bank used by default in the Python agent's `putreg`.
    pub fn primary_register_bank(&self) -> Option<&LldbRegisterGroup> {
        self.register_banks.iter().find(|b| b.is_primary)
    }

    /// Get the number of register banks.
    pub fn register_bank_count(&self) -> usize {
        self.register_banks.len()
    }

    /// Get all register bank names.
    pub fn register_bank_names(&self) -> Vec<&str> {
        self.register_banks.iter().map(|b| b.name.as_str()).collect()
    }

    /// Check if this frame has register banks.
    pub fn has_register_banks(&self) -> bool {
        !self.register_banks.is_empty()
    }

    /// Get the total number of registers across all banks.
    pub fn total_register_count(&self) -> usize {
        self.register_banks.iter().map(|b| b.len()).sum()
    }

    /// Get a register value from any bank by name.
    ///
    /// Searches all banks for the register.
    pub fn get_register_from_banks(&self, name: &str) -> Option<&RegisterValue> {
        for bank in &self.register_banks {
            if let Some(reg) = bank.get_register(name) {
                return Some(reg);
            }
        }
        None
    }

    /// Build the trace path for a specific register bank.
    pub fn bank_trace_path(&self, process_index: u32, thread_index: u32, bank_name: &str) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}].Registers.{}",
            process_index, thread_index, self.level, bank_name
        )
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
    fn test_thread_state_from_trace_str() {
        assert_eq!(LldbThreadState::from_trace_str("RUNNING"), LldbThreadState::Running);
        assert_eq!(LldbThreadState::from_trace_str("STOPPED"), LldbThreadState::Stopped);
        assert_eq!(LldbThreadState::from_trace_str("TERMINATED"), LldbThreadState::Exited);
        assert_eq!(LldbThreadState::from_trace_str("SUSPENDED"), LldbThreadState::Suspended);
        assert_eq!(LldbThreadState::from_trace_str("INACTIVE"), LldbThreadState::Inactive);
        assert_eq!(LldbThreadState::from_trace_str("UNKNOWN"), LldbThreadState::Inactive);
    }

    #[test]
    fn test_thread_state_properties() {
        assert!(LldbThreadState::Stopped.is_resumable());
        assert!(!LldbThreadState::Running.is_resumable());
        assert!(LldbThreadState::Running.is_alive());
        assert!(LldbThreadState::Stopped.is_alive());
        assert!(LldbThreadState::Suspended.is_alive());
        assert!(!LldbThreadState::Exited.is_alive());
        assert!(!LldbThreadState::Inactive.is_alive());
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
        assert!(t.detailed_stop_reason.is_none());
        assert!(t.queue_name.is_none());
        assert!(t.display.is_none());
        assert!(t.short_display.is_none());
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
    fn test_thread_builder_detailed_stop() {
        let reason = LldbDetailedStopReason::Breakpoint {
            bp_id: 1,
            bp_location_id: 1,
            address: 0x401000,
        };
        let t = LldbThread::new(1, 0)
            .with_detailed_stop_reason(reason.clone())
            .with_display("Thread 1 main");
        assert_eq!(t.detailed_stop_reason, Some(reason));
        assert_eq!(t.display, Some("Thread 1 main".to_string()));
    }

    #[test]
    fn test_thread_trace_path() {
        let t = LldbThread::new(2, 1);
        assert_eq!(t.trace_path(), "Processes[1].Threads[2]");
        assert_eq!(t.stack_path(), "Processes[1].Threads[2].Stack");
        assert_eq!(t.frame_path(0), "Processes[1].Threads[2].Stack[0]");
        assert_eq!(t.frame_registers_path(1), "Processes[1].Threads[2].Stack[1].Registers");
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

    #[test]
    fn test_thread_frames_sorted() {
        let mut t = LldbThread::new(1, 0);
        t.add_frame(LldbStackFrame::new(2, 0x403000));
        t.add_frame(LldbStackFrame::new(0, 0x401000));
        t.add_frame(LldbStackFrame::new(1, 0x402000));
        let sorted = t.frames_sorted();
        assert_eq!(sorted[0].level, 0);
        assert_eq!(sorted[1].level, 1);
        assert_eq!(sorted[2].level, 2);
    }

    #[test]
    fn test_thread_outermost_frame() {
        let mut t = LldbThread::new(1, 0);
        t.add_frame(LldbStackFrame::new(0, 0x401000));
        t.add_frame(LldbStackFrame::new(1, 0x402000));
        t.add_frame(LldbStackFrame::new(2, 0x403000));
        let outer = t.outermost_frame();
        assert!(outer.is_some());
        assert_eq!(outer.unwrap().level, 2);
        assert_eq!(outer.unwrap().pc, 0x403000);
    }

    #[test]
    fn test_thread_build_backtrace() {
        let mut t = LldbThread::new(1, 0);
        t.add_frame(LldbStackFrame::new(0, 0x401000).with_function("main"));
        t.add_frame(LldbStackFrame::new(1, 0x402000).with_function("foo"));
        let bt = t.build_backtrace();
        assert_eq!(bt.len(), 2);
        assert!(bt[0].contains("main"));
        assert!(bt[1].contains("foo"));
    }

    #[test]
    fn test_thread_build_stack_container_values() {
        let mut t = LldbThread::new(1, 0);
        t.add_frame(LldbStackFrame::new(0, 0x401000));
        t.add_frame(LldbStackFrame::new(1, 0x402000));
        let values = t.build_stack_container_values();
        assert!(values.iter().any(|(k, v)| k == "_count" && v == "2"));
    }

    #[test]
    fn test_thread_all_register_names() {
        let mut t = LldbThread::new(1, 0);
        let mut f0 = LldbStackFrame::new(0, 0x401000);
        f0.set_register(RegisterValue::from_u64("x0", 1));
        f0.set_register(RegisterValue::from_u64("x1", 2));
        t.add_frame(f0);
        let mut f1 = LldbStackFrame::new(1, 0x402000);
        f1.set_register(RegisterValue::from_u64("x0", 3));
        f1.set_register(RegisterValue::from_u64("pc", 4));
        t.add_frame(f1);

        let names = t.all_register_names();
        assert_eq!(names.len(), 3); // x0, x1, pc
        assert!(names.contains(&"x0".to_string()));
        assert!(names.contains(&"x1".to_string()));
        assert!(names.contains(&"pc".to_string()));
    }

    #[test]
    fn test_thread_frame_at_pc() {
        let mut t = LldbThread::new(1, 0);
        t.add_frame(LldbStackFrame::new(0, 0x401000));
        t.add_frame(LldbStackFrame::new(1, 0x402000));
        assert!(t.frame_at_pc(0x401000).is_some());
        assert!(t.frame_at_pc(0x403000).is_none());
    }

    #[test]
    fn test_thread_return_address() {
        let mut t = LldbThread::new(1, 0);
        assert!(t.return_address().is_none());

        t.add_frame(LldbStackFrame::new(0, 0x401000).with_return_address(0x401100));
        assert_eq!(t.return_address(), Some(0x401100));
    }

    #[test]
    fn test_thread_stopped_at_breakpoint() {
        let t = LldbThread::new(1, 0)
            .with_state(ExecutionState::Stopped)
            .with_stop_reason(LldbStopReason::Breakpoint);
        assert!(t.stopped_at_breakpoint());
        assert!(!t.stopped_by_signal());
        assert!(!t.stopped_at_step());
    }

    #[test]
    fn test_thread_stopped_by_signal() {
        let t = LldbThread::new(1, 0)
            .with_state(ExecutionState::Stopped)
            .with_stop_reason(LldbStopReason::Signal);
        assert!(t.stopped_by_signal());
        assert!(!t.stopped_at_breakpoint());
    }

    #[test]
    fn test_thread_stopped_at_step() {
        let t = LldbThread::new(1, 0)
            .with_state(ExecutionState::Stopped)
            .with_stop_reason(LldbStopReason::PlanComplete);
        assert!(t.stopped_at_step());
    }

    #[test]
    fn test_thread_state_queries() {
        let t_running = LldbThread::new(1, 0).with_state(ExecutionState::Running);
        assert!(t_running.is_running());
        assert!(!t_running.is_stopped());
        assert!(!t_running.is_exited());
        assert!(t_running.is_alive());

        let t_stopped = LldbThread::new(2, 0).with_state(ExecutionState::Stopped);
        assert!(!t_stopped.is_running());
        assert!(t_stopped.is_stopped());
        assert!(t_stopped.is_alive());

        let t_exited = LldbThread::new(3, 0).with_state(ExecutionState::Exited);
        assert!(t_exited.is_exited());
        assert!(!t_exited.is_alive());
    }

    #[test]
    fn test_thread_frame_retain_keys() {
        let mut t = LldbThread::new(1, 0);
        t.add_frame(LldbStackFrame::new(0, 0x401000));
        t.add_frame(LldbStackFrame::new(2, 0x403000));
        let keys = t.build_frame_retain_keys();
        assert!(keys.contains(&"[0]".to_string()));
        assert!(keys.contains(&"[2]".to_string()));
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_thread_update_short_display() {
        let mut t = LldbThread::new(1, 0).with_tid(0x1234);
        t.update_short_display(16);
        assert_eq!(t.short_display, Some("[0.1:0x1234]".to_string()));
    }

    #[test]
    fn test_thread_detailed_stop_reason_description() {
        let t = LldbThread::new(1, 0).with_detailed_stop_reason(
            LldbDetailedStopReason::Breakpoint {
                bp_id: 1,
                bp_location_id: 1,
                address: 0x401000,
            },
        );
        let desc = t.detailed_stop_reason_description();
        assert!(desc.is_some());
        assert!(desc.unwrap().contains("Breakpoint"));
    }

    #[test]
    fn test_stack_frame_register_retain_keys() {
        let mut f = LldbStackFrame::new(0, 0x401000);
        f.set_register(RegisterValue::from_u64("x0", 0x1234));
        f.set_register(RegisterValue::from_u64("x1", 0x5678));
        let retain = f.build_register_retain_keys();
        assert!(retain.contains(&"x0".to_string()));
        assert!(retain.contains(&"x1".to_string()));
    }
}

#[cfg(test)]
mod step_tests {
    use super::*;

    #[test]
    fn test_step_type_commands() {
        assert_eq!(LldbStepType::Over.as_lldb_command(), "thread step-over");
        assert_eq!(LldbStepType::Into.as_lldb_command(), "thread step-in");
        assert_eq!(LldbStepType::Out.as_lldb_command(), "thread step-out");
        assert_eq!(LldbStepType::Instruction.as_lldb_command(), "thread step-inst");
    }

    #[test]
    fn test_step_type_descriptions() {
        assert_eq!(LldbStepType::Over.description(), "Step Over");
        assert_eq!(LldbStepType::Into.description(), "Step Into");
    }
}

#[cfg(test)]
mod plan_tests {
    use super::*;

    #[test]
    fn test_thread_plan_step() {
        let plan = LldbThreadPlan::step(LldbStepType::Over);
        assert_eq!(plan.step_type, Some(LldbStepType::Over));
        assert!(!plan.completed);
        assert!(plan.stop_address.is_none());
    }

    #[test]
    fn test_thread_plan_run_to_address() {
        let plan = LldbThreadPlan::run_to_address(0x401000);
        assert_eq!(plan.stop_address, Some(0x401000));
        assert!(plan.step_type.is_none());
        assert!(plan.description.contains("0x401000"));
    }

    #[test]
    fn test_thread_plan_completion() {
        let mut plan = LldbThreadPlan::step_out();
        assert!(!plan.completed);
        plan.mark_complete();
        assert!(plan.completed);
    }
}

#[cfg(test)]
mod frame_details_tests {
    use super::*;

    #[test]
    fn test_frame_details() {
        let details = LldbFrameDetails::new(0)
            .with_source("/path/to/main.c", 42)
            .with_language("c")
            .with_signal_frame(false);
        assert_eq!(details.level, 0);
        assert_eq!(details.source_file.as_deref(), Some("/path/to/main.c"));
        assert_eq!(details.source_line, Some(42));
        assert_eq!(details.language.as_deref(), Some("c"));
        assert!(!details.is_signal_frame);
    }

    #[test]
    fn test_frame_details_display() {
        let details = LldbFrameDetails::new(0).with_source("main.c", 10);
        let display = details.build_display(0x401000, Some("main"));
        assert!(display.contains("#0"));
        assert!(display.contains("0x401000"));
        assert!(display.contains("main"));
        assert!(display.contains("main.c:10"));
    }

    #[test]
    fn test_frame_details_no_source() {
        let details = LldbFrameDetails::new(1);
        let display = details.build_display(0x402000, Some("foo"));
        assert!(display.contains("#1"));
        assert!(display.contains("foo"));
        assert!(!display.contains("at"));
    }
}

#[cfg(test)]
mod collection_tests {
    use super::*;

    #[test]
    fn test_thread_collection() {
        let mut coll = LldbThreadCollection::new(0);
        assert!(coll.is_empty());
        assert_eq!(coll.process_index(), 0);

        coll.insert(LldbThread::new(1, 0).with_state(ExecutionState::Running));
        coll.insert(LldbThread::new(2, 0).with_state(ExecutionState::Stopped));
        assert_eq!(coll.len(), 2);
        assert_eq!(coll.indices(), vec![1, 2]);
    }

    #[test]
    fn test_thread_collection_prune() {
        let mut coll = LldbThreadCollection::new(0);
        coll.insert(LldbThread::new(1, 0).with_state(ExecutionState::Running));
        coll.insert(LldbThread::new(2, 0).with_state(ExecutionState::Exited));
        coll.insert(LldbThread::new(3, 0).with_state(ExecutionState::Exited));

        let pruned = coll.prune_exited();
        assert_eq!(pruned.len(), 2);
        assert!(pruned.contains(&2));
        assert!(pruned.contains(&3));
        assert_eq!(coll.len(), 1);
        assert!(coll.get(1).is_some());
    }

    #[test]
    fn test_thread_collection_clear_all_frames() {
        let mut coll = LldbThreadCollection::new(0);
        let mut t1 = LldbThread::new(1, 0);
        t1.add_frame(LldbStackFrame::new(0, 0x401000));
        let mut t2 = LldbThread::new(2, 0);
        t2.add_frame(LldbStackFrame::new(0, 0x402000));
        t2.add_frame(LldbStackFrame::new(1, 0x403000));
        coll.insert(t1);
        coll.insert(t2);

        coll.clear_all_frames();
        assert_eq!(coll.get(1).unwrap().frame_count(), 0);
        assert_eq!(coll.get(2).unwrap().frame_count(), 0);
    }

    #[test]
    fn test_thread_collection_mark_all_synced() {
        let mut coll = LldbThreadCollection::new(0);
        coll.insert(LldbThread::new(1, 0));
        coll.insert(LldbThread::new(2, 0));
        coll.mark_all_synced();
        assert!(coll.get(1).unwrap().synced);
        assert!(coll.get(2).unwrap().synced);
    }

    #[test]
    fn test_thread_collection_iter() {
        let mut coll = LldbThreadCollection::new(0);
        coll.insert(LldbThread::new(1, 0));
        coll.insert(LldbThread::new(2, 0));
        let count = coll.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_thread_collection_build_info_list() {
        let mut coll = LldbThreadCollection::new(0);
        coll.insert(
            LldbThread::new(1, 0)
                .with_tid(100)
                .with_name("main")
                .with_state(ExecutionState::Running),
        );
        let list = coll.build_thread_info_list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, 100);
        assert_eq!(list[0].name.as_deref(), Some("main"));
    }
}

#[cfg(test)]
mod detailed_stop_reason_tests {
    use super::*;

    #[test]
    fn test_detailed_stop_reason_breakpoint() {
        let reason = LldbDetailedStopReason::Breakpoint {
            bp_id: 1,
            bp_location_id: 1,
            address: 0x401000,
        };
        assert!(reason.is_stopped());
        assert!(reason.description().contains("Breakpoint"));
        assert_eq!(reason.to_simple(), super::super::LldbStopReason::Breakpoint);
    }

    #[test]
    fn test_detailed_stop_reason_signal() {
        let reason = LldbDetailedStopReason::Signal {
            name: "SIGSEGV".to_string(),
            number: 11,
        };
        assert!(reason.is_stopped());
        assert!(reason.description().contains("SIGSEGV"));
        assert_eq!(reason.to_simple(), super::super::LldbStopReason::Signal);
    }

    #[test]
    fn test_detailed_stop_reason_exited() {
        let reason = LldbDetailedStopReason::Exited { code: 0 };
        assert!(!reason.is_stopped());
    }

    #[test]
    fn test_detailed_stop_reason_exited_signal() {
        let reason = LldbDetailedStopReason::ExitedSignal {
            signal: "SIGKILL".to_string(),
        };
        assert!(!reason.is_stopped());
    }
}

#[cfg(test)]
mod event_thread_tests {
    use super::*;

    #[test]
    fn test_event_thread_tracker() {
        let mut tracker = LldbEventThreadTracker::new();
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
}

#[cfg(test)]
mod frame_selection_tests {
    use super::*;

    #[test]
    fn test_frame_selection() {
        let mut sel = LldbFrameSelection::new();
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
}

#[cfg(test)]
mod register_bank_tests {
    use super::*;

    #[test]
    fn test_register_group_new() {
        let group = LldbRegisterGroup::new("General Purpose Registers");
        assert_eq!(group.name, "General Purpose Registers");
        assert!(group.is_primary);
        assert!(group.is_empty());
        assert_eq!(group.len(), 0);
    }

    #[test]
    fn test_register_group_not_primary() {
        let group = LldbRegisterGroup::new("Floating Point Registers");
        assert!(!group.is_primary);
    }

    #[test]
    fn test_register_group_with_primary() {
        let group = LldbRegisterGroup::new("Custom Registers")
            .with_primary(true);
        assert!(group.is_primary);
    }

    #[test]
    fn test_register_group_add_register() {
        let mut group = LldbRegisterGroup::new("General Purpose Registers");
        group.add_register(RegisterValue::from_u64("rax", 0x1234));
        group.add_register(RegisterValue::from_u64("rbx", 0x5678));
        assert_eq!(group.len(), 2);
        assert!(!group.is_empty());

        // Replace same name
        group.add_register(RegisterValue::from_u64("rax", 0xabcd));
        assert_eq!(group.len(), 2);
        assert_eq!(group.get_register("rax").unwrap().as_u64(), Some(0xabcd));
    }

    #[test]
    fn test_register_group_get_register() {
        let mut group = LldbRegisterGroup::new("GPR");
        group.add_register(RegisterValue::from_u64("x0", 42));
        assert!(group.get_register("x0").is_some());
        assert!(group.get_register("x1").is_none());
    }

    #[test]
    fn test_register_group_names() {
        let mut group = LldbRegisterGroup::new("GPR");
        group.add_register(RegisterValue::from_u64("x0", 1));
        group.add_register(RegisterValue::from_u64("x1", 2));
        group.add_register(RegisterValue::from_u64("pc", 3));
        let names = group.register_names();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"x0"));
        assert!(names.contains(&"x1"));
        assert!(names.contains(&"pc"));
    }

    #[test]
    fn test_register_group_clear() {
        let mut group = LldbRegisterGroup::new("GPR");
        group.add_register(RegisterValue::from_u64("x0", 1));
        group.clear();
        assert!(group.is_empty());
    }

    #[test]
    fn test_stack_frame_register_banks() {
        let mut f = LldbStackFrame::new(0, 0x401000);

        let mut gpr = LldbRegisterGroup::new("General Purpose Registers");
        gpr.add_register(RegisterValue::from_u64("rax", 0x1234));
        gpr.add_register(RegisterValue::from_u64("rbx", 0x5678));

        let mut fpr = LldbRegisterGroup::new("Floating Point Registers");
        fpr.add_register(RegisterValue::from_u64("xmm0", 0));

        f.add_register_bank(gpr);
        f.add_register_bank(fpr);

        assert_eq!(f.register_bank_count(), 2);
        assert!(f.has_register_banks());
        assert_eq!(f.total_register_count(), 3);

        let bank_names = f.register_bank_names();
        assert!(bank_names.contains(&"General Purpose Registers"));
        assert!(bank_names.contains(&"Floating Point Registers"));
    }

    #[test]
    fn test_stack_frame_primary_bank() {
        let mut f = LldbStackFrame::new(0, 0x401000);

        let mut fpr = LldbRegisterGroup::new("Floating Point Registers");
        fpr.add_register(RegisterValue::from_u64("xmm0", 0));
        f.add_register_bank(fpr);

        assert!(f.primary_register_bank().is_none());

        let mut gpr = LldbRegisterGroup::new("General Purpose Registers");
        gpr.add_register(RegisterValue::from_u64("rax", 0x1234));
        f.add_register_bank(gpr);

        let primary = f.primary_register_bank();
        assert!(primary.is_some());
        assert_eq!(primary.unwrap().name, "General Purpose Registers");
    }

    #[test]
    fn test_stack_frame_get_register_bank() {
        let mut f = LldbStackFrame::new(0, 0x401000);
        let gpr = LldbRegisterGroup::new("General Purpose Registers");
        f.add_register_bank(gpr);

        assert!(f.get_register_bank("General Purpose Registers").is_some());
        assert!(f.get_register_bank("Floating Point Registers").is_none());
    }

    #[test]
    fn test_stack_frame_get_register_from_banks() {
        let mut f = LldbStackFrame::new(0, 0x401000);

        let mut gpr = LldbRegisterGroup::new("General Purpose Registers");
        gpr.add_register(RegisterValue::from_u64("rax", 0x1234));
        f.add_register_bank(gpr);

        let mut fpr = LldbRegisterGroup::new("Floating Point Registers");
        fpr.add_register(RegisterValue::from_u64("xmm0", 0xabcd));
        f.add_register_bank(fpr);

        assert!(f.get_register_from_banks("rax").is_some());
        assert_eq!(f.get_register_from_banks("rax").unwrap().as_u64(), Some(0x1234));
        assert!(f.get_register_from_banks("xmm0").is_some());
        assert!(f.get_register_from_banks("nonexistent").is_none());
    }

    #[test]
    fn test_stack_frame_bank_trace_path() {
        let f = LldbStackFrame::new(2, 0x401000);
        assert_eq!(
            f.bank_trace_path(1, 3, "General Purpose Registers"),
            "Processes[1].Threads[3].Stack[2].Registers.General Purpose Registers"
        );
    }

    #[test]
    fn test_stack_frame_register_bank_replace() {
        let mut f = LldbStackFrame::new(0, 0x401000);

        let mut gpr1 = LldbRegisterGroup::new("GPR");
        gpr1.add_register(RegisterValue::from_u64("rax", 1));
        f.add_register_bank(gpr1);

        // Replace same name
        let mut gpr2 = LldbRegisterGroup::new("GPR");
        gpr2.add_register(RegisterValue::from_u64("rax", 2));
        gpr2.add_register(RegisterValue::from_u64("rbx", 3));
        f.add_register_bank(gpr2);

        assert_eq!(f.register_bank_count(), 1);
        let bank = f.get_register_bank("GPR").unwrap();
        assert_eq!(bank.len(), 2);
    }
}

#[cfg(test)]
mod thread_event_tests {
    use super::*;

    #[test]
    fn test_thread_event_created() {
        let event = LldbThreadEvent::Created {
            process_index: 0,
            thread_index: 1,
        };
        assert_eq!(event.process_index(), 0);
        assert_eq!(event.thread_index(), 1);
        assert!(event.description().contains("created"));
    }

    #[test]
    fn test_thread_event_exited() {
        let event = LldbThreadEvent::Exited {
            process_index: 1,
            thread_index: 2,
        };
        assert_eq!(event.process_index(), 1);
        assert_eq!(event.thread_index(), 2);
        assert!(event.description().contains("exited"));
    }

    #[test]
    fn test_thread_event_state_changed() {
        let event = LldbThreadEvent::StateChanged {
            process_index: 0,
            thread_index: 1,
            new_state: ExecutionState::Running,
        };
        assert!(event.description().contains("RUNNING"));
    }

    #[test]
    fn test_thread_event_selected() {
        let event = LldbThreadEvent::Selected {
            process_index: 0,
            thread_index: 3,
        };
        assert!(event.description().contains("selected"));
    }
}

#[cfg(test)]
mod register_batch_tests {
    use super::*;

    #[test]
    fn test_frame_register_batch() {
        let mut batch = LldbFrameRegisterBatch::new(0);
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);

        batch.push(RegisterValue::from_u64("x0", 0x1234));
        batch.push(RegisterValue::from_u64("x1", 0x5678));
        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());

        assert!(batch.get("x0").is_some());
        assert_eq!(batch.get("x0").unwrap().as_u64(), Some(0x1234));
        assert!(batch.get("x2").is_none());

        let names = batch.names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"x0"));
        assert!(names.contains(&"x1"));
    }
}

#[cfg(test)]
mod frame_details_inline_tests {
    use super::*;

    #[test]
    fn test_frame_details_with_inline() {
        let details = LldbFrameDetails::new(0)
            .with_source("main.c", 10)
            .with_language("c")
            .with_inline(true);
        assert!(details.is_inline);
        assert_eq!(details.source_file.as_deref(), Some("main.c"));
    }

    #[test]
    fn test_frame_details_inline_display() {
        let details = LldbFrameDetails::new(0).with_inline(true);
        let display = details.build_display(0x401000, Some("inlined_fn"));
        assert!(display.contains("[inlined]"));
        assert!(display.contains("inlined_fn"));
    }

    #[test]
    fn test_frame_details_no_inline_display() {
        let details = LldbFrameDetails::new(0);
        let display = details.build_display(0x401000, Some("normal_fn"));
        assert!(!display.contains("[inlined]"));
    }
}

#[cfg(test)]
mod function_return_tests {
    use super::*;

    #[test]
    fn test_thread_stopped_at_function_return() {
        let t = LldbThread::new(1, 0)
            .with_state(ExecutionState::Stopped)
            .with_detailed_stop_reason(LldbDetailedStopReason::FunctionFinished {
                return_value: Some(42),
            });
        assert!(t.stopped_at_function_return());
    }

    #[test]
    fn test_thread_not_stopped_at_function_return() {
        let t = LldbThread::new(1, 0)
            .with_state(ExecutionState::Stopped)
            .with_stop_reason(super::super::LldbStopReason::Breakpoint);
        assert!(!t.stopped_at_function_return());
    }
}
