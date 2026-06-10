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
//! `put_frames`, `convert_state`, `convert_tid`, `compute_thread_display`,
//! `put_event_thread`, etc.).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::agents::{
    ExecutionState, RegisterValue, StackFrameInfo, ThreadInfo,
};

/// A register descriptor as returned by GDB's architecture API.
///
/// Ported from the Python `RegisterDesc` dataclass in `util.py` and
/// `gdb.RegisterDescriptor` in the GDB Python API. GDB 13+ provides
/// `Architecture.registers()` which returns register descriptors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDescriptor {
    /// Register name (e.g., "rax", "rip", "xmm0").
    pub name: String,
    /// Register group (e.g., "general", "float", "vector").
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

/// Thread event for the hook system.
///
/// Tracks thread lifecycle events that need to be synchronized
/// to the Ghidra trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreadEvent {
    /// A new thread was created.
    Created {
        /// Inferior number.
        inferior_num: u32,
        /// Thread number.
        thread_num: u32,
    },
    /// A thread has exited.
    Exited {
        /// Inferior number.
        inferior_num: u32,
        /// Thread number.
        thread_num: u32,
    },
    /// A thread's state has changed (running/stopped/etc).
    StateChanged {
        /// Inferior number.
        inferior_num: u32,
        /// Thread number.
        thread_num: u32,
        /// New execution state.
        new_state: ExecutionState,
    },
    /// A thread was selected by the user.
    Selected {
        /// Inferior number.
        inferior_num: u32,
        /// Thread number.
        thread_num: u32,
    },
}

impl ThreadEvent {
    /// Get the inferior number for this event.
    pub fn inferior_num(&self) -> u32 {
        match self {
            Self::Created { inferior_num, .. }
            | Self::Exited { inferior_num, .. }
            | Self::StateChanged { inferior_num, .. }
            | Self::Selected { inferior_num, .. } => *inferior_num,
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
            Self::Created { inferior_num, thread_num } => {
                format!("Thread {} created in inferior {}", thread_num, inferior_num)
            }
            Self::Exited { inferior_num, thread_num } => {
                format!("Thread {} exited in inferior {}", thread_num, inferior_num)
            }
            Self::StateChanged {
                inferior_num,
                thread_num,
                new_state,
            } => {
                format!(
                    "Thread {} in inferior {} -> {}",
                    thread_num,
                    inferior_num,
                    new_state.as_trace_str()
                )
            }
            Self::Selected { inferior_num, thread_num } => {
                format!("Thread {} selected in inferior {}", thread_num, inferior_num)
            }
        }
    }
}

/// Stepping mode for GDB thread operations.
///
/// Determines how GDB handles signals and breakpoints during stepping.
/// Ported from GDB's `nexti` / `stepi` / `next` / `step` semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SteppingMode {
    /// Single instruction step (stepi/nexti).
    Instruction,
    /// Source line step (step/next).
    SourceLine,
}

/// Thread execution history record.
///
/// Tracks the recent execution history of a thread for display
/// and debugging purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadHistoryEntry {
    /// Program counter at this point.
    pub pc: u64,
    /// Timestamp (relative to session start, in milliseconds).
    pub timestamp: u64,
    /// Stop reason at this point, if any.
    pub stop_reason: Option<ThreadStopReason>,
    /// Frame level.
    pub frame_level: u32,
}

impl ThreadHistoryEntry {
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
    pub fn with_stop_reason(mut self, reason: ThreadStopReason) -> Self {
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
/// for a thread.
#[derive(Debug, Clone)]
pub struct ThreadHistory {
    entries: Vec<ThreadHistoryEntry>,
    max_entries: usize,
}

impl ThreadHistory {
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
    pub fn push(&mut self, entry: ThreadHistoryEntry) {
        if self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    /// Get the most recent entry.
    pub fn latest(&self) -> Option<&ThreadHistoryEntry> {
        self.entries.last()
    }

    /// Get all entries (oldest first).
    pub fn entries(&self) -> &[ThreadHistoryEntry] {
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
    pub fn last_n(&self, n: usize) -> &[ThreadHistoryEntry] {
        let start = self.entries.len().saturating_sub(n);
        &self.entries[start..]
    }
}

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
    ///
    /// Ported from `convert_state` in `commands.py`.
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

    /// Create from a trace state string.
    pub fn from_trace_str(s: &str) -> Self {
        match s {
            "RUNNING" => Self::Running,
            "STOPPED" => Self::Stopped,
            "TERMINATED" => Self::Exited,
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
        matches!(self, Self::Running | Self::Stopped)
    }
}

/// Stop reason for a specific thread stop.
///
/// Captures why a thread stopped, corresponding to information from
/// GDB's stop event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreadStopReason {
    /// Breakpoint hit at address.
    Breakpoint { bp_number: u32, address: u64 },
    /// Watchpoint triggered.
    Watchpoint { wp_number: u32 },
    /// Signal received.
    Signal { name: String, number: i32 },
    /// Step completed.
    StepComplete,
    /// Function finished (return).
    FunctionFinished { return_value: Option<u64> },
    /// Exited with code.
    Exited { code: i32 },
    /// Exited by signal.
    ExitedSignal { signal: String },
    /// Unknown reason.
    Unknown,
}

impl ThreadStopReason {
    /// Human-readable description.
    pub fn description(&self) -> String {
        match self {
            Self::Breakpoint { bp_number, address } => {
                format!("Breakpoint {} at 0x{:x}", bp_number, address)
            }
            Self::Watchpoint { wp_number } => format!("Watchpoint {}", wp_number),
            Self::Signal { name, number } => format!("Signal {} ({})", name, number),
            Self::StepComplete => "Step complete".to_string(),
            Self::FunctionFinished { .. } => "Function finished".to_string(),
            Self::Exited { code } => format!("Exited with code {}", code),
            Self::ExitedSignal { signal } => format!("Exited with signal {}", signal),
            Self::Unknown => "Unknown stop reason".to_string(),
        }
    }

    /// Whether this stop reason implies the thread is stopped (can resume).
    pub fn is_stopped(&self) -> bool {
        !matches!(self, Self::Exited { .. } | Self::ExitedSignal { .. })
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
    /// Last known stop reason, if any.
    pub stop_reason: Option<ThreadStopReason>,
    /// Cached display string (from `info thread` output).
    pub display: Option<String>,
    /// Cached short display string.
    pub short_display: Option<String>,
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
            stop_reason: None,
            display: None,
            short_display: None,
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

    /// Set the display string.
    pub fn with_display(mut self, display: impl Into<String>) -> Self {
        self.display = Some(display.into());
        self
    }

    /// Set the stop reason.
    pub fn with_stop_reason(mut self, reason: ThreadStopReason) -> Self {
        self.stop_reason = Some(reason);
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

    /// Get the trace path for a specific frame in this thread.
    pub fn frame_path(&self, level: u32) -> String {
        format!(
            "Inferiors[{}].Threads[{}].Stack[{}]",
            self.inferior_num, self.num, level
        )
    }

    /// Get the trace path for a specific frame's registers.
    pub fn frame_registers_path(&self, level: u32) -> String {
        format!(
            "Inferiors[{}].Threads[{}].Stack[{}].Registers",
            self.inferior_num, self.num, level
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

    /// Get a mutable reference to a frame by level.
    pub fn get_frame_mut(&mut self, level: u32) -> Option<&mut GdbStackFrame> {
        self.frames.get_mut(&level)
    }

    /// Get the innermost frame (level 0).
    pub fn innermost_frame(&self) -> Option<&GdbStackFrame> {
        self.frames.get(&0)
    }

    /// Get the outermost frame (highest level).
    pub fn outermost_frame(&self) -> Option<&GdbStackFrame> {
        self.frames.values().next_back()
    }

    /// Get the number of frames.
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Get all frame levels in order (innermost to outermost).
    pub fn frame_levels(&self) -> Vec<u32> {
        self.frames.keys().copied().collect()
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
    /// Ported from `put_threads` in `commands.py`.
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
        if let Some(ref display) = self.display {
            values.push(("_display".to_string(), display.clone()));
        }
        if let Some(ref short) = self.short_display {
            values.push(("_short_display".to_string(), short.clone()));
        }
        values
    }

    /// Build the short display string for this thread.
    ///
    /// Format: `[inferior.thread:tid]`
    /// Ported from the `_short_display` computation in `put_threads`.
    pub fn build_short_display(&self, radix: u32) -> String {
        let tid = self.tid.unwrap_or(0);
        let tid_str = match radix {
            16 => format!("0x{:x}", tid),
            8 => format!("0{:o}", tid),
            _ => format!("{}", tid),
        };
        format!("[{}.{}:{}]", self.inferior_num, self.num, tid_str)
    }

    /// Update cached short display string.
    pub fn update_short_display(&mut self, radix: u32) {
        self.short_display = Some(self.build_short_display(radix));
    }

    /// Mark this thread as synchronized.
    pub fn mark_synced(&mut self) {
        self.synced = true;
    }

    /// Mark the thread as exited.
    ///
    /// Clears frames and stop reason.
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

    /// Get all frames sorted by level (innermost first).
    pub fn frames_sorted(&self) -> Vec<&GdbStackFrame> {
        let mut frames: Vec<_> = self.frames.values().collect();
        frames.sort_by_key(|f| f.level);
        frames
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
    pub fn frame_at_pc(&self, pc: u64) -> Option<&GdbStackFrame> {
        self.frames.values().find(|f| f.pc == pc)
    }

    /// Get the return address for the innermost frame.
    pub fn return_address(&self) -> Option<u64> {
        self.innermost_frame().map(|f| f.return_address).filter(|&ra| ra != 0)
    }

    /// Whether the thread was stopped by a breakpoint.
    pub fn stopped_at_breakpoint(&self) -> bool {
        matches!(
            self.stop_reason,
            Some(ThreadStopReason::Breakpoint { .. })
        )
    }

    /// Whether the thread was stopped by a signal.
    pub fn stopped_by_signal(&self) -> bool {
        matches!(
            self.stop_reason,
            Some(ThreadStopReason::Signal { .. })
        )
    }

    /// Whether the thread finished a step operation.
    pub fn stopped_at_step(&self) -> bool {
        self.stop_reason == Some(ThreadStopReason::StepComplete)
    }

    /// Whether the thread finished a function call.
    pub fn stopped_at_function_return(&self) -> bool {
        matches!(
            self.stop_reason,
            Some(ThreadStopReason::FunctionFinished { .. })
        )
    }
}

/// Stepping type for GDB thread operations.
///
/// Maps to GDB's `next`, `step`, `finish`, `nexti`, `stepi` commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GdbStepType {
    /// Step over (next source line / `next` command).
    Over,
    /// Step into (step into function calls / `step` command).
    Into,
    /// Step out (run until current function returns / `finish` command).
    Out,
    /// Step over one instruction (`nexti` command).
    InstructionOver,
    /// Step into one instruction (`stepi` command).
    InstructionInto,
}

impl GdbStepType {
    /// Convert to the GDB command string.
    pub fn as_gdb_command(&self) -> &'static str {
        match self {
            Self::Over => "next",
            Self::Into => "step",
            Self::Out => "finish",
            Self::InstructionOver => "nexti",
            Self::InstructionInto => "stepi",
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

/// Thread plan tracking for GDB.
///
/// GDB uses stepping commands that define what a thread should do before
/// stopping again. This struct tracks the active stepping plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdbThreadPlan {
    /// Plan description (e.g. "step over", "finish", "until 0x401000").
    pub description: String,
    /// The step type, if this is a standard stepping plan.
    pub step_type: Option<GdbStepType>,
    /// Target stop address (for `until <address>` plans).
    pub stop_address: Option<u64>,
    /// Whether the plan is complete.
    pub completed: bool,
}

impl GdbThreadPlan {
    /// Create a plan for a standard step.
    pub fn step(step_type: GdbStepType) -> Self {
        Self {
            description: step_type.description().to_string(),
            step_type: Some(step_type),
            stop_address: None,
            completed: false,
        }
    }

    /// Create a plan to run to an address (GDB `until <address>`).
    pub fn run_to_address(addr: u64) -> Self {
        Self {
            description: format!("until 0x{:x}", addr),
            step_type: None,
            stop_address: Some(addr),
            completed: false,
        }
    }

    /// Create a plan to step out of the current function.
    pub fn step_out() -> Self {
        Self::step(GdbStepType::Out)
    }

    /// Mark the plan as complete.
    pub fn mark_complete(&mut self) {
        self.completed = true;
    }
}

/// Extended stack frame information for GDB.
///
/// Contains additional GDB-specific frame metadata beyond the basic
/// `GdbStackFrame`, including source information and language info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdbFrameDetails {
    /// Frame level.
    pub level: u32,
    /// Whether this frame is an artificial/thunk frame.
    pub is_artificial: bool,
    /// Source file path, if known.
    pub source_file: Option<String>,
    /// Source line number, if known.
    pub source_line: Option<u32>,
    /// Language of the function (e.g. "c", "c++", "rust").
    pub language: Option<String>,
    /// Whether the frame corresponds to a signal handler.
    pub is_signal_frame: bool,
    /// Whether this is an inline frame.
    pub is_inline: bool,
}

impl GdbFrameDetails {
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
        if let Some(name) = function_name {
            display += &format!(" {}", name);
        }
        if let (Some(file), Some(line)) = (&self.source_file, self.source_line) {
            display += &format!(" at {}:{}", file, line);
        }
        display
    }
}

/// A thread collection manager for a GDB inferior.
///
/// Manages thread lifecycle events (creation, exit) and provides
/// bulk operations on the thread set.
#[derive(Debug, Default)]
pub struct GdbThreadCollection {
    threads: BTreeMap<u32, GdbThread>,
    inferior_num: u32,
}

impl GdbThreadCollection {
    /// Create a new thread collection for an inferior.
    pub fn new(inferior_num: u32) -> Self {
        Self {
            threads: BTreeMap::new(),
            inferior_num,
        }
    }

    /// Add or replace a thread.
    pub fn insert(&mut self, thread: GdbThread) {
        self.threads.insert(thread.num, thread);
    }

    /// Remove a thread by number.
    pub fn remove(&mut self, num: u32) -> Option<GdbThread> {
        self.threads.remove(&num)
    }

    /// Get a thread by number.
    pub fn get(&self, num: u32) -> Option<&GdbThread> {
        self.threads.get(&num)
    }

    /// Get a mutable thread by number.
    pub fn get_mut(&mut self, num: u32) -> Option<&mut GdbThread> {
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
    pub fn iter(&self) -> impl Iterator<Item = &GdbThread> {
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

    /// Get the inferior number this collection belongs to.
    pub fn inferior_num(&self) -> u32 {
        self.inferior_num
    }

    /// Build thread info list for the common agent interface.
    pub fn build_thread_info_list(&self) -> Vec<ThreadInfo> {
        self.threads.values().map(|t| t.to_thread_info()).collect()
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
    /// Cached display string for this frame.
    pub display: Option<String>,
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
            display: None,
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

    /// Set the display string.
    pub fn with_display(mut self, display: impl Into<String>) -> Self {
        self.display = Some(display.into());
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
    /// Ported from the `_display` computation in `put_frames`.
    pub fn build_display(&self) -> String {
        match &self.function_name {
            Some(name) => format!("#{} 0x{:x} {}", self.level, self.pc, name),
            None => format!("#{} 0x{:x}", self.level, self.pc),
        }
    }

    /// Get or compute the display string.
    pub fn display_string(&self) -> String {
        self.display
            .clone()
            .unwrap_or_else(|| self.build_display())
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
}

/// Tracks the event thread for a trace.
///
/// Ported from `put_event_thread` in `commands.py`. The event thread
/// is the thread that caused the most recent stop event.
#[derive(Debug, Clone, Default)]
pub struct EventThreadTracker {
    /// The inferior number of the event thread, if any.
    pub inferior_num: Option<u32>,
    /// The thread number of the event thread, if any.
    pub thread_num: Option<u32>,
}

impl EventThreadTracker {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the event thread.
    pub fn set(&mut self, inferior_num: u32, thread_num: u32) {
        self.inferior_num = Some(inferior_num);
        self.thread_num = Some(thread_num);
    }

    /// Clear the event thread.
    pub fn clear(&mut self) {
        self.inferior_num = None;
        self.thread_num = None;
    }

    /// Get the event thread's trace path, if set.
    pub fn trace_path(&self) -> Option<String> {
        match (self.inferior_num, self.thread_num) {
            (Some(inf), Some(t)) => Some(format!("Inferiors[{}].Threads[{}]", inf, t)),
            _ => None,
        }
    }

    /// Check if a specific thread is the event thread.
    pub fn is_event_thread(&self, inferior_num: u32, thread_num: u32) -> bool {
        self.inferior_num == Some(inferior_num) && self.thread_num == Some(thread_num)
    }
}

/// Helper for frame selection tracking.
///
/// Ported from the `restore_frame` context manager in `commands.py`.
#[derive(Debug, Clone, Default)]
pub struct FrameSelection {
    /// The currently selected inferior.
    pub inferior_num: Option<u32>,
    /// The currently selected thread.
    pub thread_num: Option<u32>,
    /// The currently selected frame level.
    pub frame_level: Option<u32>,
}

impl FrameSelection {
    /// Create a new frame selection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the complete selection.
    pub fn set(&mut self, inferior_num: u32, thread_num: u32, frame_level: u32) {
        self.inferior_num = Some(inferior_num);
        self.thread_num = Some(thread_num);
        self.frame_level = Some(frame_level);
    }

    /// Clear the selection.
    pub fn clear(&mut self) {
        self.inferior_num = None;
        self.thread_num = None;
        self.frame_level = None;
    }

    /// Get the frame trace path, if fully set.
    pub fn frame_path(&self) -> Option<String> {
        match (self.inferior_num, self.thread_num, self.frame_level) {
            (Some(inf), Some(t), Some(f)) => {
                Some(format!("Inferiors[{}].Threads[{}].Stack[{}]", inf, t, f))
            }
            _ => None,
        }
    }

    /// Get the thread trace path, if set.
    pub fn thread_path(&self) -> Option<String> {
        match (self.inferior_num, self.thread_num) {
            (Some(inf), Some(t)) => Some(format!("Inferiors[{}].Threads[{}]", inf, t)),
            _ => None,
        }
    }
}

/// Source information for a stack frame.
///
/// Extended source-level debugging info for a frame, including file path,
/// line number, and function demangled name. This is more detailed than
/// the basic `GdbFrameDetails` and corresponds to source info from
/// GDB's `info source` and `info line` commands.
///
/// Ported from the Python `put_frames` source info extraction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GdbFrameSourceInfo {
    /// Source file path.
    pub file: Option<String>,
    /// Source line number.
    pub line: Option<u32>,
    /// Full function name (possibly demangled).
    pub full_function: Option<String>,
    /// Compilation directory.
    pub compilation_dir: Option<String>,
    /// Whether source is available.
    pub source_available: bool,
}

impl GdbFrameSourceInfo {
    /// Create empty source info.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the source file and line.
    pub fn with_location(mut self, file: impl Into<String>, line: u32) -> Self {
        self.file = Some(file.into());
        self.line = Some(line);
        self.source_available = true;
        self
    }

    /// Set the full function name.
    pub fn with_function(mut self, func: impl Into<String>) -> Self {
        self.full_function = Some(func.into());
        self
    }

    /// Set the compilation directory.
    pub fn with_compilation_dir(mut self, dir: impl Into<String>) -> Self {
        self.compilation_dir = Some(dir.into());
        self
    }

    /// Build a display string for this source info.
    pub fn build_display(&self) -> Option<String> {
        match (&self.file, self.line) {
            (Some(file), Some(line)) => Some(format!("{}:{}", file, line)),
            (Some(file), None) => Some(file.clone()),
            _ => None,
        }
    }

    /// Get the full path including compilation directory if available.
    pub fn full_path(&self) -> Option<String> {
        match (&self.file, &self.compilation_dir) {
            (Some(file), Some(dir)) if !file.starts_with('/') => {
                Some(format!("{}/{}", dir, file))
            }
            (Some(file), _) => Some(file.clone()),
            _ => None,
        }
    }
}

/// Tracks which threads and frames have been synchronized to the trace
/// since the last stop event.
///
/// Ported from the `visited` set in `InferiorState` in `hooks.py`.
/// The agent uses this to avoid re-syncing thread and frame data that
/// hasn't changed.
#[derive(Debug, Clone, Default)]
pub struct GdbTraceSyncTracker {
    /// Threads that have been synced since the last stop.
    synced_threads: BTreeMap<u32, BTreeSet<u32>>,
    /// Frames that have been synced (inferior -> thread -> set of frame levels).
    synced_frames: BTreeMap<u32, BTreeMap<u32, BTreeSet<u32>>>,
    /// Registers that have been synced (inferior -> thread -> frame -> set of names).
    synced_registers: BTreeMap<u32, BTreeMap<u32, BTreeMap<u32, BTreeSet<String>>>>,
}

impl GdbTraceSyncTracker {
    /// Create a new sync tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all tracking state (called when a new stop occurs).
    pub fn clear(&mut self) {
        self.synced_threads.clear();
        self.synced_frames.clear();
        self.synced_registers.clear();
    }

    /// Mark a thread as synced.
    pub fn mark_thread_synced(&mut self, inferior_num: u32, thread_num: u32) {
        self.synced_threads
            .entry(inferior_num)
            .or_default()
            .insert(thread_num);
    }

    /// Check if a thread has been synced.
    pub fn is_thread_synced(&self, inferior_num: u32, thread_num: u32) -> bool {
        self.synced_threads
            .get(&inferior_num)
            .map_or(false, |threads| threads.contains(&thread_num))
    }

    /// Mark a frame as synced.
    pub fn mark_frame_synced(
        &mut self,
        inferior_num: u32,
        thread_num: u32,
        frame_level: u32,
    ) {
        self.synced_frames
            .entry(inferior_num)
            .or_default()
            .entry(thread_num)
            .or_default()
            .insert(frame_level);
    }

    /// Check if a frame has been synced.
    pub fn is_frame_synced(
        &self,
        inferior_num: u32,
        thread_num: u32,
        frame_level: u32,
    ) -> bool {
        self.synced_frames
            .get(&inferior_num)
            .and_then(|threads| threads.get(&thread_num))
            .map_or(false, |frames| frames.contains(&frame_level))
    }

    /// Mark registers for a frame as synced.
    pub fn mark_registers_synced(
        &mut self,
        inferior_num: u32,
        thread_num: u32,
        frame_level: u32,
        register_names: &[String],
    ) {
        let entry = self
            .synced_registers
            .entry(inferior_num)
            .or_default()
            .entry(thread_num)
            .or_default()
            .entry(frame_level)
            .or_default();
        for name in register_names {
            entry.insert(name.clone());
        }
    }

    /// Check if registers for a frame have been synced.
    pub fn are_registers_synced(
        &self,
        inferior_num: u32,
        thread_num: u32,
        frame_level: u32,
    ) -> bool {
        self.synced_registers
            .get(&inferior_num)
            .and_then(|threads| threads.get(&thread_num))
            .and_then(|frames| frames.get(&frame_level))
            .map_or(false, |regs| !regs.is_empty())
    }

    /// Get all synced thread numbers for an inferior.
    pub fn synced_thread_numbers(&self, inferior_num: u32) -> Vec<u32> {
        self.synced_threads
            .get(&inferior_num)
            .map(|threads| threads.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get all synced frame levels for a thread.
    pub fn synced_frame_levels(
        &self,
        inferior_num: u32,
        thread_num: u32,
    ) -> Vec<u32> {
        self.synced_frames
            .get(&inferior_num)
            .and_then(|threads| threads.get(&thread_num))
            .map(|frames| frames.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get the total number of synced threads.
    pub fn total_synced_threads(&self) -> usize {
        self.synced_threads.values().map(|s| s.len()).sum()
    }

    /// Get the total number of synced frames.
    pub fn total_synced_frames(&self) -> usize {
        self.synced_frames
            .values()
            .flat_map(|threads| threads.values())
            .map(|frames| frames.len())
            .sum()
    }
}

/// Batch of operations to perform during a trace synchronization.
///
/// Groups multiple trace writes together for efficiency. Ported from
/// the `Batch` concept in the Python agent's `hooks.py` (`ensure_batch`
/// / `end_batch`).
#[derive(Debug, Clone, Default)]
pub struct GdbSyncBatch {
    /// Thread operations to perform.
    pub thread_ops: Vec<ThreadSyncOp>,
    /// Frame operations to perform.
    pub frame_ops: Vec<FrameSyncOp>,
    /// Register operations to perform.
    pub register_ops: Vec<RegisterSyncOp>,
}

/// A thread synchronization operation.
#[derive(Debug, Clone)]
pub enum ThreadSyncOp {
    /// Create/update a thread.
    Upsert {
        inferior_num: u32,
        thread: GdbThread,
    },
    /// Remove a thread.
    Remove {
        inferior_num: u32,
        thread_num: u32,
    },
}

/// A frame synchronization operation.
#[derive(Debug, Clone)]
pub enum FrameSyncOp {
    /// Create/update a frame.
    Upsert {
        inferior_num: u32,
        thread_num: u32,
        frame: GdbStackFrame,
    },
    /// Remove a frame.
    Remove {
        inferior_num: u32,
        thread_num: u32,
        frame_level: u32,
    },
    /// Clear all frames for a thread.
    ClearAll {
        inferior_num: u32,
        thread_num: u32,
    },
}

/// A register synchronization operation.
#[derive(Debug, Clone)]
pub enum RegisterSyncOp {
    /// Set a register value.
    SetValue {
        inferior_num: u32,
        thread_num: u32,
        frame_level: u32,
        register: RegisterValue,
    },
    /// Clear registers for a frame.
    ClearAll {
        inferior_num: u32,
        thread_num: u32,
        frame_level: u32,
    },
}

impl GdbSyncBatch {
    /// Create a new empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a thread upsert operation.
    pub fn upsert_thread(&mut self, inferior_num: u32, thread: GdbThread) {
        self.thread_ops.push(ThreadSyncOp::Upsert {
            inferior_num,
            thread,
        });
    }

    /// Add a thread removal operation.
    pub fn remove_thread(&mut self, inferior_num: u32, thread_num: u32) {
        self.thread_ops.push(ThreadSyncOp::Remove {
            inferior_num,
            thread_num,
        });
    }

    /// Add a frame upsert operation.
    pub fn upsert_frame(
        &mut self,
        inferior_num: u32,
        thread_num: u32,
        frame: GdbStackFrame,
    ) {
        self.frame_ops.push(FrameSyncOp::Upsert {
            inferior_num,
            thread_num,
            frame,
        });
    }

    /// Add a frame removal operation.
    pub fn remove_frame(
        &mut self,
        inferior_num: u32,
        thread_num: u32,
        frame_level: u32,
    ) {
        self.frame_ops.push(FrameSyncOp::Remove {
            inferior_num,
            thread_num,
            frame_level,
        });
    }

    /// Add a clear-all-frames operation.
    pub fn clear_frames(&mut self, inferior_num: u32, thread_num: u32) {
        self.frame_ops.push(FrameSyncOp::ClearAll {
            inferior_num,
            thread_num,
        });
    }

    /// Add a register set operation.
    pub fn set_register(
        &mut self,
        inferior_num: u32,
        thread_num: u32,
        frame_level: u32,
        register: RegisterValue,
    ) {
        self.register_ops.push(RegisterSyncOp::SetValue {
            inferior_num,
            thread_num,
            frame_level,
            register,
        });
    }

    /// Add a clear-all-registers operation.
    pub fn clear_registers(
        &mut self,
        inferior_num: u32,
        thread_num: u32,
        frame_level: u32,
    ) {
        self.register_ops.push(RegisterSyncOp::ClearAll {
            inferior_num,
            thread_num,
            frame_level,
        });
    }

    /// Get the total number of operations in this batch.
    pub fn total_operations(&self) -> usize {
        self.thread_ops.len() + self.frame_ops.len() + self.register_ops.len()
    }

    /// Check if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.thread_ops.is_empty()
            && self.frame_ops.is_empty()
            && self.register_ops.is_empty()
    }

    /// Clear all operations.
    pub fn clear(&mut self) {
        self.thread_ops.clear();
        self.frame_ops.clear();
        self.register_ops.clear();
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
    fn test_gdb_thread_state_from_trace_str() {
        assert_eq!(GdbThreadState::from_trace_str("RUNNING"), GdbThreadState::Running);
        assert_eq!(GdbThreadState::from_trace_str("STOPPED"), GdbThreadState::Stopped);
        assert_eq!(GdbThreadState::from_trace_str("TERMINATED"), GdbThreadState::Exited);
        assert_eq!(GdbThreadState::from_trace_str("INACTIVE"), GdbThreadState::Inactive);
        assert_eq!(GdbThreadState::from_trace_str("UNKNOWN"), GdbThreadState::Inactive);
    }

    #[test]
    fn test_gdb_thread_state_properties() {
        assert!(GdbThreadState::Stopped.is_resumable());
        assert!(!GdbThreadState::Running.is_resumable());
        assert!(GdbThreadState::Running.is_alive());
        assert!(GdbThreadState::Stopped.is_alive());
        assert!(!GdbThreadState::Exited.is_alive());
        assert!(!GdbThreadState::Inactive.is_alive());
    }

    #[test]
    fn test_thread_stop_reason() {
        let bp = ThreadStopReason::Breakpoint {
            bp_number: 1,
            address: 0x401000,
        };
        assert!(bp.is_stopped());
        assert!(bp.description().contains("Breakpoint"));

        let sig = ThreadStopReason::Signal {
            name: "SIGSEGV".to_string(),
            number: 11,
        };
        assert!(sig.is_stopped());
        assert!(sig.description().contains("SIGSEGV"));

        let exited = ThreadStopReason::Exited { code: 0 };
        assert!(!exited.is_stopped());
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
        assert!(t.stop_reason.is_none());
        assert!(t.display.is_none());
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
            .with_state(ExecutionState::Running)
            .with_display("Thread 1 main");
        assert_eq!(t.tid, Some(1234));
        assert_eq!(t.name, Some("main".to_string()));
        assert_eq!(t.state, ExecutionState::Running);
        assert_eq!(t.display, Some("Thread 1 main".to_string()));
    }

    #[test]
    fn test_thread_trace_path() {
        let t = GdbThread::in_inferior(2, 1);
        assert_eq!(t.trace_path(), "Inferiors[1].Threads[2]");
        assert_eq!(t.stack_path(), "Inferiors[1].Threads[2].Stack");
        assert_eq!(t.frame_path(0), "Inferiors[1].Threads[2].Stack[0]");
        assert_eq!(t.frame_registers_path(1), "Inferiors[1].Threads[2].Stack[1].Registers");
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
        t.add_frame(GdbStackFrame::new(2, 0x403000));
        assert_eq!(t.frame_count(), 3);
        assert!(t.innermost_frame().is_some());
        assert_eq!(t.innermost_frame().unwrap().pc, 0x401000);
        assert!(t.outermost_frame().is_some());
        assert_eq!(t.outermost_frame().unwrap().pc, 0x403000);

        let levels = t.frame_levels();
        assert_eq!(levels, vec![0, 1, 2]);

        let removed = t.remove_frame(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().pc, 0x402000);
        assert_eq!(t.frame_count(), 2);

        t.clear_frames();
        assert_eq!(t.frame_count(), 0);
    }

    #[test]
    fn test_thread_frame_retain_keys() {
        let mut t = GdbThread::new(1);
        t.add_frame(GdbStackFrame::new(0, 0x401000));
        t.add_frame(GdbStackFrame::new(2, 0x403000));
        let keys = t.build_frame_retain_keys();
        assert!(keys.contains(&"[0]".to_string()));
        assert!(keys.contains(&"[2]".to_string()));
        assert_eq!(keys.len(), 2);
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
            .with_state(ExecutionState::Stopped)
            .with_display("Thread 1 main");
        let values = t.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "State" && v == "STOPPED"));
        assert!(values.iter().any(|(k, v)| k == "Name" && v == "main"));
        assert!(values.iter().any(|(k, v)| k == "TID" && v == "42"));
        assert!(values.iter().any(|(k, v)| k == "_display" && v == "Thread 1 main"));
    }

    #[test]
    fn test_thread_build_short_display() {
        let t = GdbThread::in_inferior(1, 1).with_tid(0x1234);
        assert_eq!(t.build_short_display(16), "[1.1:0x1234]");
        assert_eq!(t.build_short_display(10), "[1.1:4660]");
        assert_eq!(t.build_short_display(8), "[1.1:011064]");
    }

    #[test]
    fn test_thread_update_short_display() {
        let mut t = GdbThread::in_inferior(1, 1).with_tid(0x1234);
        t.update_short_display(16);
        assert_eq!(t.short_display, Some("[1.1:0x1234]".to_string()));
    }

    #[test]
    fn test_thread_exit() {
        let mut t = GdbThread::new(1).with_state(ExecutionState::Running);
        t.add_frame(GdbStackFrame::new(0, 0x401000));
        t.stop_reason = Some(ThreadStopReason::StepComplete);
        assert!(t.is_alive());

        t.mark_exited();
        assert!(!t.is_alive());
        assert!(t.is_exited());
        assert_eq!(t.state, ExecutionState::Exited);
        assert!(t.frames.is_empty());
        assert!(t.stop_reason.is_none());
    }

    #[test]
    fn test_thread_state_queries() {
        let t_running = GdbThread::new(1).with_state(ExecutionState::Running);
        assert!(t_running.is_running());
        assert!(!t_running.is_stopped());
        assert!(!t_running.is_exited());
        assert!(t_running.is_alive());

        let t_stopped = GdbThread::new(2).with_state(ExecutionState::Stopped);
        assert!(!t_stopped.is_running());
        assert!(t_stopped.is_stopped());
        assert!(t_stopped.is_alive());

        let t_exited = GdbThread::new(3).with_state(ExecutionState::Exited);
        assert!(t_exited.is_exited());
        assert!(!t_exited.is_alive());
    }

    #[test]
    fn test_stack_frame_new() {
        let f = GdbStackFrame::new(0, 0x401000);
        assert_eq!(f.level, 0);
        assert_eq!(f.pc, 0x401000);
        assert_eq!(f.sp, 0);
        assert!(f.function_name.is_none());
        assert!(f.display.is_none());
    }

    #[test]
    fn test_stack_frame_builder() {
        let f = GdbStackFrame::new(0, 0x401000)
            .with_sp(0x7fff00)
            .with_fp(0x7fff10)
            .with_return_address(0x401100)
            .with_function("main")
            .with_display("#0 0x401000 in main ()");
        assert_eq!(f.sp, 0x7fff00);
        assert_eq!(f.fp, 0x7fff10);
        assert_eq!(f.return_address, 0x401100);
        assert_eq!(f.function_name.as_deref(), Some("main"));
        assert_eq!(f.display.as_deref(), Some("#0 0x401000 in main ()"));
    }

    #[test]
    fn test_stack_frame_display() {
        let f = GdbStackFrame::new(0, 0x401000).with_function("main");
        assert_eq!(f.build_display(), "#0 0x401000 main");
        assert_eq!(f.display_string(), "#0 0x401000 main");

        let f2 = GdbStackFrame::new(1, 0x402000);
        assert_eq!(f2.build_display(), "#1 0x402000");

        let f3 = GdbStackFrame::new(0, 0x401000)
            .with_function("main")
            .with_display("#0 0x401000 in main () at main.c:10");
        assert_eq!(f3.display_string(), "#0 0x401000 in main () at main.c:10");
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

        let retain = f.build_register_retain_keys();
        assert!(retain.contains(&"rax".to_string()));
        assert!(retain.contains(&"rbx".to_string()));

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

    #[test]
    fn test_event_thread_tracker() {
        let mut tracker = EventThreadTracker::new();
        assert!(tracker.trace_path().is_none());
        assert!(!tracker.is_event_thread(1, 1));

        tracker.set(1, 2);
        assert_eq!(
            tracker.trace_path(),
            Some("Inferiors[1].Threads[2]".to_string())
        );
        assert!(tracker.is_event_thread(1, 2));
        assert!(!tracker.is_event_thread(1, 3));
        assert!(!tracker.is_event_thread(2, 2));

        tracker.clear();
        assert!(tracker.trace_path().is_none());
    }

    #[test]
    fn test_frame_selection() {
        let mut sel = FrameSelection::new();
        assert!(sel.frame_path().is_none());
        assert!(sel.thread_path().is_none());

        sel.set(1, 2, 3);
        assert_eq!(
            sel.frame_path(),
            Some("Inferiors[1].Threads[2].Stack[3]".to_string())
        );
        assert_eq!(
            sel.thread_path(),
            Some("Inferiors[1].Threads[2]".to_string())
        );

        sel.clear();
        assert!(sel.frame_path().is_none());
    }

    #[test]
    fn test_thread_frames_sorted() {
        let mut t = GdbThread::new(1);
        t.add_frame(GdbStackFrame::new(2, 0x403000));
        t.add_frame(GdbStackFrame::new(0, 0x401000));
        t.add_frame(GdbStackFrame::new(1, 0x402000));
        let sorted = t.frames_sorted();
        assert_eq!(sorted[0].level, 0);
        assert_eq!(sorted[1].level, 1);
        assert_eq!(sorted[2].level, 2);
    }

    #[test]
    fn test_thread_outermost_frame() {
        let mut t = GdbThread::new(1);
        t.add_frame(GdbStackFrame::new(0, 0x401000));
        t.add_frame(GdbStackFrame::new(1, 0x402000));
        t.add_frame(GdbStackFrame::new(2, 0x403000));
        let outer = t.outermost_frame();
        assert!(outer.is_some());
        assert_eq!(outer.unwrap().level, 2);
        assert_eq!(outer.unwrap().pc, 0x403000);
    }

    #[test]
    fn test_thread_build_backtrace() {
        let mut t = GdbThread::new(1);
        t.add_frame(GdbStackFrame::new(0, 0x401000).with_function("main"));
        t.add_frame(GdbStackFrame::new(1, 0x402000).with_function("foo"));
        let bt = t.build_backtrace();
        assert_eq!(bt.len(), 2);
        assert!(bt[0].contains("main"));
        assert!(bt[1].contains("foo"));
    }

    #[test]
    fn test_thread_build_stack_container_values() {
        let mut t = GdbThread::new(1);
        t.add_frame(GdbStackFrame::new(0, 0x401000));
        t.add_frame(GdbStackFrame::new(1, 0x402000));
        let values = t.build_stack_container_values();
        assert!(values.iter().any(|(k, v)| k == "_count" && v == "2"));
    }

    #[test]
    fn test_thread_all_register_names() {
        let mut t = GdbThread::new(1);
        let mut f0 = GdbStackFrame::new(0, 0x401000);
        f0.set_register(RegisterValue::from_u64("rax", 1));
        f0.set_register(RegisterValue::from_u64("rbx", 2));
        t.add_frame(f0);
        let mut f1 = GdbStackFrame::new(1, 0x402000);
        f1.set_register(RegisterValue::from_u64("rax", 3));
        f1.set_register(RegisterValue::from_u64("rip", 4));
        t.add_frame(f1);

        let names = t.all_register_names();
        assert_eq!(names.len(), 3); // rax, rbx, rip
        assert!(names.contains(&"rax".to_string()));
        assert!(names.contains(&"rbx".to_string()));
        assert!(names.contains(&"rip".to_string()));
    }

    #[test]
    fn test_thread_frame_at_pc() {
        let mut t = GdbThread::new(1);
        t.add_frame(GdbStackFrame::new(0, 0x401000));
        t.add_frame(GdbStackFrame::new(1, 0x402000));
        assert!(t.frame_at_pc(0x401000).is_some());
        assert!(t.frame_at_pc(0x403000).is_none());
    }

    #[test]
    fn test_thread_return_address() {
        let mut t = GdbThread::new(1);
        assert!(t.return_address().is_none());

        t.add_frame(GdbStackFrame::new(0, 0x401000).with_return_address(0x401100));
        assert_eq!(t.return_address(), Some(0x401100));
    }

    #[test]
    fn test_thread_stopped_at_breakpoint() {
        let t = GdbThread::new(1)
            .with_state(ExecutionState::Stopped)
            .with_stop_reason(ThreadStopReason::Breakpoint {
                bp_number: 1,
                address: 0x401000,
            });
        assert!(t.stopped_at_breakpoint());
        assert!(!t.stopped_by_signal());
        assert!(!t.stopped_at_step());
    }

    #[test]
    fn test_thread_stopped_by_signal() {
        let t = GdbThread::new(1)
            .with_state(ExecutionState::Stopped)
            .with_stop_reason(ThreadStopReason::Signal {
                name: "SIGSEGV".to_string(),
                number: 11,
            });
        assert!(t.stopped_by_signal());
        assert!(!t.stopped_at_breakpoint());
    }

    #[test]
    fn test_thread_stopped_at_step() {
        let t = GdbThread::new(1)
            .with_state(ExecutionState::Stopped)
            .with_stop_reason(ThreadStopReason::StepComplete);
        assert!(t.stopped_at_step());
    }

    #[test]
    fn test_thread_stopped_at_function_return() {
        let t = GdbThread::new(1)
            .with_state(ExecutionState::Stopped)
            .with_stop_reason(ThreadStopReason::FunctionFinished {
                return_value: Some(42),
            });
        assert!(t.stopped_at_function_return());
    }
}

#[cfg(test)]
mod step_tests {
    use super::*;

    #[test]
    fn test_step_type_commands() {
        assert_eq!(GdbStepType::Over.as_gdb_command(), "next");
        assert_eq!(GdbStepType::Into.as_gdb_command(), "step");
        assert_eq!(GdbStepType::Out.as_gdb_command(), "finish");
        assert_eq!(GdbStepType::InstructionOver.as_gdb_command(), "nexti");
        assert_eq!(GdbStepType::InstructionInto.as_gdb_command(), "stepi");
    }

    #[test]
    fn test_step_type_descriptions() {
        assert_eq!(GdbStepType::Over.description(), "Step Over");
        assert_eq!(GdbStepType::Into.description(), "Step Into");
        assert_eq!(GdbStepType::Out.description(), "Step Out");
    }
}

#[cfg(test)]
mod plan_tests {
    use super::*;

    #[test]
    fn test_thread_plan_step() {
        let plan = GdbThreadPlan::step(GdbStepType::Over);
        assert_eq!(plan.step_type, Some(GdbStepType::Over));
        assert!(!plan.completed);
        assert!(plan.stop_address.is_none());
    }

    #[test]
    fn test_thread_plan_run_to_address() {
        let plan = GdbThreadPlan::run_to_address(0x401000);
        assert_eq!(plan.stop_address, Some(0x401000));
        assert!(plan.step_type.is_none());
        assert!(plan.description.contains("0x401000"));
    }

    #[test]
    fn test_thread_plan_completion() {
        let mut plan = GdbThreadPlan::step_out();
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
        let details = GdbFrameDetails::new(0)
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
        let details = GdbFrameDetails::new(0).with_source("main.c", 10);
        let display = details.build_display(0x401000, Some("main"));
        assert!(display.contains("#0"));
        assert!(display.contains("0x401000"));
        assert!(display.contains("main"));
        assert!(display.contains("main.c:10"));
    }

    #[test]
    fn test_frame_details_no_source() {
        let details = GdbFrameDetails::new(1);
        let display = details.build_display(0x402000, Some("foo"));
        assert!(display.contains("#1"));
        assert!(display.contains("foo"));
        assert!(!display.contains("at"));
    }

    #[test]
    fn test_frame_details_inline() {
        let details = GdbFrameDetails::new(0)
            .with_inline(true)
            .with_artificial(false);
        assert!(details.is_inline);
        assert!(!details.is_artificial);
    }

    #[test]
    fn test_frame_details_signal() {
        let details = GdbFrameDetails::new(0)
            .with_signal_frame(true);
        assert!(details.is_signal_frame);
    }
}

#[cfg(test)]
mod collection_tests {
    use super::*;

    #[test]
    fn test_thread_collection() {
        let mut coll = GdbThreadCollection::new(1);
        assert!(coll.is_empty());
        assert_eq!(coll.inferior_num(), 1);

        coll.insert(GdbThread::new(1).with_state(ExecutionState::Running));
        coll.insert(GdbThread::new(2).with_state(ExecutionState::Stopped));
        assert_eq!(coll.len(), 2);
        assert_eq!(coll.numbers(), vec![1, 2]);
    }

    #[test]
    fn test_thread_collection_prune() {
        let mut coll = GdbThreadCollection::new(1);
        coll.insert(GdbThread::new(1).with_state(ExecutionState::Running));
        coll.insert(GdbThread::new(2).with_state(ExecutionState::Exited));
        coll.insert(GdbThread::new(3).with_state(ExecutionState::Exited));

        let pruned = coll.prune_exited();
        assert_eq!(pruned.len(), 2);
        assert!(pruned.contains(&2));
        assert!(pruned.contains(&3));
        assert_eq!(coll.len(), 1);
        assert!(coll.get(1).is_some());
    }

    #[test]
    fn test_thread_collection_clear_all_frames() {
        let mut coll = GdbThreadCollection::new(1);
        let mut t1 = GdbThread::new(1);
        t1.add_frame(GdbStackFrame::new(0, 0x401000));
        let mut t2 = GdbThread::new(2);
        t2.add_frame(GdbStackFrame::new(0, 0x402000));
        t2.add_frame(GdbStackFrame::new(1, 0x403000));
        coll.insert(t1);
        coll.insert(t2);

        coll.clear_all_frames();
        assert_eq!(coll.get(1).unwrap().frame_count(), 0);
        assert_eq!(coll.get(2).unwrap().frame_count(), 0);
    }

    #[test]
    fn test_thread_collection_mark_all_synced() {
        let mut coll = GdbThreadCollection::new(1);
        coll.insert(GdbThread::new(1));
        coll.insert(GdbThread::new(2));
        coll.mark_all_synced();
        assert!(coll.get(1).unwrap().synced);
        assert!(coll.get(2).unwrap().synced);
    }

    #[test]
    fn test_thread_collection_iter() {
        let mut coll = GdbThreadCollection::new(1);
        coll.insert(GdbThread::new(1));
        coll.insert(GdbThread::new(2));
        let count = coll.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_thread_collection_build_info_list() {
        let mut coll = GdbThreadCollection::new(1);
        coll.insert(
            GdbThread::new(1)
                .with_tid(100)
                .with_name("main")
                .with_state(ExecutionState::Running),
        );
        let list = coll.build_thread_info_list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, 1); // GDB uses thread num as id
        assert_eq!(list[0].name.as_deref(), Some("main"));
    }
}

#[cfg(test)]
mod register_descriptor_tests {
    use super::*;

    #[test]
    fn test_register_descriptor_new() {
        let desc = RegisterDescriptor::new("rax");
        assert_eq!(desc.name, "rax");
        assert!(desc.group.is_none());
        assert!(desc.size.is_none());
    }

    #[test]
    fn test_register_descriptor_builder() {
        let desc = RegisterDescriptor::new("xmm0")
            .with_group("vector")
            .with_size(16);
        assert_eq!(desc.name, "xmm0");
        assert_eq!(desc.group.as_deref(), Some("vector"));
        assert_eq!(desc.size, Some(16));
    }
}

#[cfg(test)]
mod frame_register_batch_tests {
    use super::*;

    #[test]
    fn test_frame_register_batch_new() {
        let batch = FrameRegisterBatch::new(0);
        assert_eq!(batch.frame_level, 0);
        assert!(batch.is_empty());
    }

    #[test]
    fn test_frame_register_batch_push() {
        let mut batch = FrameRegisterBatch::new(0);
        batch.push(RegisterValue::from_u64("rax", 0x1234));
        batch.push(RegisterValue::from_u64("rbx", 0x5678));
        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_frame_register_batch_get() {
        let mut batch = FrameRegisterBatch::new(0);
        batch.push(RegisterValue::from_u64("rax", 0x1234));
        assert!(batch.get("rax").is_some());
        assert_eq!(batch.get("rax").unwrap().as_u64(), Some(0x1234));
        assert!(batch.get("rcx").is_none());
    }

    #[test]
    fn test_frame_register_batch_names() {
        let mut batch = FrameRegisterBatch::new(0);
        batch.push(RegisterValue::from_u64("rax", 1));
        batch.push(RegisterValue::from_u64("rbx", 2));
        batch.push(RegisterValue::from_u64("rcx", 3));
        let names = batch.names();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"rax"));
        assert!(names.contains(&"rbx"));
        assert!(names.contains(&"rcx"));
    }
}

#[cfg(test)]
mod thread_event_tests {
    use super::*;

    #[test]
    fn test_thread_event_created() {
        let event = ThreadEvent::Created {
            inferior_num: 1,
            thread_num: 2,
        };
        assert_eq!(event.inferior_num(), 1);
        assert_eq!(event.thread_num(), 2);
        assert!(event.description().contains("created"));
    }

    #[test]
    fn test_thread_event_exited() {
        let event = ThreadEvent::Exited {
            inferior_num: 1,
            thread_num: 2,
        };
        assert!(event.description().contains("exited"));
    }

    #[test]
    fn test_thread_event_state_changed() {
        let event = ThreadEvent::StateChanged {
            inferior_num: 1,
            thread_num: 2,
            new_state: ExecutionState::Stopped,
        };
        assert!(event.description().contains("STOPPED"));
    }

    #[test]
    fn test_thread_event_selected() {
        let event = ThreadEvent::Selected {
            inferior_num: 1,
            thread_num: 3,
        };
        assert!(event.description().contains("selected"));
    }
}

#[cfg(test)]
mod thread_history_tests {
    use super::*;

    #[test]
    fn test_thread_history_entry() {
        let entry = ThreadHistoryEntry::new(0x401000, 1000)
            .with_stop_reason(ThreadStopReason::Breakpoint {
                bp_number: 1,
                address: 0x401000,
            })
            .with_frame_level(0);
        assert_eq!(entry.pc, 0x401000);
        assert_eq!(entry.timestamp, 1000);
        assert!(entry.stop_reason.is_some());
        assert_eq!(entry.frame_level, 0);
    }

    #[test]
    fn test_thread_history_basic() {
        let mut history = ThreadHistory::new(10);
        assert!(history.is_empty());
        assert!(history.latest().is_none());

        history.push(ThreadHistoryEntry::new(0x401000, 100));
        history.push(ThreadHistoryEntry::new(0x402000, 200));
        assert_eq!(history.len(), 2);
        assert_eq!(history.latest().unwrap().pc, 0x402000);
    }

    #[test]
    fn test_thread_history_overflow() {
        let mut history = ThreadHistory::new(3);
        history.push(ThreadHistoryEntry::new(0x1000, 1));
        history.push(ThreadHistoryEntry::new(0x2000, 2));
        history.push(ThreadHistoryEntry::new(0x3000, 3));
        history.push(ThreadHistoryEntry::new(0x4000, 4)); // evicts 0x1000
        assert_eq!(history.len(), 3);
        assert_eq!(history.entries()[0].pc, 0x2000);
        assert_eq!(history.latest().unwrap().pc, 0x4000);
    }

    #[test]
    fn test_thread_history_last_n() {
        let mut history = ThreadHistory::new(100);
        for i in 0..10 {
            history.push(ThreadHistoryEntry::new(i * 0x1000, i));
        }
        let last3 = history.last_n(3);
        assert_eq!(last3.len(), 3);
        assert_eq!(last3[0].pc, 7 * 0x1000);
        assert_eq!(last3[2].pc, 9 * 0x1000);
    }

    #[test]
    fn test_thread_history_default_capacity() {
        let history = ThreadHistory::with_default_capacity();
        assert!(history.is_empty());
        assert_eq!(history.max_entries, 100);
    }

    #[test]
    fn test_thread_history_clear() {
        let mut history = ThreadHistory::new(10);
        history.push(ThreadHistoryEntry::new(0x1000, 1));
        history.push(ThreadHistoryEntry::new(0x2000, 2));
        assert_eq!(history.len(), 2);
        history.clear();
        assert!(history.is_empty());
    }
}

#[cfg(test)]
mod stepping_mode_tests {
    use super::*;

    #[test]
    fn test_stepping_mode() {
        assert_ne!(SteppingMode::Instruction, SteppingMode::SourceLine);
        assert_eq!(SteppingMode::Instruction, SteppingMode::Instruction);
    }
}

#[cfg(test)]
mod frame_source_info_tests {
    use super::*;

    #[test]
    fn test_frame_source_info_new() {
        let info = GdbFrameSourceInfo::new();
        assert!(info.file.is_none());
        assert!(info.line.is_none());
        assert!(!info.source_available);
    }

    #[test]
    fn test_frame_source_info_builder() {
        let info = GdbFrameSourceInfo::new()
            .with_location("/path/to/main.c", 42)
            .with_function("main")
            .with_compilation_dir("/project/src");
        assert_eq!(info.file.as_deref(), Some("/path/to/main.c"));
        assert_eq!(info.line, Some(42));
        assert!(info.source_available);
        assert_eq!(info.full_function.as_deref(), Some("main"));
        assert_eq!(info.compilation_dir.as_deref(), Some("/project/src"));
    }

    #[test]
    fn test_frame_source_info_display() {
        let info = GdbFrameSourceInfo::new()
            .with_location("main.c", 10);
        assert_eq!(info.build_display(), Some("main.c:10".to_string()));

        let info_none = GdbFrameSourceInfo::new();
        assert_eq!(info_none.build_display(), None);
    }

    #[test]
    fn test_frame_source_info_full_path() {
        let info = GdbFrameSourceInfo::new()
            .with_location("main.c", 10)
            .with_compilation_dir("/project");
        assert_eq!(info.full_path(), Some("/project/main.c".to_string()));

        let info_abs = GdbFrameSourceInfo::new()
            .with_location("/absolute/path/main.c", 10)
            .with_compilation_dir("/project");
        assert_eq!(info_abs.full_path(), Some("/absolute/path/main.c".to_string()));
    }
}

#[cfg(test)]
mod sync_tracker_tests {
    use super::*;

    #[test]
    fn test_sync_tracker_new() {
        let tracker = GdbTraceSyncTracker::new();
        assert_eq!(tracker.total_synced_threads(), 0);
        assert_eq!(tracker.total_synced_frames(), 0);
    }

    #[test]
    fn test_sync_tracker_threads() {
        let mut tracker = GdbTraceSyncTracker::new();
        tracker.mark_thread_synced(1, 1);
        tracker.mark_thread_synced(1, 2);
        tracker.mark_thread_synced(2, 1);
        assert!(tracker.is_thread_synced(1, 1));
        assert!(tracker.is_thread_synced(1, 2));
        assert!(tracker.is_thread_synced(2, 1));
        assert!(!tracker.is_thread_synced(1, 3));
        assert_eq!(tracker.total_synced_threads(), 3);
    }

    #[test]
    fn test_sync_tracker_frames() {
        let mut tracker = GdbTraceSyncTracker::new();
        tracker.mark_frame_synced(1, 1, 0);
        tracker.mark_frame_synced(1, 1, 1);
        assert!(tracker.is_frame_synced(1, 1, 0));
        assert!(tracker.is_frame_synced(1, 1, 1));
        assert!(!tracker.is_frame_synced(1, 1, 2));
        assert_eq!(tracker.total_synced_frames(), 2);
    }

    #[test]
    fn test_sync_tracker_registers() {
        let mut tracker = GdbTraceSyncTracker::new();
        tracker.mark_registers_synced(1, 1, 0, &["rax".to_string(), "rbx".to_string()]);
        assert!(tracker.are_registers_synced(1, 1, 0));
        assert!(!tracker.are_registers_synced(1, 1, 1));
    }

    #[test]
    fn test_sync_tracker_clear() {
        let mut tracker = GdbTraceSyncTracker::new();
        tracker.mark_thread_synced(1, 1);
        tracker.mark_frame_synced(1, 1, 0);
        tracker.mark_registers_synced(1, 1, 0, &["rax".to_string()]);
        tracker.clear();
        assert!(!tracker.is_thread_synced(1, 1));
        assert!(!tracker.is_frame_synced(1, 1, 0));
        assert!(!tracker.are_registers_synced(1, 1, 0));
    }

    #[test]
    fn test_sync_tracker_synced_numbers() {
        let mut tracker = GdbTraceSyncTracker::new();
        tracker.mark_thread_synced(1, 1);
        tracker.mark_thread_synced(1, 3);
        let nums = tracker.synced_thread_numbers(1);
        assert_eq!(nums.len(), 2);
        assert!(nums.contains(&1));
        assert!(nums.contains(&3));
    }

    #[test]
    fn test_sync_tracker_synced_frame_levels() {
        let mut tracker = GdbTraceSyncTracker::new();
        tracker.mark_frame_synced(1, 1, 0);
        tracker.mark_frame_synced(1, 1, 2);
        let levels = tracker.synced_frame_levels(1, 1);
        assert_eq!(levels.len(), 2);
        assert!(levels.contains(&0));
        assert!(levels.contains(&2));
    }
}

#[cfg(test)]
mod sync_batch_tests {
    use super::*;

    #[test]
    fn test_sync_batch_new() {
        let batch = GdbSyncBatch::new();
        assert!(batch.is_empty());
        assert_eq!(batch.total_operations(), 0);
    }

    #[test]
    fn test_sync_batch_thread_ops() {
        let mut batch = GdbSyncBatch::new();
        batch.upsert_thread(1, GdbThread::new(1));
        batch.upsert_thread(1, GdbThread::new(2));
        batch.remove_thread(1, 3);
        assert_eq!(batch.thread_ops.len(), 3);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_sync_batch_frame_ops() {
        let mut batch = GdbSyncBatch::new();
        batch.upsert_frame(1, 1, GdbStackFrame::new(0, 0x401000));
        batch.remove_frame(1, 1, 1);
        batch.clear_frames(1, 2);
        assert_eq!(batch.frame_ops.len(), 3);
    }

    #[test]
    fn test_sync_batch_register_ops() {
        let mut batch = GdbSyncBatch::new();
        batch.set_register(
            1,
            1,
            0,
            RegisterValue::from_u64("rax", 0x1234),
        );
        batch.clear_registers(1, 1, 1);
        assert_eq!(batch.register_ops.len(), 2);
    }

    #[test]
    fn test_sync_batch_total_operations() {
        let mut batch = GdbSyncBatch::new();
        batch.upsert_thread(1, GdbThread::new(1));
        batch.upsert_frame(1, 1, GdbStackFrame::new(0, 0x401000));
        batch.set_register(1, 1, 0, RegisterValue::from_u64("rax", 0x1234));
        assert_eq!(batch.total_operations(), 3);
    }

    #[test]
    fn test_sync_batch_clear() {
        let mut batch = GdbSyncBatch::new();
        batch.upsert_thread(1, GdbThread::new(1));
        batch.upsert_frame(1, 1, GdbStackFrame::new(0, 0x401000));
        assert!(!batch.is_empty());
        batch.clear();
        assert!(batch.is_empty());
    }
}
