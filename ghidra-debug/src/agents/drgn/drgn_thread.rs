//! drgn thread representation.
//!
//! Models a drgn thread within a process. In drgn, threads are identified
//! by a thread number and may have an OS-level TID. Each thread has
//! associated stack frames and register values.
//!
//! For kernel debugging, each CPU appears as a separate thread.
//!
//! This corresponds to the `Processes[N].Threads[M]` node in the Ghidra
//! trace object tree and maps to `TraceThread` on the model side.
//!
//! Ported from Ghidra's `Debugger-agent-drgn` Python commands (`put_threads`,
//! `put_frames`, `put_registers`, etc.).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::agents::{
    ExecutionState, RegisterValue, StackFrameInfo, ThreadInfo,
};

/// Execution state of a drgn thread.
///
/// This extends the common `ExecutionState` with drgn-specific states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DrgnThreadState {
    /// Thread is running.
    Running,
    /// Thread is stopped (breakpoint, signal, step).
    Stopped,
    /// Thread has exited.
    Exited,
    /// Thread is not yet started or unknown.
    Inactive,
}

impl DrgnThreadState {
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

    /// Parse from drgn thread state booleans.
    ///
    /// drgn Python API provides `is_running()`, `is_stopped()`, `is_exited()`.
    pub fn from_drgn_state(is_running: bool, is_stopped: bool, is_exited: bool) -> Self {
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

/// A drgn thread within a process.
///
/// Each thread in drgn has a thread number (0-based for kernel CPUs),
/// an optional OS-level TID, and associated stack frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrgnThread {
    /// Thread number (0-based for kernel CPUs).
    pub num: u32,
    /// OS-level thread ID, if known.
    pub tid: Option<i64>,
    /// Thread name (e.g. "CPU 0", or process name for userspace).
    pub name: Option<String>,
    /// Current execution state.
    pub state: ExecutionState,
    /// Stack frames, keyed by level (0 = innermost).
    pub frames: BTreeMap<u32, DrgnStackFrame>,
    /// Whether this thread has been synchronized to the trace.
    pub synced: bool,
    /// The process number this thread belongs to.
    pub process_num: u32,
    /// CPU number for kernel threads (maps to thread num).
    pub cpu: Option<u32>,
}

impl DrgnThread {
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
            cpu: None,
        }
    }

    /// Create a kernel CPU thread.
    pub fn cpu_thread(num: u32, cpu: u32) -> Self {
        Self {
            num,
            name: Some(format!("CPU {}", cpu)),
            cpu: Some(cpu),
            process_num: 0,
            ..Self::new(num)
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
    pub fn add_frame(&mut self, frame: DrgnStackFrame) {
        self.frames.insert(frame.level, frame);
    }

    /// Remove a stack frame by level.
    pub fn remove_frame(&mut self, level: u32) -> Option<DrgnStackFrame> {
        self.frames.remove(&level)
    }

    /// Clear all frames.
    pub fn clear_frames(&mut self) {
        self.frames.clear();
    }

    /// Get a frame by level.
    pub fn get_frame(&self, level: u32) -> Option<&DrgnStackFrame> {
        self.frames.get(&level)
    }

    /// Get a mutable reference to a frame by level.
    pub fn get_frame_mut(&mut self, level: u32) -> Option<&mut DrgnStackFrame> {
        self.frames.get_mut(&level)
    }

    /// Get the innermost frame (level 0).
    pub fn innermost_frame(&self) -> Option<&DrgnStackFrame> {
        self.frames.get(&0)
    }

    /// Get the number of frames.
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Get all frame levels sorted.
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
        if let Some(cpu) = self.cpu {
            values.push(("CPU".to_string(), cpu.to_string()));
        }
        values
    }

    /// Build the short display string for this thread.
    ///
    /// Format: `[process.thread]` or `[process.thread:cpu]` for kernel threads.
    pub fn build_short_display(&self) -> String {
        match self.cpu {
            Some(cpu) => format!("[{}.{}:cpu{}]", self.process_num, self.num, cpu),
            None => format!("[{}.{}]", self.process_num, self.num),
        }
    }

    /// Build the long display string for this thread.
    ///
    /// Format: `idx process:tid name` or `idx process:tid cpu=N`
    pub fn build_long_display(&self, index: usize) -> String {
        let tid = self.tid.unwrap_or(0);
        let base = format!("{:x} {:x}:{:x}", index, self.process_num, tid);
        match &self.name {
            Some(name) => format!("{} {}", base, name),
            None => base,
        }
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

    /// Build trace object key-value pairs including TID and Name.
    ///
    /// Extended version matching the Python agent's `put_threads` output.
    /// The Python agent uses:
    /// - `TID` with the raw value
    /// - `_short_display` as `'{tnum:d} {pid:x}:{tid:x}'`
    /// - `_display` as `'{tnum:x} {pid:x}:{tid:x} {name}'`
    /// - `Name` for the thread name
    /// - `CPU` for kernel CPU threads
    pub fn build_trace_values_extended(&self) -> Vec<(String, String)> {
        let tid = self.tid.unwrap_or(0);
        let mut values = vec![
            ("State".to_string(), self.state.as_trace_str().to_string()),
            ("TID".to_string(), format!("{}", tid)),
            (
                "_short_display".to_string(),
                format!(
                    "{} {:x}:{:x}",
                    self.num, self.process_num, tid
                ),
            ),
        ];
        let display = self.build_display_extended();
        values.push(("_display".to_string(), display));
        if let Some(ref name) = self.name {
            values.push(("Name".to_string(), name.clone()));
        }
        if let Some(cpu) = self.cpu {
            values.push(("CPU".to_string(), cpu.to_string()));
        }
        values
    }

    /// Build the extended display string matching the Python agent.
    ///
    /// Format for kernel: `'{tnum:x} {pid:x}:{tid:x} {name}'`
    /// Format for user: `'{tnum:x} {pid:x}:{tid:x} {name}'`
    pub fn build_display_extended(&self) -> String {
        let tid = self.tid.unwrap_or(0);
        let base = format!(
            "{:x} {:x}:{:x}",
            self.num, self.process_num, tid
        );
        match &self.name {
            Some(n) if !n.is_empty() => format!("{} {}", base, n),
            _ => base,
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
    pub fn sorted_frames(&self) -> Vec<&DrgnStackFrame> {
        let mut frames: Vec<&DrgnStackFrame> = self.frames.values().collect();
        frames.sort_by_key(|f| f.level);
        frames
    }

    /// Get the outermost frame (highest level).
    pub fn outermost_frame(&self) -> Option<&DrgnStackFrame> {
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
    pub fn frame_at_pc(&self, pc: u64) -> Option<&DrgnStackFrame> {
        self.frames.values().find(|f| f.pc == pc)
    }

    /// Get the return address for the innermost frame.
    pub fn return_address(&self) -> Option<u64> {
        self.innermost_frame()
            .map(|f| f.return_address)
            .filter(|&ra| ra != 0)
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

    /// Build the retain keys for this thread's frame children.
    pub fn build_frame_retain_keys(&self) -> Vec<String> {
        self.frames
            .keys()
            .map(|level| format!("[{}]", level))
            .collect()
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

}

/// Source location information for a stack frame.
///
/// Captured from drgn's `StackFrame.source()` which returns
/// (filename, line, column).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameSourceInfo {
    /// Source file path.
    pub filename: String,
    /// Line number.
    pub line: i64,
    /// Column number.
    pub column: i64,
}

impl FrameSourceInfo {
    /// Create a new source info.
    pub fn new(filename: impl Into<String>, line: i64, column: i64) -> Self {
        Self {
            filename: filename.into(),
            line,
            column,
        }
    }

    /// Build trace values for this source info.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        vec![
            ("Filename".to_string(), self.filename.clone()),
            ("Line".to_string(), self.line.to_string()),
            ("Column".to_string(), self.column.to_string()),
        ]
    }
}

/// A stack frame within a drgn thread.
///
/// Each frame represents one level of the call stack. Frame 0 is the
/// currently executing function. Frame 1 is its caller, and so on.
///
/// For kernel debugging, frames correspond to kernel stack frames.
///
/// Ported from `put_frames()` in commands.py which reads `StackFrame.pc`,
/// `StackFrame.sp`, `StackFrame.name`, `StackFrame.is_inline`,
/// `StackFrame.interrupted`, and `StackFrame.source()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrgnStackFrame {
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
    /// Whether this frame is an inline frame.
    pub is_inline: bool,
    /// Whether execution was interrupted (e.g. by signal).
    pub interrupted: bool,
    /// Source location, if available.
    pub source: Option<FrameSourceInfo>,
    /// Register values for this frame.
    #[serde(skip)]
    pub registers: Vec<RegisterValue>,
}

impl DrgnStackFrame {
    /// Create a new stack frame.
    pub fn new(level: u32, pc: u64) -> Self {
        Self {
            level,
            pc,
            sp: 0,
            fp: 0,
            return_address: 0,
            function_name: None,
            is_inline: false,
            interrupted: false,
            source: None,
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

    /// Set whether this is an inline frame.
    pub fn with_inline(mut self, is_inline: bool) -> Self {
        self.is_inline = is_inline;
        self
    }

    /// Set whether execution was interrupted.
    pub fn with_interrupted(mut self, interrupted: bool) -> Self {
        self.interrupted = interrupted;
        self
    }

    /// Set the source location.
    pub fn with_source(mut self, source: FrameSourceInfo) -> Self {
        self.source = Some(source);
        self
    }

    /// Get the trace path for this frame.
    pub fn trace_path(&self, process_num: u32, thread_num: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}]",
            process_num, thread_num, self.level
        )
    }

    /// Get the trace path for this frame's registers.
    pub fn registers_trace_path(&self, process_num: u32, thread_num: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}].Registers",
            process_num, thread_num, self.level
        )
    }

    /// Get the trace path for this frame's locals.
    pub fn locals_trace_path(&self, process_num: u32, thread_num: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}].Locals",
            process_num, thread_num, self.level
        )
    }

    /// Get the trace path for this frame's attributes.
    pub fn attributes_trace_path(&self, process_num: u32, thread_num: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}].Attributes",
            process_num, thread_num, self.level
        )
    }

    /// Get the trace path for this frame's source info.
    pub fn source_trace_path(&self, process_num: u32, thread_num: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}].Source",
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

    /// Build trace object key-value pairs for this frame.
    ///
    /// These are used to populate the `Processes[N].Threads[M].Stack[L]` node.
    /// Matches the output of `put_frames()` in the Python agent.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let mut values = vec![
            (
                "_display".to_string(),
                match &self.function_name {
                    Some(name) => format!("#{} 0x{:x} {}", self.level, self.pc, name),
                    None => format!("#{} 0x{:x}", self.level, self.pc),
                },
            ),
        ];
        if let Some(ref name) = self.function_name {
            values.push(("Name".to_string(), name.clone()));
        }
        values
    }

    /// Build trace values for this frame's attributes (inline, interrupted).
    ///
    /// Matches the `fobj.Attributes` output from `put_frames()`.
    pub fn build_attribute_values(&self) -> Vec<(String, String)> {
        vec![
            ("Inline".to_string(), self.is_inline.to_string()),
            ("Interrupted".to_string(), self.interrupted.to_string()),
        ]
    }

    /// Build trace values for this frame's source info.
    ///
    /// Matches the `fobj.Source` output from `put_frames()`.
    pub fn build_source_values(&self) -> Option<Vec<(String, String)>> {
        self.source.as_ref().map(|s| s.build_trace_values())
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

    /// Build register display value (hex string).
    ///
    /// Matches the Python `hex(value)` output in `putreg()`.
    pub fn build_register_display(value: u64) -> String {
        format!("0x{:x}", value)
    }
}

/// A local variable value within a stack frame.
///
/// Ported from Python `put_locals()` in `commands.py` which iterates
/// `frame.locals()` and calls `put_object()` for each. This captures
/// the variable's value at a particular point in time for a specific
/// frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrgnLocalVariableValue {
    /// Variable name.
    pub name: String,
    /// Type name as string.
    pub type_name: String,
    /// Stringified value.
    pub value: String,
    /// Address in memory, if addressable.
    pub address: Option<u64>,
    /// Whether the value is absent (optimized out).
    pub is_absent: bool,
    /// drgn type kind (for display).
    pub type_kind: Option<String>,
}

impl DrgnLocalVariableValue {
    /// Create a new local variable value.
    pub fn new(
        name: impl Into<String>,
        type_name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            type_name: type_name.into(),
            value: value.into(),
            address: None,
            is_absent: false,
            type_kind: None,
        }
    }

    /// Set the address.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Mark as absent.
    pub fn with_absent(mut self, absent: bool) -> Self {
        self.is_absent = absent;
        self
    }

    /// Set the type kind.
    pub fn with_type_kind(mut self, kind: impl Into<String>) -> Self {
        self.type_kind = Some(kind.into());
        self
    }

    /// Build the trace path for this local variable.
    pub fn trace_path(&self, process_num: u32, thread_num: u32, frame_level: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}].Locals.{}",
            process_num, thread_num, frame_level, self.name
        )
    }

    /// Build trace object key-value pairs.
    ///
    /// Matches the Python `put_object()` output format.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let mut values = vec![
            (
                "_display".to_string(),
                format!("{} [{}:{}]", self.name, self.type_name, self.value),
            ),
        ];
        if let Some(ref kind) = self.type_kind {
            values.push(("Kind".to_string(), kind.clone()));
        }
        values.push(("Type".to_string(), self.type_name.clone()));
        if self.is_absent {
            values.push(("Value".to_string(), "<absent>".to_string()));
        } else {
            values.push(("Value".to_string(), self.value.clone()));
        }
        if let Some(addr) = self.address {
            values.push(("Address".to_string(), format!("0x{:x}", addr)));
        }
        values
    }
}

/// Container for all local variables within a stack frame.
///
/// Groups the locals for a single frame level, ported from the
/// `LocalsContainer` schema and `put_locals()` function in `commands.py`.
#[derive(Debug, Clone, Default)]
pub struct DrgnFrameLocals {
    /// Frame level.
    pub frame_level: u32,
    /// Thread number.
    pub thread_num: u32,
    /// Process number.
    pub process_num: u32,
    /// Local variables, keyed by name.
    pub locals: BTreeMap<String, DrgnLocalVariableValue>,
}

impl DrgnFrameLocals {
    /// Create a new frame locals container.
    pub fn new(process_num: u32, thread_num: u32, frame_level: u32) -> Self {
        Self {
            frame_level,
            thread_num,
            process_num,
            locals: BTreeMap::new(),
        }
    }

    /// Add a local variable. Replaces if same name exists.
    pub fn add_local(&mut self, local: DrgnLocalVariableValue) {
        self.locals.insert(local.name.clone(), local);
    }

    /// Remove a local by name.
    pub fn remove_local(&mut self, name: &str) -> Option<DrgnLocalVariableValue> {
        self.locals.remove(name)
    }

    /// Get a local by name.
    pub fn get_local(&self, name: &str) -> Option<&DrgnLocalVariableValue> {
        self.locals.get(name)
    }

    /// Get all local names.
    pub fn local_names(&self) -> Vec<&str> {
        self.locals.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of locals.
    pub fn local_count(&self) -> usize {
        self.locals.len()
    }

    /// Clear all locals.
    pub fn clear(&mut self) {
        self.locals.clear();
    }

    /// Get the trace path for the Locals container.
    pub fn trace_path(&self) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}].Locals",
            self.process_num, self.thread_num, self.frame_level
        )
    }

    /// Build all local variable trace values.
    pub fn build_all_trace_values(&self) -> Vec<(String, Vec<(String, String)>)> {
        self.locals
            .values()
            .map(|local| {
                let path = local.trace_path(self.process_num, self.thread_num, self.frame_level);
                (path, local.build_trace_values())
            })
            .collect()
    }
}

/// A batch of register values for a single frame.
///
/// Groups register values for efficient trace writing. Ported from
/// the register syncing logic in `commands.py` `putreg()`.
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

    /// Clear all registers.
    pub fn clear(&mut self) {
        self.registers.clear();
    }

    /// Build the trace path for the registers container of this frame.
    pub fn trace_path(&self, process_num: u32, thread_num: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}].Registers",
            process_num, thread_num, self.frame_level
        )
    }

    /// Build individual register trace path/value pairs.
    pub fn build_register_pairs(
        &self,
        process_num: u32,
        thread_num: u32,
    ) -> Vec<(String, Vec<u8>)> {
        self.registers
            .iter()
            .map(|r| {
                let path = format!(
                    "Processes[{}].Threads[{}].Stack[{}].Registers.{}",
                    process_num, thread_num, self.frame_level, r.name
                );
                (path, r.bytes.clone())
            })
            .collect()
    }
}

/// Stop reason for a drgn thread.
///
/// Captures why a thread stopped. Ported from the Python agent's
/// state detection logic in `hooks.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DrgnStopReason {
    /// Breakpoint hit.
    Breakpoint,
    /// Watchpoint triggered.
    Watchpoint,
    /// Signal received.
    Signal,
    /// Step completed.
    StepComplete,
    /// Function finished (return).
    FunctionFinished,
    /// Exec (execve).
    Exec,
    /// Thread exiting.
    ThreadExiting,
    /// Unknown reason.
    Unknown,
}

impl DrgnStopReason {
    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Breakpoint => "Breakpoint",
            Self::Watchpoint => "Watchpoint",
            Self::Signal => "Signal",
            Self::StepComplete => "Step complete",
            Self::FunctionFinished => "Function finished",
            Self::Exec => "Exec",
            Self::ThreadExiting => "Thread exiting",
            Self::Unknown => "Unknown",
        }
    }

    /// Whether this stop reason implies the thread is stopped (can resume).
    pub fn is_stopped(&self) -> bool {
        !matches!(self, Self::ThreadExiting)
    }
}

/// Detailed stop reason for a specific thread stop.
///
/// Captures why a thread stopped with more detail than the simple
/// `DrgnStopReason` enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DrgnDetailedStopReason {
    /// Breakpoint hit at address.
    Breakpoint {
        /// Breakpoint ID.
        bp_id: u32,
        /// Address where breakpoint was hit.
        address: u64,
    },
    /// Watchpoint triggered.
    Watchpoint {
        /// Watchpoint ID.
        wp_id: u32,
        /// Address that was watched.
        address: u64,
    },
    /// Signal received.
    Signal {
        /// Signal name.
        name: String,
        /// Signal number.
        number: i32,
    },
    /// Step completed.
    StepComplete,
    /// Function finished (return).
    FunctionFinished {
        /// Return value, if available.
        return_value: Option<u64>,
    },
    /// Exited with code.
    Exited {
        /// Exit code.
        code: i32,
    },
    /// Exited by signal.
    ExitedSignal {
        /// Signal name.
        signal: String,
    },
    /// Unknown reason.
    Unknown,
}

impl DrgnDetailedStopReason {
    /// Human-readable description.
    pub fn description(&self) -> String {
        match self {
            Self::Breakpoint {
                bp_id, address, ..
            } => {
                format!("Breakpoint {} at 0x{:x}", bp_id, address)
            }
            Self::Watchpoint { wp_id, .. } => format!("Watchpoint {}", wp_id),
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

    /// Convert to the simple `DrgnStopReason`.
    pub fn to_simple(&self) -> DrgnStopReason {
        match self {
            Self::Breakpoint { .. } => DrgnStopReason::Breakpoint,
            Self::Watchpoint { .. } => DrgnStopReason::Watchpoint,
            Self::Signal { .. } => DrgnStopReason::Signal,
            Self::StepComplete => DrgnStopReason::StepComplete,
            Self::FunctionFinished { .. } => DrgnStopReason::FunctionFinished,
            Self::Exited { .. } | Self::ExitedSignal { .. } => DrgnStopReason::Unknown,
            Self::Unknown => DrgnStopReason::Unknown,
        }
    }
}

/// Thread lifecycle event for drgn.
///
/// Tracks thread lifecycle events that need to be synchronized to the
/// Ghidra trace. Ported from the Python agent's thread event handling
/// in `hooks.py`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DrgnThreadEvent {
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
    /// A thread was selected by the user.
    Selected {
        /// Process number.
        process_num: u32,
        /// Thread number.
        thread_num: u32,
    },
}

impl DrgnThreadEvent {
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

/// Stepping type for drgn thread operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DrgnStepType {
    /// Step over (next instruction / source line).
    Over,
    /// Step into (step instruction / into function calls).
    Into,
    /// Step out (run until current function returns).
    Out,
    /// Single-step one instruction.
    Instruction,
}

impl DrgnStepType {
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

/// Thread plan tracking for drgn.
///
/// Describes what a thread should do before stopping again. This
/// mirrors the Python agent's stepping semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrgnThreadPlan {
    /// Plan description (e.g. "step over", "step until 0x401000").
    pub description: String,
    /// The step type, if this is a standard stepping plan.
    pub step_type: Option<DrgnStepType>,
    /// Target stop address (for "run to address" plans).
    pub stop_address: Option<u64>,
    /// Whether the plan is complete.
    pub completed: bool,
}

impl DrgnThreadPlan {
    /// Create a plan for a standard step.
    pub fn step(step_type: DrgnStepType) -> Self {
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
        Self::step(DrgnStepType::Out)
    }

    /// Mark the plan as complete.
    pub fn mark_complete(&mut self) {
        self.completed = true;
    }
}

/// Extended stack frame information for drgn.
///
/// Contains additional drgn-specific frame metadata beyond the basic
/// `DrgnStackFrame`, including unwinding information and language info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrgnFrameDetails {
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

impl DrgnFrameDetails {
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

/// A thread collection manager for a drgn process.
///
/// Manages thread lifecycle events (creation, exit) and provides
/// bulk operations on the thread set. Ported from the Python
/// `ProcessState` class in `hooks.py`.
#[derive(Debug, Default)]
pub struct DrgnThreadCollection {
    threads: BTreeMap<u32, DrgnThread>,
    process_num: u32,
}

impl DrgnThreadCollection {
    /// Create a new thread collection for a process.
    pub fn new(process_num: u32) -> Self {
        Self {
            threads: BTreeMap::new(),
            process_num,
        }
    }

    /// Add or replace a thread.
    pub fn insert(&mut self, thread: DrgnThread) {
        self.threads.insert(thread.num, thread);
    }

    /// Remove a thread by number.
    pub fn remove(&mut self, num: u32) -> Option<DrgnThread> {
        self.threads.remove(&num)
    }

    /// Get a thread by number.
    pub fn get(&self, num: u32) -> Option<&DrgnThread> {
        self.threads.get(&num)
    }

    /// Get a mutable thread by number.
    pub fn get_mut(&mut self, num: u32) -> Option<&mut DrgnThread> {
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
    pub fn iter(&self) -> impl Iterator<Item = &DrgnThread> {
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

/// Tracks the event thread for a trace.
///
/// Ported from the Python agent's event thread tracking. The event
/// thread is the thread that caused the most recent stop event.
#[derive(Debug, Clone, Default)]
pub struct DrgnEventThreadTracker {
    /// The process number of the event thread, if any.
    pub process_num: Option<u32>,
    /// The thread number of the event thread, if any.
    pub thread_num: Option<u32>,
}

impl DrgnEventThreadTracker {
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

/// Helper for frame selection tracking.
///
/// Ported from the frame selection context management in `commands.py`.
#[derive(Debug, Clone, Default)]
pub struct DrgnFrameSelection {
    /// The currently selected process.
    pub process_num: Option<u32>,
    /// The currently selected thread.
    pub thread_num: Option<u32>,
    /// The currently selected frame level.
    pub frame_level: Option<u32>,
}

impl DrgnFrameSelection {
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
                Some(format!(
                    "Processes[{}].Threads[{}].Stack[{}]",
                    p, t, f
                ))
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

/// Tracks whether a particular object path has been inserted into
/// the trace during this sync cycle.
///
/// Used to implement the retain_values pattern from the Python agent
/// where the container's children list is set to match exactly what
/// was synced.
#[derive(Debug, Clone, Default)]
pub struct TraceSyncTracker {
    /// Paths that have been synced in this cycle.
    pub synced_paths: Vec<String>,
}

impl TraceSyncTracker {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a path as synced.
    pub fn record(&mut self, path: String) {
        self.synced_paths.push(path);
    }

    /// Get the key patterns for retain_values.
    pub fn key_patterns(&self) -> Vec<String> {
        self.synced_paths.clone()
    }

    /// Clear for a new sync cycle.
    pub fn clear(&mut self) {
        self.synced_paths.clear();
    }

    /// Number of synced paths.
    pub fn len(&self) -> usize {
        self.synced_paths.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.synced_paths.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_state() {
        assert_eq!(
            DrgnThreadState::from_drgn_state(true, false, false),
            DrgnThreadState::Running
        );
        assert_eq!(
            DrgnThreadState::from_drgn_state(false, true, false),
            DrgnThreadState::Stopped
        );
        assert_eq!(
            DrgnThreadState::from_drgn_state(false, false, true),
            DrgnThreadState::Exited
        );
        assert_eq!(
            DrgnThreadState::from_drgn_state(false, false, false),
            DrgnThreadState::Inactive
        );
    }

    #[test]
    fn test_thread_state_to_execution_state() {
        assert_eq!(
            DrgnThreadState::Running.to_execution_state(),
            ExecutionState::Running
        );
        assert_eq!(
            DrgnThreadState::Stopped.to_execution_state(),
            ExecutionState::Stopped
        );
    }

    #[test]
    fn test_thread_state_trace_str() {
        assert_eq!(DrgnThreadState::Running.as_trace_str(), "RUNNING");
        assert_eq!(DrgnThreadState::Stopped.as_trace_str(), "STOPPED");
        assert_eq!(DrgnThreadState::Exited.as_trace_str(), "TERMINATED");
        assert_eq!(DrgnThreadState::Inactive.as_trace_str(), "INACTIVE");
    }

    #[test]
    fn test_thread_new() {
        let t = DrgnThread::new(0);
        assert_eq!(t.num, 0);
        assert_eq!(t.tid, None);
        assert_eq!(t.name, None);
        assert_eq!(t.state, ExecutionState::NotStarted);
        assert!(t.frames.is_empty());
        assert_eq!(t.process_num, 0);
        assert_eq!(t.cpu, None);
    }

    #[test]
    fn test_thread_cpu_thread() {
        let t = DrgnThread::cpu_thread(0, 3);
        assert_eq!(t.num, 0);
        assert_eq!(t.cpu, Some(3));
        assert_eq!(t.name, Some("CPU 3".to_string()));
        assert_eq!(t.process_num, 0);
    }

    #[test]
    fn test_thread_in_process() {
        let t = DrgnThread::in_process(2, 1);
        assert_eq!(t.num, 2);
        assert_eq!(t.process_num, 1);
    }

    #[test]
    fn test_thread_builder() {
        let t = DrgnThread::new(0)
            .with_tid(1234)
            .with_name("main")
            .with_state(ExecutionState::Running);
        assert_eq!(t.tid, Some(1234));
        assert_eq!(t.name, Some("main".to_string()));
        assert_eq!(t.state, ExecutionState::Running);
    }

    #[test]
    fn test_thread_trace_path() {
        let t = DrgnThread::in_process(2, 0);
        assert_eq!(t.trace_path(), "Processes[0].Threads[2]");
        assert_eq!(t.stack_path(), "Processes[0].Threads[2].Stack");
    }

    #[test]
    fn test_thread_frame_management() {
        let mut t = DrgnThread::new(0);
        t.add_frame(DrgnStackFrame::new(0, 0xffffffff81234567));
        t.add_frame(DrgnStackFrame::new(1, 0xffffffff81234000));
        assert_eq!(t.frame_count(), 2);
        assert!(t.innermost_frame().is_some());
        assert_eq!(t.innermost_frame().unwrap().pc, 0xffffffff81234567);

        let removed = t.remove_frame(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().pc, 0xffffffff81234000);
        assert_eq!(t.frame_count(), 1);

        t.clear_frames();
        assert_eq!(t.frame_count(), 0);
    }

    #[test]
    fn test_thread_frame_levels() {
        let mut t = DrgnThread::new(0);
        t.add_frame(DrgnStackFrame::new(0, 0x1000));
        t.add_frame(DrgnStackFrame::new(2, 0x2000));
        t.add_frame(DrgnStackFrame::new(1, 0x3000));
        let levels = t.frame_levels();
        assert_eq!(levels.len(), 3);
        assert!(levels.contains(&0));
        assert!(levels.contains(&1));
        assert!(levels.contains(&2));
    }

    #[test]
    fn test_thread_frame_mut() {
        let mut t = DrgnThread::new(0);
        t.add_frame(DrgnStackFrame::new(0, 0x1000));
        {
            let f = t.get_frame_mut(0).unwrap();
            f.sp = 0x7fff00;
        }
        assert_eq!(t.get_frame(0).unwrap().sp, 0x7fff00);
    }

    #[test]
    fn test_thread_to_thread_info() {
        let t = DrgnThread::cpu_thread(0, 2)
            .with_state(ExecutionState::Stopped);
        let info = t.to_thread_info();
        assert_eq!(info.id, 0);
        assert_eq!(info.name, Some("CPU 2".to_string()));
        assert_eq!(info.state, ExecutionState::Stopped);
    }

    #[test]
    fn test_thread_build_trace_values() {
        let t = DrgnThread::cpu_thread(0, 1)
            .with_tid(42)
            .with_state(ExecutionState::Stopped);
        let values = t.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "_state" && v == "STOPPED"));
        assert!(values.iter().any(|(k, v)| k == "_display" && v == "CPU 1"));
        assert!(values.iter().any(|(k, v)| k == "TID" && v == "42"));
        assert!(values.iter().any(|(k, v)| k == "CPU" && v == "1"));
    }

    #[test]
    fn test_thread_build_short_display() {
        let t = DrgnThread::in_process(0, 0).with_tid(0x1234);
        assert_eq!(t.build_short_display(), "[0.0]");

        let t = DrgnThread::cpu_thread(0, 3);
        assert_eq!(t.build_short_display(), "[0.0:cpu3]");
    }

    #[test]
    fn test_thread_build_long_display() {
        let t = DrgnThread::cpu_thread(0, 1)
            .with_tid(42)
            .with_name("CPU 1");
        assert_eq!(t.build_long_display(0), "0 0:2a CPU 1");

        let t = DrgnThread::new(0).with_tid(100);
        assert_eq!(t.build_long_display(2), "2 0:64");
    }

    #[test]
    fn test_thread_exit() {
        let mut t = DrgnThread::new(0).with_state(ExecutionState::Running);
        t.add_frame(DrgnStackFrame::new(0, 0xffffffff81234567));
        assert!(t.is_alive());

        t.mark_exited();
        assert!(!t.is_alive());
        assert_eq!(t.state, ExecutionState::Exited);
        assert!(t.frames.is_empty());
    }

    #[test]
    fn test_stack_frame_new() {
        let f = DrgnStackFrame::new(0, 0xffffffff81234567);
        assert_eq!(f.level, 0);
        assert_eq!(f.pc, 0xffffffff81234567);
        assert_eq!(f.sp, 0);
        assert!(f.function_name.is_none());
        assert!(!f.is_inline);
        assert!(!f.interrupted);
        assert!(f.source.is_none());
    }

    #[test]
    fn test_stack_frame_builder() {
        let f = DrgnStackFrame::new(0, 0xffffffff81234567)
            .with_sp(0xffff888000000000)
            .with_fp(0xffff888000001000)
            .with_return_address(0xffffffff81234000)
            .with_function("do_sys_open")
            .with_inline(false)
            .with_interrupted(true);
        assert_eq!(f.sp, 0xffff888000000000);
        assert_eq!(f.fp, 0xffff888000001000);
        assert_eq!(f.return_address, 0xffffffff81234000);
        assert_eq!(f.function_name.as_deref(), Some("do_sys_open"));
        assert!(!f.is_inline);
        assert!(f.interrupted);
    }

    #[test]
    fn test_stack_frame_with_source() {
        let f = DrgnStackFrame::new(0, 0xffffffff81234567)
            .with_source(FrameSourceInfo::new("fs/open.c", 1234, 5));
        assert!(f.source.is_some());
        let src = f.source.as_ref().unwrap();
        assert_eq!(src.filename, "fs/open.c");
        assert_eq!(src.line, 1234);
        assert_eq!(src.column, 5);
    }

    #[test]
    fn test_stack_frame_trace_paths() {
        let f = DrgnStackFrame::new(2, 0xffffffff81234567);
        assert_eq!(
            f.trace_path(0, 3),
            "Processes[0].Threads[3].Stack[2]"
        );
        assert_eq!(
            f.registers_trace_path(0, 3),
            "Processes[0].Threads[3].Stack[2].Registers"
        );
        assert_eq!(
            f.locals_trace_path(0, 3),
            "Processes[0].Threads[3].Stack[2].Locals"
        );
        assert_eq!(
            f.attributes_trace_path(0, 3),
            "Processes[0].Threads[3].Stack[2].Attributes"
        );
        assert_eq!(
            f.source_trace_path(0, 3),
            "Processes[0].Threads[3].Stack[2].Source"
        );
    }

    #[test]
    fn test_stack_frame_display() {
        let f = DrgnStackFrame::new(0, 0xffffffff81234567).with_function("do_sys_open");
        assert_eq!(f.build_display(), "#0 0xffffffff81234567 do_sys_open");

        let f = DrgnStackFrame::new(1, 0xffffffff81234000);
        assert_eq!(f.build_display(), "#1 0xffffffff81234000");
    }

    #[test]
    fn test_stack_frame_build_trace_values() {
        let f = DrgnStackFrame::new(0, 0xffffffff81234567)
            .with_function("do_sys_open");
        let values = f.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "Name" && v == "do_sys_open"));
        assert!(values.iter().any(|(k, v)| k == "_display" && v.contains("do_sys_open")));
    }

    #[test]
    fn test_stack_frame_build_attribute_values() {
        let f = DrgnStackFrame::new(0, 0xffffffff81234567)
            .with_inline(true)
            .with_interrupted(false);
        let values = f.build_attribute_values();
        assert!(values.iter().any(|(k, v)| k == "Inline" && v == "true"));
        assert!(values.iter().any(|(k, v)| k == "Interrupted" && v == "false"));
    }

    #[test]
    fn test_stack_frame_build_source_values() {
        let f = DrgnStackFrame::new(0, 0xffffffff81234567)
            .with_source(FrameSourceInfo::new("fs/open.c", 1234, 5));
        let values = f.build_source_values();
        assert!(values.is_some());
        let v = values.unwrap();
        assert!(v.iter().any(|(k, val)| k == "Filename" && val == "fs/open.c"));
        assert!(v.iter().any(|(k, val)| k == "Line" && val == "1234"));
        assert!(v.iter().any(|(k, val)| k == "Column" && val == "5"));

        let f2 = DrgnStackFrame::new(0, 0x1000);
        assert!(f2.build_source_values().is_none());
    }

    #[test]
    fn test_stack_frame_to_info() {
        let f = DrgnStackFrame::new(0, 0xffffffff81234567)
            .with_sp(0xffff888000000000)
            .with_function("do_sys_open");
        let info = f.to_stack_frame_info();
        assert_eq!(info.level, 0);
        assert_eq!(info.pc, 0xffffffff81234567);
        assert_eq!(info.sp, 0xffff888000000000);
        assert_eq!(info.function_name.as_deref(), Some("do_sys_open"));
    }

    #[test]
    fn test_stack_frame_registers() {
        let mut f = DrgnStackFrame::new(0, 0xffffffff81234567);
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
    fn test_register_display() {
        assert_eq!(DrgnStackFrame::build_register_display(0x1234), "0x1234");
        assert_eq!(DrgnStackFrame::build_register_display(0), "0x0");
        assert_eq!(
            DrgnStackFrame::build_register_display(0xffffffff81234567),
            "0xffffffff81234567"
        );
    }

    #[test]
    fn test_frame_source_info() {
        let src = FrameSourceInfo::new("kernel/sched/core.c", 5678, 12);
        let values = src.build_trace_values();
        assert_eq!(values.len(), 3);
        assert!(values.iter().any(|(k, v)| k == "Filename" && v == "kernel/sched/core.c"));
        assert!(values.iter().any(|(k, v)| k == "Line" && v == "5678"));
        assert!(values.iter().any(|(k, v)| k == "Column" && v == "12"));
    }

    #[test]
    fn test_thread_build_trace_values_extended() {
        let t = DrgnThread::cpu_thread(0, 1)
            .with_tid(42)
            .with_state(ExecutionState::Stopped);
        let values = t.build_trace_values_extended();
        assert!(values.iter().any(|(k, v)| k == "State" && v == "STOPPED"));
        assert!(values.iter().any(|(k, v)| k == "TID" && v == "42"));
        assert!(values.iter().any(|(k, v)| k == "CPU" && v == "1"));
        assert!(values.iter().any(|(k, v)| k == "Name" && v == "CPU 1"));
        assert!(values.iter().any(|(k, v)| k == "_short_display" && v.contains("0:2a")));
    }

    #[test]
    fn test_thread_build_display_extended_user() {
        let t = DrgnThread::in_process(1, 0)
            .with_tid(0x1234)
            .with_name("main");
        let disp = t.build_display_extended();
        assert!(disp.contains("1234"));
        assert!(disp.contains("main"));
    }

    #[test]
    fn test_thread_build_display_extended_kernel() {
        let t = DrgnThread::in_process(1, 0).with_tid(0x1234);
        let disp = t.build_display_extended();
        assert!(disp.contains("1234"));
    }

    #[test]
    fn test_thread_pc_sp() {
        let mut t = DrgnThread::new(0);
        assert!(t.pc().is_none());
        assert!(t.sp().is_none());

        t.add_frame(
            DrgnStackFrame::new(0, 0xffffffff81234567)
                .with_sp(0xffff888000000000)
                .with_fp(0xffff888000001000)
                .with_return_address(0xffffffff81234000),
        );
        assert_eq!(t.pc(), Some(0xffffffff81234567));
        assert_eq!(t.sp(), Some(0xffff888000000000));
    }

    #[test]
    fn test_thread_sorted_frames() {
        let mut t = DrgnThread::new(0);
        t.add_frame(DrgnStackFrame::new(2, 0x3000));
        t.add_frame(DrgnStackFrame::new(0, 0x1000));
        t.add_frame(DrgnStackFrame::new(1, 0x2000));
        let sorted = t.sorted_frames();
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[0].level, 0);
        assert_eq!(sorted[1].level, 1);
        assert_eq!(sorted[2].level, 2);
    }

    #[test]
    fn test_thread_frame_mut_v2() {
        let mut t = DrgnThread::new(0);
        t.add_frame(DrgnStackFrame::new(0, 0x1000));
        {
            let f = t.get_frame_mut(0).unwrap();
            f.sp = 0x7fff00;
        }
        assert_eq!(t.get_frame(0).unwrap().sp, 0x7fff00);
    }

    #[test]
    fn test_thread_build_trace_values_with_tid_and_name() {
        let t = DrgnThread::new(5)
            .with_tid(100)
            .with_name("worker")
            .with_state(ExecutionState::Running);
        let values = t.build_trace_values_extended();
        assert!(values.iter().any(|(k, v)| k == "State" && v == "RUNNING"));
        assert!(values.iter().any(|(k, v)| k == "TID" && v == "100"));
        assert!(values.iter().any(|(k, v)| k == "Name" && v == "worker"));
        assert!(values.iter().any(|(k, v)| k == "_display" && v.contains("worker")));
    }

    #[test]
    fn test_stack_frame_build_trace_values_with_name() {
        let f = DrgnStackFrame::new(0, 0xffffffff81234567)
            .with_function("do_sys_open");
        let values = f.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "Name" && v == "do_sys_open"));
        assert!(values.iter().any(|(k, v)| k == "_display" && v.contains("do_sys_open")));
    }

    #[test]
    fn test_stack_frame_locals_trace_path() {
        let f = DrgnStackFrame::new(1, 0x1000);
        assert_eq!(
            f.locals_trace_path(0, 2),
            "Processes[0].Threads[2].Stack[1].Locals"
        );
    }

    #[test]
    fn test_local_variable_value() {
        let local = DrgnLocalVariableValue::new("fd", "int", "3")
            .with_address(0x7fff0000)
            .with_type_kind("INT");
        assert_eq!(local.name, "fd");
        assert_eq!(local.type_name, "int");
        assert_eq!(local.value, "3");
        assert_eq!(local.address, Some(0x7fff0000));
        assert!(!local.is_absent);
        assert_eq!(local.type_kind.as_deref(), Some("INT"));
        assert_eq!(
            local.trace_path(0, 1, 2),
            "Processes[0].Threads[1].Stack[2].Locals.fd"
        );
    }

    #[test]
    fn test_local_variable_value_absent() {
        let local = DrgnLocalVariableValue::new("reg", "unsigned long", "<optimized out>")
            .with_absent(true);
        assert!(local.is_absent);
        let values = local.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "Value" && v == "<absent>"));
        assert!(values.iter().any(|(k, v)| k == "Type" && v == "unsigned long"));
    }

    #[test]
    fn test_local_variable_value_build_trace() {
        let local = DrgnLocalVariableValue::new("count", "size_t", "42")
            .with_address(0x1000);
        let values = local.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "Type" && v == "size_t"));
        assert!(values.iter().any(|(k, v)| k == "Value" && v == "42"));
        assert!(values.iter().any(|(k, v)| k == "Address" && v == "0x1000"));
        assert!(values.iter().any(|(k, _)| k == "_display"));
    }

    #[test]
    fn test_frame_locals() {
        let mut locals = DrgnFrameLocals::new(0, 1, 2);
        assert_eq!(locals.local_count(), 0);

        locals.add_local(DrgnLocalVariableValue::new("fd", "int", "3"));
        locals.add_local(DrgnLocalVariableValue::new("buf", "char *", "0x7fff0000"));
        assert_eq!(locals.local_count(), 2);
        assert!(locals.get_local("fd").is_some());
        assert!(locals.get_local("buf").is_some());
        assert!(locals.get_local("missing").is_none());

        let names = locals.local_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"fd"));
        assert!(names.contains(&"buf"));
    }

    #[test]
    fn test_frame_locals_replace() {
        let mut locals = DrgnFrameLocals::new(0, 0, 0);
        locals.add_local(DrgnLocalVariableValue::new("x", "int", "1"));
        locals.add_local(DrgnLocalVariableValue::new("x", "int", "2"));
        assert_eq!(locals.local_count(), 1);
        assert_eq!(locals.get_local("x").unwrap().value, "2");
    }

    #[test]
    fn test_frame_locals_remove() {
        let mut locals = DrgnFrameLocals::new(0, 0, 0);
        locals.add_local(DrgnLocalVariableValue::new("x", "int", "1"));
        let removed = locals.remove_local("x");
        assert!(removed.is_some());
        assert_eq!(locals.local_count(), 0);
    }

    #[test]
    fn test_frame_locals_trace_path() {
        let locals = DrgnFrameLocals::new(0, 2, 3);
        assert_eq!(
            locals.trace_path(),
            "Processes[0].Threads[2].Stack[3].Locals"
        );
    }

    #[test]
    fn test_frame_locals_build_all() {
        let mut locals = DrgnFrameLocals::new(0, 1, 0);
        locals.add_local(DrgnLocalVariableValue::new("a", "int", "1"));
        locals.add_local(DrgnLocalVariableValue::new("b", "int", "2"));
        let all = locals.build_all_trace_values();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|(p, _)| p.contains("Locals.a")));
        assert!(all.iter().any(|(p, _)| p.contains("Locals.b")));
    }

    #[test]
    fn test_frame_locals_clear() {
        let mut locals = DrgnFrameLocals::new(0, 0, 0);
        locals.add_local(DrgnLocalVariableValue::new("x", "int", "1"));
        locals.clear();
        assert_eq!(locals.local_count(), 0);
    }

    #[test]
    fn test_frame_register_batch() {
        let mut batch = FrameRegisterBatch::new(0);
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);

        batch.push(RegisterValue::from_u64("rax", 0x1234));
        batch.push(RegisterValue::from_u64("rbx", 0x5678));
        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());

        assert!(batch.get("rax").is_some());
        assert_eq!(batch.get("rax").unwrap().as_u64(), Some(0x1234));
        assert!(batch.get("rcx").is_none());

        let names = batch.names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"rax"));
        assert!(names.contains(&"rbx"));
    }

    #[test]
    fn test_frame_register_batch_trace_path() {
        let batch = FrameRegisterBatch::new(2);
        assert_eq!(
            batch.trace_path(0, 3),
            "Processes[0].Threads[3].Stack[2].Registers"
        );
    }

    #[test]
    fn test_frame_register_batch_pairs() {
        let mut batch = FrameRegisterBatch::new(0);
        batch.push(RegisterValue::from_u64("rax", 0x1234));
        let pairs = batch.build_register_pairs(0, 1);
        assert_eq!(pairs.len(), 1);
        assert!(pairs[0].0.contains("Registers.rax"));
        assert_eq!(pairs[0].1.len(), 8); // u64 = 8 bytes
    }

    #[test]
    fn test_frame_register_batch_clear() {
        let mut batch = FrameRegisterBatch::new(0);
        batch.push(RegisterValue::from_u64("rax", 0x1234));
        batch.clear();
        assert!(batch.is_empty());
    }

    #[test]
    fn test_trace_sync_tracker() {
        let mut tracker = TraceSyncTracker::new();
        assert!(tracker.is_empty());

        tracker.record("Processes[0].Threads[0]".to_string());
        tracker.record("Processes[0].Threads[1]".to_string());
        assert_eq!(tracker.len(), 2);

        let keys = tracker.key_patterns();
        assert_eq!(keys.len(), 2);

        tracker.clear();
        assert!(tracker.is_empty());
    }

    #[test]
    fn test_thread_outermost_frame() {
        let mut t = DrgnThread::new(0);
        assert!(t.outermost_frame().is_none());
        t.add_frame(DrgnStackFrame::new(0, 0x1000));
        t.add_frame(DrgnStackFrame::new(2, 0x3000));
        t.add_frame(DrgnStackFrame::new(1, 0x2000));
        let outer = t.outermost_frame();
        assert!(outer.is_some());
        assert_eq!(outer.unwrap().level, 2);
    }

    #[test]
    fn test_thread_build_backtrace() {
        let mut t = DrgnThread::new(0);
        t.add_frame(DrgnStackFrame::new(0, 0x1000).with_function("main"));
        t.add_frame(DrgnStackFrame::new(1, 0x2000).with_function("foo"));
        let bt = t.build_backtrace();
        assert_eq!(bt.len(), 2);
        assert!(bt[0].contains("main"));
        assert!(bt[1].contains("foo"));
    }

    #[test]
    fn test_thread_stack_container_values() {
        let mut t = DrgnThread::new(0);
        t.add_frame(DrgnStackFrame::new(0, 0x1000));
        let values = t.build_stack_container_values();
        assert!(values.iter().any(|(k, v)| k == "_count" && v == "1"));
    }

    #[test]
    fn test_thread_all_register_names() {
        let mut t = DrgnThread::new(0);
        let mut f = DrgnStackFrame::new(0, 0x1000);
        f.set_register(RegisterValue::from_u64("rax", 0x1234));
        f.set_register(RegisterValue::from_u64("rbx", 0x5678));
        t.add_frame(f);
        let mut f2 = DrgnStackFrame::new(1, 0x2000);
        f2.set_register(RegisterValue::from_u64("rax", 0x9999));
        f2.set_register(RegisterValue::from_u64("rcx", 0xaaaa));
        t.add_frame(f2);
        let names = t.all_register_names();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"rax".to_string()));
        assert!(names.contains(&"rbx".to_string()));
        assert!(names.contains(&"rcx".to_string()));
    }

    #[test]
    fn test_thread_frame_at_pc() {
        let mut t = DrgnThread::new(0);
        t.add_frame(DrgnStackFrame::new(0, 0x1000));
        t.add_frame(DrgnStackFrame::new(1, 0x2000));
        assert!(t.frame_at_pc(0x1000).is_some());
        assert!(t.frame_at_pc(0x2000).is_some());
        assert!(t.frame_at_pc(0x3000).is_none());
    }

    #[test]
    fn test_thread_return_address() {
        let mut t = DrgnThread::new(0);
        assert!(t.return_address().is_none());
        t.add_frame(
            DrgnStackFrame::new(0, 0x1000).with_return_address(0),
        );
        assert!(t.return_address().is_none());
        t.clear_frames();
        t.add_frame(
            DrgnStackFrame::new(0, 0x1000).with_return_address(0x4000),
        );
        assert_eq!(t.return_address(), Some(0x4000));
    }

    #[test]
    fn test_thread_state_queries() {
        let t = DrgnThread::new(0).with_state(ExecutionState::Running);
        assert!(t.is_running());
        assert!(!t.is_stopped());
        assert!(!t.is_exited());

        let t = DrgnThread::new(0).with_state(ExecutionState::Stopped);
        assert!(t.is_stopped());
        assert!(!t.is_running());

        let t = DrgnThread::new(0).with_state(ExecutionState::Exited);
        assert!(t.is_exited());
    }

    #[test]
    fn test_thread_frame_retain_keys() {
        let mut t = DrgnThread::new(0);
        t.add_frame(DrgnStackFrame::new(0, 0x1000));
        t.add_frame(DrgnStackFrame::new(2, 0x3000));
        let keys = t.build_frame_retain_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"[0]".to_string()));
        assert!(keys.contains(&"[2]".to_string()));
    }

    #[test]
    fn test_thread_frame_paths() {
        let t = DrgnThread::in_process(1, 0);
        assert_eq!(t.frame_path(2), "Processes[0].Threads[1].Stack[2]");
        assert_eq!(
            t.frame_registers_path(3),
            "Processes[0].Threads[1].Stack[3].Registers"
        );
    }

    #[test]
    fn test_stop_reason() {
        assert_eq!(DrgnStopReason::Breakpoint.description(), "Breakpoint");
        assert!(DrgnStopReason::Breakpoint.is_stopped());
        assert!(DrgnStopReason::Signal.is_stopped());
        assert!(!DrgnStopReason::ThreadExiting.is_stopped());
    }

    #[test]
    fn test_detailed_stop_reason() {
        let reason = DrgnDetailedStopReason::Breakpoint {
            bp_id: 1,
            address: 0x401000,
        };
        assert!(reason.description().contains("Breakpoint"));
        assert!(reason.is_stopped());
        assert_eq!(reason.to_simple(), DrgnStopReason::Breakpoint);

        let signal = DrgnDetailedStopReason::Signal {
            name: "SIGSEGV".to_string(),
            number: 11,
        };
        assert!(signal.description().contains("SIGSEGV"));
        assert_eq!(signal.to_simple(), DrgnStopReason::Signal);

        let exited = DrgnDetailedStopReason::Exited { code: 0 };
        assert!(!exited.is_stopped());
    }

    #[test]
    fn test_thread_event() {
        let evt = DrgnThreadEvent::Created {
            process_num: 0,
            thread_num: 1,
        };
        assert_eq!(evt.process_num(), 0);
        assert_eq!(evt.thread_num(), 1);
        assert!(evt.description().contains("created"));

        let evt2 = DrgnThreadEvent::StateChanged {
            process_num: 0,
            thread_num: 1,
            new_state: ExecutionState::Stopped,
        };
        assert!(evt2.description().contains("STOPPED"));
    }

    #[test]
    fn test_step_type() {
        assert_eq!(DrgnStepType::Over.description(), "Step Over");
        assert_eq!(DrgnStepType::Into.description(), "Step Into");
        assert_eq!(DrgnStepType::Out.description(), "Step Out");
        assert_eq!(
            DrgnStepType::Instruction.description(),
            "Step Instruction"
        );
    }

    #[test]
    fn test_thread_plan() {
        let plan = DrgnThreadPlan::step(DrgnStepType::Over);
        assert_eq!(plan.step_type, Some(DrgnStepType::Over));
        assert!(!plan.completed);
        assert!(plan.description.contains("Step Over"));

        let plan2 = DrgnThreadPlan::run_to_address(0x401000);
        assert!(plan2.description.contains("0x401000"));
        assert_eq!(plan2.stop_address, Some(0x401000));
        assert!(plan2.step_type.is_none());

        let mut plan3 = DrgnThreadPlan::step_out();
        assert!(!plan3.completed);
        plan3.mark_complete();
        assert!(plan3.completed);
    }

    #[test]
    fn test_frame_details() {
        let details = DrgnFrameDetails::new(0)
            .with_source("fs/open.c", 1234)
            .with_language("c")
            .with_inline(true);
        assert_eq!(details.level, 0);
        assert!(details.is_inline);
        assert_eq!(details.source_file.as_deref(), Some("fs/open.c"));
        assert_eq!(details.source_line, Some(1234));
        assert_eq!(details.language.as_deref(), Some("c"));
        let display = details.build_display(0x401000, Some("do_sys_open"));
        assert!(display.contains("inlined"));
        assert!(display.contains("do_sys_open"));
        assert!(display.contains("fs/open.c:1234"));
    }

    #[test]
    fn test_thread_collection() {
        let mut coll = DrgnThreadCollection::new(0);
        assert!(coll.is_empty());
        assert_eq!(coll.process_num(), 0);

        coll.insert(DrgnThread::new(0).with_state(ExecutionState::Running));
        coll.insert(DrgnThread::new(1).with_state(ExecutionState::Stopped));
        coll.insert(DrgnThread::new(2).with_state(ExecutionState::Exited));
        assert_eq!(coll.len(), 3);
        assert!(coll.get(0).is_some());
        assert!(coll.get(3).is_none());

        let exited = coll.prune_exited();
        assert_eq!(exited, vec![2]);
        assert_eq!(coll.len(), 2);

        coll.clear_all_frames();
        coll.mark_all_synced();
        assert!(coll.get(0).unwrap().synced);
    }

    #[test]
    fn test_thread_collection_info() {
        let mut coll = DrgnThreadCollection::new(0);
        coll.insert(DrgnThread::new(0).with_tid(100).with_name("main"));
        coll.insert(DrgnThread::new(1).with_tid(200).with_name("worker"));
        let info = coll.build_thread_info_list();
        assert_eq!(info.len(), 2);
    }

    #[test]
    fn test_event_thread_tracker() {
        let mut tracker = DrgnEventThreadTracker::new();
        assert!(tracker.trace_path().is_none());

        tracker.set(0, 1);
        assert_eq!(
            tracker.trace_path(),
            Some("Processes[0].Threads[1]".to_string())
        );
        assert!(tracker.is_event_thread(0, 1));
        assert!(!tracker.is_event_thread(0, 2));

        tracker.clear();
        assert!(tracker.trace_path().is_none());
    }

    #[test]
    fn test_frame_selection() {
        let mut sel = DrgnFrameSelection::new();
        assert!(sel.frame_path().is_none());
        assert!(sel.thread_path().is_none());

        sel.set(0, 1, 2);
        assert_eq!(
            sel.frame_path(),
            Some("Processes[0].Threads[1].Stack[2]".to_string())
        );
        assert_eq!(
            sel.thread_path(),
            Some("Processes[0].Threads[1]".to_string())
        );

        sel.clear();
        assert!(sel.frame_path().is_none());
    }
}
