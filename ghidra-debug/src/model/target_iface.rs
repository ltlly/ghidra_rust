//! TraceObjectInterface - interfaces that objects in the target tree can implement.
//!
//! Ported from Ghidra's `ghidra.trace.model.target.iface` package.
//! These interfaces define behaviors that objects in the debug target tree
//! can support, such as being a thread, a process, an activatable entity, etc.

use serde::{Deserialize, Serialize};

use crate::target::key_path::KeyPath;

/// Well-known keys used by the target object system.
pub mod keys {
    /// Display name for the object.
    pub const DISPLAY: &str = "_display";
    /// Short display name.
    pub const SHORT_DISPLAY: &str = "_short_display";
    /// Kind/type label.
    pub const KIND: &str = "_kind";
    /// Ordering key.
    pub const ORDER: &str = "_order";
    /// Last-modified timestamp.
    pub const MODIFIED: &str = "_modified";
    /// Type information.
    pub const TYPE: &str = "_type";
    /// Value.
    pub const VALUE: &str = "_value";
    /// Comment text.
    pub const COMMENT: &str = "_comment";
}

/// The common interface for all object-based trace manager entries.
///
/// Every object in the target tree that acts as a named entity (thread,
/// process, module, etc.) implements this interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceObjectInterface {
    /// The path to this object in the target tree.
    pub path: KeyPath,
    /// The display name.
    pub display: Option<String>,
    /// A comment or description.
    pub comment: Option<String>,
}

impl TraceObjectInterface {
    /// Create a new object interface binding.
    pub fn new(path: KeyPath) -> Self {
        Self {
            path,
            display: None,
            comment: None,
        }
    }

    /// Set the display name.
    pub fn with_display(mut self, display: impl Into<String>) -> Self {
        self.display = Some(display.into());
        self
    }
}

/// An entity that can be activated (focused) in the UI.
///
/// This includes threads, processes, and other entities that the user
/// can select as the "current" target for debugging operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceActivatable {
    /// Whether this entity is currently active.
    pub active: bool,
    /// The path to the object.
    pub path: KeyPath,
}

impl TraceActivatable {
    /// Create a new activatable binding.
    pub fn new(path: KeyPath) -> Self {
        Self {
            active: false,
            path,
        }
    }

    /// Check if active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Set active state.
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }
}

/// An entity that can be toggled on/off.
///
/// Used for breakpoints, watchpoints, and similar binary-state items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTogglable {
    /// Whether this entity is enabled.
    pub enabled: bool,
    /// The path to the object.
    pub path: KeyPath,
}

impl TraceTogglable {
    /// Create a new togglable binding.
    pub fn new(path: KeyPath) -> Self {
        Self { enabled: true, path }
    }

    /// Toggle the enabled state.
    pub fn toggle(&mut self) {
        self.enabled = !self.enabled;
    }

    /// Check if enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// An entity with execution state (running, stopped, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionState {
    /// The target is alive and running.
    Running,
    /// The target is stopped (e.g., at a breakpoint).
    Stopped,
    /// The target is in the process of terminating.
    Terminating,
    /// The target has terminated.
    Terminated,
    /// The target is in an unknown state.
    Unknown,
}

/// An entity that has execution state.
///
/// Used for threads and processes that can be in various execution states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceExecutionStateful {
    /// The current execution state.
    pub state: ExecutionState,
    /// The path to the object.
    pub path: KeyPath,
}

impl TraceExecutionStateful {
    /// Create a new execution-stateful binding.
    pub fn new(path: KeyPath) -> Self {
        Self {
            state: ExecutionState::Unknown,
            path,
        }
    }

    /// Check if the target is running.
    pub fn is_running(&self) -> bool {
        self.state == ExecutionState::Running
    }

    /// Check if the target is stopped.
    pub fn is_stopped(&self) -> bool {
        self.state == ExecutionState::Stopped
    }
}

/// An entity that determines the focus scope for the debug session.
///
/// The focus scope determines which thread/process is "in focus" for
/// operations like stepping and reading registers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceFocusScope {
    /// The path of the object that currently has focus.
    pub focus_path: Option<KeyPath>,
    /// The path of this scope object.
    pub path: KeyPath,
}

impl TraceFocusScope {
    /// Create a new focus scope.
    pub fn new(path: KeyPath) -> Self {
        Self {
            focus_path: None,
            path,
        }
    }

    /// Get the focused path, if any.
    pub fn focused(&self) -> Option<&KeyPath> {
        self.focus_path.as_ref()
    }

    /// Set the focus.
    pub fn set_focus(&mut self, path: Option<KeyPath>) {
        self.focus_path = path;
    }
}

/// An entity that defines the event scope for the debug session.
///
/// The event scope determines which events (breakpoints, signals, etc.)
/// are visible in the current context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEventScope {
    /// The path of this scope.
    pub path: KeyPath,
}

impl TraceEventScope {
    /// Create a new event scope.
    pub fn new(path: KeyPath) -> Self {
        Self { path }
    }
}

/// An entity representing the debug environment (OS, architecture info).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEnvironment {
    /// The operating system name.
    pub os: String,
    /// The architecture name.
    pub arch: String,
    /// The path to this environment object.
    pub path: KeyPath,
}

impl TraceEnvironment {
    /// Create a new environment binding.
    pub fn new(path: KeyPath, os: impl Into<String>, arch: impl Into<String>) -> Self {
        Self {
            os: os.into(),
            arch: arch.into(),
            path,
        }
    }
}

/// A method (function) in the debug target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMethod {
    /// The name of the method.
    pub name: String,
    /// The entry point address.
    pub entry_point: u64,
    /// The path to this method object.
    pub path: KeyPath,
}

impl TraceMethod {
    /// Create a new method binding.
    pub fn new(path: KeyPath, name: impl Into<String>, entry_point: u64) -> Self {
        Self {
            name: name.into(),
            entry_point,
            path,
        }
    }
}

/// An aggregate object that contains multiple sub-objects.
///
/// Used to represent containers like process->threads, module->sections, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceAggregate {
    /// The path to this aggregate.
    pub path: KeyPath,
    /// The number of contained elements.
    pub element_count: usize,
}

impl TraceAggregate {
    /// Create a new aggregate binding.
    pub fn new(path: KeyPath) -> Self {
        Self {
            path,
            element_count: 0,
        }
    }
}

/// A section within a loaded module (target object view).
///
/// Represents a memory section like `.text`, `.data`, `.bss`, etc.
/// This is the target-tree interface version; the model-level section
/// is in `model::module::TraceSection`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTargetSection {
    /// The section name (e.g., ".text").
    pub name: String,
    /// The start address in the trace.
    pub trace_start: u64,
    /// The end address in the trace (inclusive).
    pub trace_end: u64,
    /// The section offset within the module.
    pub module_offset: u64,
    /// The length in bytes.
    pub length: u64,
    /// The path to this section.
    pub path: KeyPath,
}

impl TraceTargetSection {
    /// Create a new section.
    pub fn new(
        path: KeyPath,
        name: impl Into<String>,
        trace_start: u64,
        trace_end: u64,
        module_offset: u64,
    ) -> Self {
        let length = trace_end - trace_start + 1;
        Self {
            name: name.into(),
            trace_start,
            trace_end,
            module_offset,
            length,
            path,
        }
    }

    /// Whether this section contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.trace_start && addr <= self.trace_end
    }
}

/// A container for register values at a particular point in time.
///
/// Ported from Ghidra's `TraceRegisterContainer` target interface.
/// This is the target-tree interface version; the model-level container
/// is in `model::register::TraceRegisterContainer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTargetRegisterContainer {
    /// The path to this register container.
    pub path: KeyPath,
    /// The register names held by this container.
    pub register_names: Vec<String>,
}

impl TraceTargetRegisterContainer {
    /// Create a new register container.
    pub fn new(path: KeyPath) -> Self {
        Self {
            path,
            register_names: Vec::new(),
        }
    }

    /// Add a register name.
    pub fn add_register(&mut self, name: impl Into<String>) {
        self.register_names.push(name.into());
    }
}

/// A stack frame in a thread's call stack (target object view).
///
/// Ported from Ghidra's `TraceStackFrame` target interface.
/// This is the target-tree interface version; the model-level frame
/// is in `model::stack::TraceStackFrame`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTargetStackFrame {
    /// The frame level (0 = innermost).
    pub level: u32,
    /// The program counter (return address or current instruction).
    pub pc: u64,
    /// The stack pointer for this frame.
    pub stack_pointer: u64,
    /// The frame pointer for this frame.
    pub frame_pointer: Option<u64>,
    /// The path to this frame.
    pub path: KeyPath,
}

impl TraceTargetStackFrame {
    /// Create a new stack frame.
    pub fn new(path: KeyPath, level: u32, pc: u64, stack_pointer: u64) -> Self {
        Self {
            level,
            pc,
            stack_pointer,
            frame_pointer: None,
            path,
        }
    }

    /// Set the frame pointer.
    pub fn with_frame_pointer(mut self, fp: u64) -> Self {
        self.frame_pointer = Some(fp);
        self
    }
}

/// A call stack for a thread (target object view).
///
/// Ported from Ghidra's `TraceStack` target interface.
/// This is the target-tree interface version; the model-level stack
/// is in `model::stack::TraceStack`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTargetStack {
    /// The path to this stack.
    pub path: KeyPath,
    /// The frames in this stack (innermost first).
    pub frames: Vec<TraceTargetStackFrame>,
    /// The thread ID this stack belongs to.
    pub thread_id: u64,
}

impl TraceTargetStack {
    /// Create a new stack.
    pub fn new(path: KeyPath, thread_id: u64) -> Self {
        Self {
            path,
            frames: Vec::new(),
            thread_id,
        }
    }

    /// Add a frame.
    pub fn push_frame(&mut self, frame: TraceTargetStackFrame) {
        self.frames.push(frame);
    }

    /// Get the depth (number of frames).
    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Get the innermost frame (level 0).
    pub fn innermost(&self) -> Option<&TraceTargetStackFrame> {
        self.frames.first()
    }
}

/// A process in the debug target (target object view).
///
/// Ported from Ghidra's `TraceProcess` target interface.
/// This is the target-tree interface version; the model-level process
/// is in `model::thread::TraceProcess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTargetProcess {
    /// The process ID.
    pub pid: u64,
    /// The process name.
    pub name: String,
    /// The path to this process.
    pub path: KeyPath,
    /// The execution state of the process.
    pub state: ExecutionState,
}

impl TraceTargetProcess {
    /// Create a new process.
    pub fn new(path: KeyPath, pid: u64, name: impl Into<String>) -> Self {
        Self {
            pid,
            name: name.into(),
            path,
            state: ExecutionState::Unknown,
        }
    }

    /// Check if the process is alive.
    pub fn is_alive(&self) -> bool {
        !matches!(self.state, ExecutionState::Terminated)
    }
}

/// A memory region in the debug target.
///
/// Ported from Ghidra's `TraceRegion` / `TraceMemoryRegion`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRegion {
    /// The region name.
    pub name: String,
    /// The start address.
    pub start: u64,
    /// The end address (inclusive).
    pub end: u64,
    /// Whether this region is readable.
    pub readable: bool,
    /// Whether this region is writable.
    pub writable: bool,
    /// Whether this region is executable.
    pub executable: bool,
    /// The path to this region.
    pub path: KeyPath,
}

impl TraceRegion {
    /// Create a new memory region.
    pub fn new(
        path: KeyPath,
        name: impl Into<String>,
        start: u64,
        end: u64,
        readable: bool,
        writable: bool,
        executable: bool,
    ) -> Self {
        Self {
            name: name.into(),
            start,
            end,
            readable,
            writable,
            executable,
            path,
        }
    }

    /// The length of the region.
    pub fn length(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Whether this region contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr <= self.end
    }
}

/// A register value in the debug target (target object view).
///
/// Ported from Ghidra's `TraceRegister` / register value concepts.
/// This is the target-tree interface version; the model-level register
/// value is in `model::register_context::TraceRegisterValue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTargetRegisterValue {
    /// The register name.
    pub name: String,
    /// The register value bytes.
    pub value: Vec<u8>,
    /// The bit size of the register.
    pub bit_size: u32,
}

impl TraceTargetRegisterValue {
    /// Create a new register value.
    pub fn new(name: impl Into<String>, value: Vec<u8>, bit_size: u32) -> Self {
        Self {
            name: name.into(),
            value,
            bit_size,
        }
    }

    /// Interpret the value as a u64 (little-endian).
    pub fn as_u64_le(&self) -> Option<u64> {
        if self.value.len() > 8 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf[..self.value.len()].copy_from_slice(&self.value);
        Some(u64::from_le_bytes(buf))
    }
}

/// An event (e.g., a breakpoint hit, signal) in the debug target.
///
/// Ported from Ghidra's trace event concepts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTargetEvent {
    /// The event type (e.g., "breakpoint-hit", "signal", "step").
    pub event_type: String,
    /// The thread the event occurred in, if any.
    pub thread_id: Option<u64>,
    /// The process the event occurred in, if any.
    pub process_id: Option<u64>,
    /// The path to this event.
    pub path: KeyPath,
    /// Additional event details.
    pub details: std::collections::BTreeMap<String, String>,
}

impl TraceTargetEvent {
    /// Create a new event.
    pub fn new(path: KeyPath, event_type: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
            thread_id: None,
            process_id: None,
            path,
            details: std::collections::BTreeMap::new(),
        }
    }

    /// Set the thread ID.
    pub fn with_thread_id(mut self, tid: u64) -> Self {
        self.thread_id = Some(tid);
        self
    }

    /// Set the process ID.
    pub fn with_process_id(mut self, pid: u64) -> Self {
        self.process_id = Some(pid);
        self
    }

    /// Add a detail entry.
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_object_interface() {
        let iface = TraceObjectInterface::new(KeyPath::parse("Processes[0].Threads[1]"))
            .with_display("Thread #1");
        assert_eq!(iface.display.as_deref(), Some("Thread #1"));
    }

    #[test]
    fn test_activatable() {
        let mut act = TraceActivatable::new(KeyPath::parse("Threads[0]"));
        assert!(!act.is_active());
        act.set_active(true);
        assert!(act.is_active());
    }

    #[test]
    fn test_togglable() {
        let mut tog = TraceTogglable::new(KeyPath::parse("Breakpoints[0]"));
        assert!(tog.is_enabled());
        tog.toggle();
        assert!(!tog.is_enabled());
        tog.toggle();
        assert!(tog.is_enabled());
    }

    #[test]
    fn test_execution_stateful() {
        let mut es = TraceExecutionStateful::new(KeyPath::parse("Threads[0]"));
        assert!(!es.is_running());
        assert!(!es.is_stopped());
        es.state = ExecutionState::Running;
        assert!(es.is_running());
        es.state = ExecutionState::Stopped;
        assert!(es.is_stopped());
    }

    #[test]
    fn test_focus_scope() {
        let mut fs = TraceFocusScope::new(KeyPath::parse("Session"));
        assert!(fs.focused().is_none());
        fs.set_focus(Some(KeyPath::parse("Threads[0]")));
        assert!(!fs.focused().unwrap().to_string().is_empty());
    }

    #[test]
    fn test_environment() {
        let env = TraceEnvironment::new(
            KeyPath::parse("Environment"),
            "linux",
            "x86_64",
        );
        assert_eq!(env.os, "linux");
        assert_eq!(env.arch, "x86_64");
    }

    #[test]
    fn test_method() {
        let m = TraceMethod::new(KeyPath::parse("Functions[0]"), "main", 0x401000);
        assert_eq!(m.name, "main");
        assert_eq!(m.entry_point, 0x401000);
    }

    #[test]
    fn test_aggregate() {
        let agg = TraceAggregate::new(KeyPath::parse("Processes"));
        assert_eq!(agg.element_count, 0);
    }

    #[test]
    fn test_keys() {
        assert_eq!(keys::DISPLAY, "_display");
        assert_eq!(keys::VALUE, "_value");
        assert_eq!(keys::COMMENT, "_comment");
    }

    #[test]
    fn test_trace_target_section() {
        let section = TraceTargetSection::new(
            KeyPath::parse("Modules[0].Sections[0]"),
            ".text",
            0x400000,
            0x400fff,
            0x1000,
        );
        assert_eq!(section.name, ".text");
        assert_eq!(section.length, 0x1000);
        assert!(section.contains(0x400500));
        assert!(!section.contains(0x500000));
    }

    #[test]
    fn test_target_register_container() {
        let mut rc = TraceTargetRegisterContainer::new(KeyPath::parse("Threads[0].Registers"));
        rc.add_register("RIP");
        rc.add_register("RSP");
        assert_eq!(rc.register_names.len(), 2);
    }

    #[test]
    fn test_target_stack_frame() {
        let frame = TraceTargetStackFrame::new(
            KeyPath::parse("Threads[0].Stack[0]"),
            0,
            0x401000,
            0x7fff0000,
        )
        .with_frame_pointer(0x7fff0010);
        assert_eq!(frame.level, 0);
        assert_eq!(frame.pc, 0x401000);
        assert_eq!(frame.frame_pointer, Some(0x7fff0010));
    }

    #[test]
    fn test_target_stack() {
        let mut stack = TraceTargetStack::new(KeyPath::parse("Threads[0].Stack"), 1);
        assert_eq!(stack.depth(), 0);
        assert!(stack.innermost().is_none());

        stack.push_frame(TraceTargetStackFrame::new(
            KeyPath::parse("Stack[0]"), 0, 0x401000, 0x7fff0000,
        ));
        stack.push_frame(TraceTargetStackFrame::new(
            KeyPath::parse("Stack[1]"), 1, 0x402000, 0x7fff0020,
        ));
        assert_eq!(stack.depth(), 2);
        assert_eq!(stack.innermost().unwrap().pc, 0x401000);
    }

    #[test]
    fn test_target_process() {
        let mut proc = TraceTargetProcess::new(KeyPath::parse("Processes[0]"), 1234, "test_program");
        assert_eq!(proc.pid, 1234);
        assert!(proc.is_alive());
        proc.state = ExecutionState::Terminated;
        assert!(!proc.is_alive());
    }

    #[test]
    fn test_trace_region() {
        let region = TraceRegion::new(
            KeyPath::parse("Memory.Regions[0]"),
            "stack",
            0x7fff0000,
            0x7fffffff,
            true,
            true,
            false,
        );
        assert_eq!(region.length(), 0x10000);
        assert!(region.readable);
        assert!(region.writable);
        assert!(!region.executable);
        assert!(region.contains(0x7fff5000));
    }

    #[test]
    fn test_target_register_value() {
        let rv = TraceTargetRegisterValue::new("RAX", vec![0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 64);
        assert_eq!(rv.as_u64_le(), Some(0x42));
    }

    #[test]
    fn test_target_event() {
        let event = TraceTargetEvent::new(
            KeyPath::parse("Events[0]"),
            "breakpoint-hit",
        )
        .with_thread_id(1)
        .with_process_id(100)
        .with_detail("reason", "hardware breakpoint");
        assert_eq!(event.event_type, "breakpoint-hit");
        assert_eq!(event.thread_id, Some(1));
        assert_eq!(event.details.get("reason").unwrap(), "hardware breakpoint");
    }

    #[test]
    fn test_section_serde() {
        let section = TraceTargetSection::new(
            KeyPath::parse("S[0]"), ".text", 0x1000, 0x2000, 0,
        );
        let json = serde_json::to_string(&section).unwrap();
        let back: TraceTargetSection = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, ".text");
    }

    #[test]
    fn test_region_serde() {
        let region = TraceRegion::new(
            KeyPath::parse("R[0]"), "heap", 0, 0xfff, true, true, false,
        );
        let json = serde_json::to_string(&region).unwrap();
        let back: TraceRegion = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "heap");
    }
}
