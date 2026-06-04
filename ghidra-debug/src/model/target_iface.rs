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
}
