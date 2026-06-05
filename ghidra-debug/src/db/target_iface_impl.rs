//! Database implementations of trace object interface types.
//!
//! Ported from Ghidra's Framework-TraceModeling `ghidra.trace.database.target.iface`:
//! - `DBTraceObjectActivatable`
//! - `DBTraceObjectAggregate`
//! - `DBTraceObjectEnvironment`
//! - `DBTraceObjectEventScope`
//! - `DBTraceObjectExecutionStateful`
//! - `DBTraceObjectFocusScope`
//! - `DBTraceObjectMethod`
//! - `DBTraceObjectTogglable`
//!
//! These provide database-backed implementations of the target object
//! interfaces (TraceActivatable, TraceAggregate, TraceEnvironment, etc.).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::model::TraceExecutionState;

/// Whether a target object can be activated (resumed, continued, etc.).
///
/// Ported from Ghidra's `TraceActivatable` interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivatableState {
    /// The object is active (running).
    Active,
    /// The object is inactive (stopped).
    Inactive,
    /// The state is unknown.
    Unknown,
}

impl Default for ActivatableState {
    fn default() -> Self {
        ActivatableState::Inactive
    }
}

impl ActivatableState {
    /// Whether the object is active.
    pub fn is_active(&self) -> bool {
        matches!(self, ActivatableState::Active)
    }

    /// Whether the object is inactive.
    pub fn is_inactive(&self) -> bool {
        matches!(self, ActivatableState::Inactive)
    }
}

/// Database implementation of `TraceActivatable`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceObjectActivatable {
    /// The object key in the trace database.
    pub object_key: i64,
    /// The activation state.
    pub state: ActivatableState,
}

impl DBTraceObjectActivatable {
    /// Create a new activatable interface implementation.
    pub fn new(object_key: i64) -> Self {
        Self {
            object_key,
            state: ActivatableState::default(),
        }
    }

    /// Activate the object.
    pub fn activate(&mut self) {
        self.state = ActivatableState::Active;
    }

    /// Deactivate the object.
    pub fn deactivate(&mut self) {
        self.state = ActivatableState::Inactive;
    }

    /// Toggle activation state.
    pub fn toggle(&mut self) {
        match self.state {
            ActivatableState::Active => self.state = ActivatableState::Inactive,
            _ => self.state = ActivatableState::Active,
        }
    }
}

/// Database implementation of `TraceAggregate`.
///
/// An aggregate object contains named child entries (attributes or elements).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceObjectAggregate {
    /// The object key in the trace database.
    pub object_key: i64,
    /// Named attributes (key -> child object key).
    pub attributes: BTreeMap<String, i64>,
    /// Ordered elements (index -> child object key).
    pub elements: Vec<i64>,
}

impl DBTraceObjectAggregate {
    /// Create a new aggregate interface implementation.
    pub fn new(object_key: i64) -> Self {
        Self {
            object_key,
            attributes: BTreeMap::new(),
            elements: Vec::new(),
        }
    }

    /// Add a named attribute.
    pub fn set_attribute(&mut self, name: impl Into<String>, child_key: i64) {
        self.attributes.insert(name.into(), child_key);
    }

    /// Get an attribute by name.
    pub fn get_attribute(&self, name: &str) -> Option<i64> {
        self.attributes.get(name).copied()
    }

    /// Remove an attribute by name.
    pub fn remove_attribute(&mut self, name: &str) -> Option<i64> {
        self.attributes.remove(name)
    }

    /// Add an element.
    pub fn add_element(&mut self, child_key: i64) -> usize {
        let index = self.elements.len();
        self.elements.push(child_key);
        index
    }

    /// Get an element by index.
    pub fn get_element(&self, index: usize) -> Option<i64> {
        self.elements.get(index).copied()
    }

    /// Get the number of elements.
    pub fn element_count(&self) -> usize {
        self.elements.len()
    }

    /// Get the number of attributes.
    pub fn attribute_count(&self) -> usize {
        self.attributes.len()
    }

    /// Get all attribute names.
    pub fn attribute_names(&self) -> Vec<&str> {
        self.attributes.keys().map(|s| s.as_str()).collect()
    }

    /// Get all child keys (attributes and elements).
    pub fn all_children(&self) -> BTreeSet<i64> {
        let mut keys = BTreeSet::new();
        for &k in self.attributes.values() {
            keys.insert(k);
        }
        for &k in &self.elements {
            keys.insert(k);
        }
        keys
    }
}

/// Database implementation of `TraceEnvironment`.
///
/// Represents the debug target's environment (OS, architecture, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceObjectEnvironment {
    /// The object key in the trace database.
    pub object_key: i64,
    /// Environment variables (key -> value).
    pub env_vars: BTreeMap<String, String>,
    /// The operating system name.
    pub os: Option<String>,
    /// The architecture name.
    pub architecture: Option<String>,
    /// The debugger type (e.g., "gdb", "dbgeng").
    pub debugger: Option<String>,
}

impl DBTraceObjectEnvironment {
    /// Create a new environment interface implementation.
    pub fn new(object_key: i64) -> Self {
        Self {
            object_key,
            env_vars: BTreeMap::new(),
            os: None,
            architecture: None,
            debugger: None,
        }
    }

    /// Set an environment variable.
    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.env_vars.insert(key.into(), value.into());
    }

    /// Get an environment variable.
    pub fn get_env(&self, key: &str) -> Option<&str> {
        self.env_vars.get(key).map(|s| s.as_str())
    }

    /// Remove an environment variable.
    pub fn remove_env(&mut self, key: &str) -> Option<String> {
        self.env_vars.remove(key)
    }

    /// Get all environment variable names.
    pub fn env_keys(&self) -> Vec<&str> {
        self.env_vars.keys().map(|s| s.as_str()).collect()
    }
}

/// Database implementation of `TraceEventScope`.
///
/// Represents a scope for debug events (exceptions, signals, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceObjectEventScope {
    /// The object key in the trace database.
    pub object_key: i64,
    /// The parent scope key, if any.
    pub parent_key: Option<i64>,
    /// The event type (e.g., "Exception", "Signal").
    pub event_type: String,
    /// Event-specific parameters.
    pub parameters: BTreeMap<String, String>,
}

impl DBTraceObjectEventScope {
    /// Create a new event scope implementation.
    pub fn new(object_key: i64, event_type: impl Into<String>) -> Self {
        Self {
            object_key,
            parent_key: None,
            event_type: event_type.into(),
            parameters: BTreeMap::new(),
        }
    }

    /// Set a parameter.
    pub fn set_parameter(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.parameters.insert(key.into(), value.into());
    }

    /// Get a parameter value.
    pub fn get_parameter(&self, key: &str) -> Option<&str> {
        self.parameters.get(key).map(|s| s.as_str())
    }

    /// Set the parent scope.
    pub fn set_parent(&mut self, parent_key: Option<i64>) {
        self.parent_key = parent_key;
    }

    /// Whether this is the root scope.
    pub fn is_root(&self) -> bool {
        self.parent_key.is_none()
    }
}

/// Database implementation of `TraceExecutionStateful`.
///
/// Tracks the execution state of a target (running, stopped, terminated, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceObjectExecutionStateful {
    /// The object key in the trace database.
    pub object_key: i64,
    /// The current execution state.
    pub state: TraceExecutionState,
    /// The reason for the current state (e.g., "breakpoint hit").
    pub reason: Option<String>,
    /// The exit code (if terminated).
    pub exit_code: Option<i32>,
}

impl DBTraceObjectExecutionStateful {
    /// Create a new execution stateful implementation.
    pub fn new(object_key: i64) -> Self {
        Self {
            object_key,
            state: TraceExecutionState::Stopped,
            reason: None,
            exit_code: None,
        }
    }

    /// Set the execution state to running.
    pub fn set_running(&mut self, reason: Option<String>) {
        self.state = TraceExecutionState::Running;
        self.reason = reason;
    }

    /// Set the execution state to stopped.
    pub fn set_stopped(&mut self, reason: Option<String>) {
        self.state = TraceExecutionState::Stopped;
        self.reason = reason;
    }

    /// Set the execution state to terminated.
    pub fn set_terminated(&mut self, exit_code: i32) {
        self.state = TraceExecutionState::Terminated;
        self.exit_code = Some(exit_code);
    }

    /// Whether the target is running.
    pub fn is_running(&self) -> bool {
        self.state == TraceExecutionState::Running
    }

    /// Whether the target is stopped.
    pub fn is_stopped(&self) -> bool {
        self.state == TraceExecutionState::Stopped
    }

    /// Whether the target has terminated.
    pub fn is_terminated(&self) -> bool {
        self.state == TraceExecutionState::Terminated
    }
}

/// Database implementation of `TraceFocusScope`.
///
/// Represents a focus scope for debugging (e.g., which thread/process is focused).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceObjectFocusScope {
    /// The object key in the trace database.
    pub object_key: i64,
    /// The currently focused object key.
    pub focused_key: Option<i64>,
    /// The focus path (breadcrumb trail).
    pub focus_path: Vec<i64>,
}

impl DBTraceObjectFocusScope {
    /// Create a new focus scope implementation.
    pub fn new(object_key: i64) -> Self {
        Self {
            object_key,
            focused_key: None,
            focus_path: Vec::new(),
        }
    }

    /// Set the focused object.
    pub fn set_focus(&mut self, target_key: i64) {
        self.focused_key = Some(target_key);
        self.focus_path.push(target_key);
    }

    /// Clear the focus.
    pub fn clear_focus(&mut self) {
        self.focused_key = None;
    }

    /// Get the currently focused object.
    pub fn get_focused(&self) -> Option<i64> {
        self.focused_key
    }

    /// Whether an object is focused.
    pub fn is_focused(&self, key: i64) -> bool {
        self.focused_key == Some(key)
    }
}

/// Database implementation of `TraceMethod`.
///
/// Represents a callable method on a target object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceObjectMethod {
    /// The object key in the trace database.
    pub object_key: i64,
    /// The method name.
    pub name: String,
    /// Parameter names and types.
    pub parameters: Vec<(String, String)>,
    /// Return type (if any).
    pub return_type: Option<String>,
    /// Whether this method is currently available.
    pub available: bool,
}

impl DBTraceObjectMethod {
    /// Create a new method implementation.
    pub fn new(object_key: i64, name: impl Into<String>) -> Self {
        Self {
            object_key,
            name: name.into(),
            parameters: Vec::new(),
            return_type: None,
            available: true,
        }
    }

    /// Add a parameter.
    pub fn add_parameter(&mut self, name: impl Into<String>, param_type: impl Into<String>) {
        self.parameters.push((name.into(), param_type.into()));
    }

    /// Set the return type.
    pub fn set_return_type(&mut self, return_type: impl Into<String>) {
        self.return_type = Some(return_type.into());
    }

    /// Get the number of parameters.
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }

    /// Check if the method has a return type.
    pub fn has_return_type(&self) -> bool {
        self.return_type.is_some()
    }
}

/// Database implementation of `TraceTogglable`.
///
/// Represents an object that can be toggled on/off (e.g., a breakpoint enable/disable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceObjectTogglable {
    /// The object key in the trace database.
    pub object_key: i64,
    /// Whether the object is toggled on.
    pub enabled: bool,
}

impl DBTraceObjectTogglable {
    /// Create a new togglable implementation.
    pub fn new(object_key: i64, enabled: bool) -> Self {
        Self {
            object_key,
            enabled,
        }
    }

    /// Toggle the state.
    pub fn toggle(&mut self) {
        self.enabled = !self.enabled;
    }

    /// Set enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether the object is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activatable() {
        let mut act = DBTraceObjectActivatable::new(42);
        assert!(!act.state.is_active());
        assert!(act.state.is_inactive());

        act.activate();
        assert!(act.state.is_active());

        act.toggle();
        assert!(act.state.is_inactive());

        act.toggle();
        assert!(act.state.is_active());
    }

    #[test]
    fn test_aggregate() {
        let mut agg = DBTraceObjectAggregate::new(1);
        agg.set_attribute("Memory", 10);
        agg.set_attribute("Threads", 11);

        assert_eq!(agg.get_attribute("Memory"), Some(10));
        assert_eq!(agg.get_attribute("Threads"), Some(11));
        assert_eq!(agg.attribute_count(), 2);

        let idx = agg.add_element(20);
        assert_eq!(idx, 0);
        let idx = agg.add_element(21);
        assert_eq!(idx, 1);

        assert_eq!(agg.element_count(), 2);
        assert_eq!(agg.get_element(0), Some(20));

        let children = agg.all_children();
        assert_eq!(children.len(), 4); // 2 attrs + 2 elements

        agg.remove_attribute("Memory");
        assert_eq!(agg.attribute_count(), 1);
    }

    #[test]
    fn test_environment() {
        let mut env = DBTraceObjectEnvironment::new(5);
        env.os = Some("Linux".into());
        env.architecture = Some("x86_64".into());
        env.set_env("PATH", "/usr/bin:/bin");
        env.set_env("HOME", "/home/user");

        assert_eq!(env.get_env("PATH"), Some("/usr/bin:/bin"));
        assert_eq!(env.get_env("HOME"), Some("/home/user"));
        assert_eq!(env.env_keys().len(), 2);

        env.remove_env("HOME");
        assert!(env.get_env("HOME").is_none());
    }

    #[test]
    fn test_event_scope() {
        let mut scope = DBTraceObjectEventScope::new(10, "Exception");
        assert!(scope.is_root());

        scope.set_parent(Some(5));
        assert!(!scope.is_root());

        scope.set_parameter("code", "0xC0000005");
        assert_eq!(scope.get_parameter("code"), Some("0xC0000005"));
    }

    #[test]
    fn test_execution_stateful() {
        let mut exec = DBTraceObjectExecutionStateful::new(20);
        assert!(exec.is_stopped());

        exec.set_running(Some("continue".into()));
        assert!(exec.is_running());
        assert_eq!(exec.reason, Some("continue".into()));

        exec.set_stopped(Some("breakpoint".into()));
        assert!(exec.is_stopped());

        exec.set_terminated(0);
        assert!(exec.is_terminated());
        assert_eq!(exec.exit_code, Some(0));
    }

    #[test]
    fn test_focus_scope() {
        let mut focus = DBTraceObjectFocusScope::new(30);
        assert!(focus.get_focused().is_none());

        focus.set_focus(100);
        assert!(focus.is_focused(100));
        assert!(!focus.is_focused(200));

        focus.set_focus(200);
        assert_eq!(focus.focus_path.len(), 2);

        focus.clear_focus();
        assert!(focus.get_focused().is_none());
    }

    #[test]
    fn test_method() {
        let mut method = DBTraceObjectMethod::new(40, "read_memory");
        method.add_parameter("address", "u64");
        method.add_parameter("length", "usize");
        method.set_return_type("Vec<u8>");

        assert_eq!(method.name, "read_memory");
        assert_eq!(method.parameter_count(), 2);
        assert!(method.has_return_type());
        assert!(method.available);
    }

    #[test]
    fn test_togglable() {
        let mut tog = DBTraceObjectTogglable::new(50, false);
        assert!(!tog.is_enabled());

        tog.toggle();
        assert!(tog.is_enabled());

        tog.set_enabled(false);
        assert!(!tog.is_enabled());
    }
}
