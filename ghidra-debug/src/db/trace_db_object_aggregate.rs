//! DBTraceObjectAggregate, DBTraceObjectEnvironment, DBTraceObjectEventScope,
//! DBTraceObjectMethod, DBTraceObjectTogglable, DBTraceObjectActivatable.
//!
//! Ported from Ghidra's `ghidra.trace.database.target.iface` package.
//! These are the database-backed implementations of the target object
//! interfaces (TraceAggregate, TraceEnvironment, TraceEventScope,
//! TraceMethod, TraceTogglable, TraceActivatable).

use serde::{Deserialize, Serialize};


/// Database-backed implementation of the aggregate interface.
///
/// Corresponds to Java's `DBTraceObjectAggregate`. An aggregate object
/// is one that contains multiple sub-objects (e.g., a process contains
/// threads, a thread contains frames).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbObjectAggregate {
    /// The object identifier.
    pub object_id: u64,
    /// The child object IDs.
    pub children: Vec<u64>,
}

impl DbObjectAggregate {
    /// Create a new aggregate binding.
    pub fn new(object_id: u64) -> Self {
        Self {
            object_id,
            children: Vec::new(),
        }
    }

    /// Add a child object.
    pub fn add_child(&mut self, child_id: u64) {
        if !self.children.contains(&child_id) {
            self.children.push(child_id);
        }
    }

    /// Remove a child object.
    pub fn remove_child(&mut self, child_id: u64) {
        self.children.retain(|&id| id != child_id);
    }

    /// Get the number of children.
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// Check if this aggregate has children.
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    /// Get the children list.
    pub fn get_children(&self) -> &[u64] {
        &self.children
    }
}

/// Database-backed implementation of the environment interface.
///
/// Corresponds to Java's `DBTraceObjectEnvironment`. An environment
/// object represents the execution environment of a process (e.g.,
/// OS, architecture, bitness).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbObjectEnvironment {
    /// The object identifier.
    pub object_id: u64,
    /// The environment description (e.g., "Windows/x86_64").
    pub description: String,
    /// The language ID (e.g., "x86:LE:64:default").
    pub language_id: Option<String>,
    /// The compiler spec ID.
    pub compiler_spec_id: Option<String>,
}

impl DbObjectEnvironment {
    /// Create a new environment binding.
    pub fn new(object_id: u64, description: impl Into<String>) -> Self {
        Self {
            object_id,
            description: description.into(),
            language_id: None,
            compiler_spec_id: None,
        }
    }

    /// Set the language ID.
    pub fn with_language_id(mut self, id: impl Into<String>) -> Self {
        self.language_id = Some(id.into());
        self
    }

    /// Set the compiler spec ID.
    pub fn with_compiler_spec_id(mut self, id: impl Into<String>) -> Self {
        self.compiler_spec_id = Some(id.into());
        self
    }
}

/// Database-backed implementation of the event scope interface.
///
/// Corresponds to Java's `DBTraceObjectEventScope`. An event scope
/// defines the context for events (e.g., breakpoints, watchpoints)
/// in the target tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbObjectEventScope {
    /// The object identifier.
    pub object_id: u64,
    /// The scope level (0 = global, 1 = process, 2 = thread).
    pub level: u32,
    /// The parent scope ID, if any.
    pub parent_scope_id: Option<u64>,
}

impl DbObjectEventScope {
    /// Create a new event scope binding.
    pub fn new(object_id: u64, level: u32) -> Self {
        Self {
            object_id,
            level,
            parent_scope_id: None,
        }
    }

    /// Set the parent scope.
    pub fn with_parent_scope(mut self, parent_id: u64) -> Self {
        self.parent_scope_id = Some(parent_id);
        self
    }

    /// Check if this is a global scope.
    pub fn is_global(&self) -> bool {
        self.level == 0
    }

    /// Check if this is a process scope.
    pub fn is_process(&self) -> bool {
        self.level == 1
    }

    /// Check if this is a thread scope.
    pub fn is_thread(&self) -> bool {
        self.level == 2
    }
}

/// Database-backed implementation of the method interface.
///
/// Corresponds to Java's `DBTraceObjectMethod`. A method object
/// represents a callable method in the target program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbObjectMethod {
    /// The object identifier.
    pub object_id: u64,
    /// The method name.
    pub name: String,
    /// The entry point address.
    pub entry_address: u64,
    /// The return type description.
    pub return_type: Option<String>,
    /// Parameter count.
    pub parameter_count: usize,
}

impl DbObjectMethod {
    /// Create a new method binding.
    pub fn new(object_id: u64, name: impl Into<String>, entry_address: u64) -> Self {
        Self {
            object_id,
            name: name.into(),
            entry_address,
            return_type: None,
            parameter_count: 0,
        }
    }

    /// Set the return type.
    pub fn with_return_type(mut self, return_type: impl Into<String>) -> Self {
        self.return_type = Some(return_type.into());
        self
    }

    /// Set the parameter count.
    pub fn with_parameter_count(mut self, count: usize) -> Self {
        self.parameter_count = count;
        self
    }
}

/// Database-backed implementation of the togglable interface.
///
/// Corresponds to Java's `DBTraceObjectTogglable`. A togglable object
/// can be enabled or disabled (e.g., breakpoints).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbObjectTogglable {
    /// The object identifier.
    pub object_id: u64,
    /// Whether this object is currently enabled.
    pub enabled: bool,
}

impl DbObjectTogglable {
    /// Create a new togglable binding (default: enabled).
    pub fn new(object_id: u64) -> Self {
        Self {
            object_id,
            enabled: true,
        }
    }

    /// Create in a specific state.
    pub fn with_state(object_id: u64, enabled: bool) -> Self {
        Self { object_id, enabled }
    }

    /// Toggle the enabled state.
    pub fn toggle(&mut self) {
        self.enabled = !self.enabled;
    }

    /// Check if enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

/// Database-backed implementation of the activatable interface.
///
/// Corresponds to Java's `DBTraceObjectActivatable`. An activatable
/// object can be selected as the current target for debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbObjectActivatable {
    /// The object identifier.
    pub object_id: u64,
    /// Whether this object is currently active.
    pub active: bool,
}

impl DbObjectActivatable {
    /// Create a new activatable binding (default: inactive).
    pub fn new(object_id: u64) -> Self {
        Self {
            object_id,
            active: false,
        }
    }

    /// Activate this object.
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Deactivate this object.
    pub fn deactivate(&mut self) {
        self.active = false;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregate() {
        let mut agg = DbObjectAggregate::new(1);
        assert!(!agg.has_children());
        agg.add_child(2);
        agg.add_child(3);
        assert_eq!(agg.child_count(), 2);
        assert!(agg.has_children());
        agg.remove_child(2);
        assert_eq!(agg.child_count(), 1);
    }

    #[test]
    fn test_aggregate_no_duplicate_children() {
        let mut agg = DbObjectAggregate::new(1);
        agg.add_child(2);
        agg.add_child(2);
        assert_eq!(agg.child_count(), 1);
    }

    #[test]
    fn test_environment() {
        let env = DbObjectEnvironment::new(1, "Linux/x86_64")
            .with_language_id("x86:LE:64:default")
            .with_compiler_spec_id("default");
        assert_eq!(env.description, "Linux/x86_64");
        assert!(env.language_id.is_some());
        assert!(env.compiler_spec_id.is_some());
    }

    #[test]
    fn test_event_scope() {
        let scope = DbObjectEventScope::new(1, 0).with_parent_scope(0);
        assert!(scope.is_global());
        assert!(!scope.is_process());
        assert!(!scope.is_thread());

        let proc_scope = DbObjectEventScope::new(2, 1);
        assert!(proc_scope.is_process());

        let thread_scope = DbObjectEventScope::new(3, 2);
        assert!(thread_scope.is_thread());
    }

    #[test]
    fn test_method() {
        let method = DbObjectMethod::new(1, "main", 0x400000)
            .with_return_type("int")
            .with_parameter_count(2);
        assert_eq!(method.name, "main");
        assert_eq!(method.entry_address, 0x400000);
        assert_eq!(method.parameter_count, 2);
    }

    #[test]
    fn test_togglable() {
        let mut tog = DbObjectTogglable::new(1);
        assert!(tog.is_enabled());
        tog.toggle();
        assert!(!tog.is_enabled());
        tog.set_enabled(true);
        assert!(tog.is_enabled());
    }

    #[test]
    fn test_activatable() {
        let mut act = DbObjectActivatable::new(1);
        assert!(!act.is_active());
        act.activate();
        assert!(act.is_active());
        act.deactivate();
        assert!(!act.is_active());
    }

    #[test]
    fn test_togglable_with_state() {
        let tog = DbObjectTogglable::with_state(1, false);
        assert!(!tog.is_enabled());
    }
}
