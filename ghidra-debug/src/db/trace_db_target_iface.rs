//! Database-level target object interface implementations.
//!
//! Ported from Ghidra's `ghidra.trace.database.target.iface` package in
//! Framework-TraceModeling. Provides concrete implementations of the
//! target object interfaces that bind to the database layer.

use serde::{Deserialize, Serialize};

use crate::model::execution_state::TraceExecutionState;

// ---------------------------------------------------------------------------
// DB Object Activatable
// ---------------------------------------------------------------------------

/// Database implementation of the Activatable interface.
///
/// Ported from Ghidra's `DBTraceObjectActivatable`. Tracks whether a
/// target object (e.g., thread, process) is currently active/resumed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbObjectActivatable {
    /// The object key in the database.
    pub object_key: i64,
    /// Whether the object is currently active (resumed).
    pub active: bool,
    /// The snap at which the state was last changed.
    pub last_changed_snap: i64,
}

impl DbObjectActivatable {
    /// Create a new activatable object state.
    pub fn new(object_key: i64) -> Self {
        Self {
            object_key,
            active: false,
            last_changed_snap: 0,
        }
    }

    /// Activate (resume) the object.
    pub fn activate(&mut self, snap: i64) {
        self.active = true;
        self.last_changed_snap = snap;
    }

    /// Deactivate (suspend) the object.
    pub fn deactivate(&mut self, snap: i64) {
        self.active = false;
        self.last_changed_snap = snap;
    }
}

// ---------------------------------------------------------------------------
// DB Object Aggregate
// ---------------------------------------------------------------------------

/// Database implementation of the Aggregate interface.
///
/// Ported from Ghidra's `DBTraceObjectAggregate`. Groups related
/// target objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbObjectAggregate {
    /// The object key.
    pub object_key: i64,
    /// The aggregate name.
    pub name: String,
    /// Child object keys.
    pub children: Vec<i64>,
}

impl DbObjectAggregate {
    /// Create a new aggregate.
    pub fn new(object_key: i64, name: impl Into<String>) -> Self {
        Self {
            object_key,
            name: name.into(),
            children: Vec::new(),
        }
    }

    /// Add a child to the aggregate.
    pub fn add_child(&mut self, child_key: i64) {
        if !self.children.contains(&child_key) {
            self.children.push(child_key);
        }
    }

    /// Remove a child from the aggregate.
    pub fn remove_child(&mut self, child_key: i64) {
        self.children.retain(|&k| k != child_key);
    }
}

// ---------------------------------------------------------------------------
// DB Object Environment
// ---------------------------------------------------------------------------

/// Database implementation of the Environment interface.
///
/// Ported from Ghidra's `DBTraceObjectEnvironment`. Provides
/// information about the target environment (architecture, OS, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbObjectEnvironment {
    /// The object key.
    pub object_key: i64,
    /// The architecture string (e.g., "x86_64", "ARM").
    pub architecture: Option<String>,
    /// The OS string (e.g., "windows", "linux").
    pub os: Option<String>,
    /// The debugger name (e.g., "gdb", "lldb").
    pub debugger: Option<String>,
    /// The endianness (e.g., "little", "big").
    pub endian: Option<String>,
}

impl DbObjectEnvironment {
    /// Create a new environment object.
    pub fn new(object_key: i64) -> Self {
        Self {
            object_key,
            architecture: None,
            os: None,
            debugger: None,
            endian: None,
        }
    }

    /// Set the architecture.
    pub fn set_architecture(&mut self, arch: impl Into<String>) {
        self.architecture = Some(arch.into());
    }

    /// Set the OS.
    pub fn set_os(&mut self, os: impl Into<String>) {
        self.os = Some(os.into());
    }
}

// ---------------------------------------------------------------------------
// DB Object Execution Stateful
// ---------------------------------------------------------------------------

/// Database implementation of the ExecutionStateful interface.
///
/// Ported from Ghidra's execution state handling in the target object
/// model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbObjectExecutionStateful {
    /// The object key.
    pub object_key: i64,
    /// The current execution state.
    pub state: TraceExecutionState,
    /// The snap at which the state was last changed.
    pub last_changed_snap: i64,
}

impl DbObjectExecutionStateful {
    /// Create a new execution stateful object.
    pub fn new(object_key: i64) -> Self {
        Self {
            object_key,
            state: TraceExecutionState::Stopped,
            last_changed_snap: 0,
        }
    }

    /// Update the execution state.
    pub fn set_state(&mut self, state: TraceExecutionState, snap: i64) {
        self.state = state;
        self.last_changed_snap = snap;
    }
}

// ---------------------------------------------------------------------------
// DB Object Focus Scope
// ---------------------------------------------------------------------------

/// Database implementation of the FocusScope interface.
///
/// Ported from Ghidra's `TraceFocusScope` handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbObjectFocusScope {
    /// The object key.
    pub object_key: i64,
    /// The focused object key (if any).
    pub focused_object_key: Option<i64>,
}

impl DbObjectFocusScope {
    /// Create a new focus scope.
    pub fn new(object_key: i64) -> Self {
        Self {
            object_key,
            focused_object_key: None,
        }
    }

    /// Set the focused object.
    pub fn set_focus(&mut self, target_key: Option<i64>) {
        self.focused_object_key = target_key;
    }
}

// ---------------------------------------------------------------------------
// DB Object Togglable
// ---------------------------------------------------------------------------

/// Database implementation of the Togglable interface.
///
/// Ported from Ghidra's `TraceTogglable` handling. Represents objects
/// that can be toggled on/off (e.g., breakpoints).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbObjectTogglable {
    /// The object key.
    pub object_key: i64,
    /// Whether the object is toggled on.
    pub toggled: bool,
    /// The snap at which the toggle state was last changed.
    pub last_changed_snap: i64,
}

impl DbObjectTogglable {
    /// Create a new togglable object.
    pub fn new(object_key: i64) -> Self {
        Self {
            object_key,
            toggled: false,
            last_changed_snap: 0,
        }
    }

    /// Toggle the state.
    pub fn toggle(&mut self, snap: i64) {
        self.toggled = !self.toggled;
        self.last_changed_snap = snap;
    }

    /// Set the toggle state explicitly.
    pub fn set_toggled(&mut self, toggled: bool, snap: i64) {
        self.toggled = toggled;
        self.last_changed_snap = snap;
    }
}

// ---------------------------------------------------------------------------
// DB Target Interface Registry
// ---------------------------------------------------------------------------

/// Registry of database-level target object interface implementations.
///
/// Ported from Ghidra's `BuiltinTraceObjectInterfaceFactory`. Maps
/// interface names to their database implementation constructors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DbTargetInterfaceRegistry {
    /// Registered activatable objects.
    pub activatables: Vec<DbObjectActivatable>,
    /// Registered aggregates.
    pub aggregates: Vec<DbObjectAggregate>,
    /// Registered environments.
    pub environments: Vec<DbObjectEnvironment>,
    /// Registered execution stateful objects.
    pub execution_stateful: Vec<DbObjectExecutionStateful>,
    /// Registered focus scopes.
    pub focus_scopes: Vec<DbObjectFocusScope>,
    /// Registered togglable objects.
    pub togglables: Vec<DbObjectTogglable>,
}

impl DbTargetInterfaceRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the total number of registered interface implementations.
    pub fn total_count(&self) -> usize {
        self.activatables.len()
            + self.aggregates.len()
            + self.environments.len()
            + self.execution_stateful.len()
            + self.focus_scopes.len()
            + self.togglables.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_object_activatable() {
        let mut obj = DbObjectActivatable::new(1);
        assert!(!obj.active);
        obj.activate(10);
        assert!(obj.active);
        assert_eq!(obj.last_changed_snap, 10);
        obj.deactivate(20);
        assert!(!obj.active);
    }

    #[test]
    fn test_db_object_aggregate() {
        let mut agg = DbObjectAggregate::new(1, "Processes");
        agg.add_child(10);
        agg.add_child(20);
        assert_eq!(agg.children.len(), 2);
        agg.add_child(10); // duplicate
        assert_eq!(agg.children.len(), 2);
        agg.remove_child(10);
        assert_eq!(agg.children.len(), 1);
    }

    #[test]
    fn test_db_object_environment() {
        let mut env = DbObjectEnvironment::new(1);
        assert!(env.architecture.is_none());
        env.set_architecture("x86_64");
        env.set_os("linux");
        assert_eq!(env.architecture.as_deref(), Some("x86_64"));
        assert_eq!(env.os.as_deref(), Some("linux"));
    }

    #[test]
    fn test_db_object_execution_stateful() {
        let mut obj = DbObjectExecutionStateful::new(1);
        assert_eq!(obj.state, TraceExecutionState::Stopped);
        obj.set_state(TraceExecutionState::Running, 10);
        assert_eq!(obj.state, TraceExecutionState::Running);
    }

    #[test]
    fn test_db_object_focus_scope() {
        let mut scope = DbObjectFocusScope::new(1);
        assert!(scope.focused_object_key.is_none());
        scope.set_focus(Some(42));
        assert_eq!(scope.focused_object_key, Some(42));
        scope.set_focus(None);
        assert!(scope.focused_object_key.is_none());
    }

    #[test]
    fn test_db_object_togglable() {
        let mut obj = DbObjectTogglable::new(1);
        assert!(!obj.toggled);
        obj.toggle(10);
        assert!(obj.toggled);
        obj.toggle(20);
        assert!(!obj.toggled);
        obj.set_toggled(true, 30);
        assert!(obj.toggled);
    }

    #[test]
    fn test_db_target_interface_registry() {
        let mut reg = DbTargetInterfaceRegistry::new();
        assert_eq!(reg.total_count(), 0);
        reg.activatables.push(DbObjectActivatable::new(1));
        reg.environments.push(DbObjectEnvironment::new(2));
        assert_eq!(reg.total_count(), 2);
    }
}
