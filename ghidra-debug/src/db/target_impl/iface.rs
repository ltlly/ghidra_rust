//! Database-backed implementations of target object interfaces.
//!
//! Ported from Ghidra's `ghidra.trace.database.target.iface` package.
//!
//! Each struct wraps a reference to a `DbTraceObject` and implements both the
//! model-level interface (e.g. `TraceActivatable`) and the database-level
//! `DbTraceObjectInterface` trait for event translation.
//!
//! The eight interface implementations correspond to:
//! - `DbTraceObjectActivatable` -- objects that can be activated/focused
//! - `DbTraceObjectAggregate` -- objects that represent aggregate containers
//! - `DbTraceObjectEnvironment` -- environment info (OS, arch, debugger, endian)
//! - `DbTraceObjectEventScope` -- the root event-emitting scope
//! - `DbTraceObjectExecutionStateful` -- objects with run/stop/terminated state
//! - `DbTraceObjectFocusScope` -- objects that track the current focus
//! - `DbTraceObjectMethod` -- callable method objects
//! - `DbTraceObjectTogglable` -- objects that can be enabled/disabled

use serde::{Deserialize, Serialize};

use crate::model::target_iface::{
    ExecutionState, TraceActivatable, TraceAggregate, TraceEnvironment,
    TraceExecutionStateful, TraceFocusScope, TraceMethod, TraceTogglable,
};
use crate::target::key_path::KeyPath;

/// The trait that all database-level object interface implementations satisfy.
///
/// In Ghidra's Java code this is `DBTraceObjectInterface`, which requires a
/// `translateEvent` method for converting change records. In Rust we model
/// this as a simple trait with a path accessor and optional event translation.
pub trait DbTraceObjectInterface: std::fmt::Debug {
    /// Get the path to this object in the target tree.
    fn path(&self) -> &KeyPath;

    /// Translate a change record, returning `None` if the event is not
    /// relevant to this interface (the Java version returns null).
    fn translate_event(&self, _event: &TraceEventRecord) -> Option<&TraceEventRecord> {
        None
    }
}

/// A placeholder for the Java `TraceChangeRecord` used in event translation.
///
/// In the full Ghidra implementation, this would carry the actual change
/// details. For the ported module it serves as a type marker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEventRecord {
    /// The kind of change that occurred.
    pub kind: String,
    /// The object path affected.
    pub path: KeyPath,
}

/// Database-backed implementation of `TraceActivatable`.
///
/// Objects that can be activated (e.g., threads, processes) are wrapped in
/// this type when accessed through the trace database layer.
#[derive(Debug, Clone)]
pub struct DbTraceObjectActivatable {
    path: KeyPath,
    active: bool,
}

impl DbTraceObjectActivatable {
    /// Create a new activatable DB object wrapper.
    pub fn new(path: KeyPath) -> Self {
        Self { path, active: false }
    }

    /// Create from an existing `TraceActivatable` model object.
    pub fn from_model(model: &TraceActivatable) -> Self {
        Self {
            path: model.path.clone(),
            active: model.active,
        }
    }

    /// Whether this object is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Set the active state.
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }
}

impl DbTraceObjectInterface for DbTraceObjectActivatable {
    fn path(&self) -> &KeyPath {
        &self.path
    }
}

/// Database-backed implementation of `TraceAggregate`.
///
/// Aggregate objects (e.g., process containers, module containers) are
/// wrapped in this type at the database layer.
#[derive(Debug, Clone)]
pub struct DbTraceObjectAggregate {
    path: KeyPath,
    element_count: usize,
}

impl DbTraceObjectAggregate {
    /// Create a new aggregate DB object wrapper.
    pub fn new(path: KeyPath) -> Self {
        Self {
            path,
            element_count: 0,
        }
    }

    /// Create from an existing `TraceAggregate` model object.
    pub fn from_model(model: &TraceAggregate) -> Self {
        Self {
            path: model.path.clone(),
            element_count: model.element_count,
        }
    }

    /// Get the number of contained elements.
    pub fn element_count(&self) -> usize {
        self.element_count
    }

    /// Update the element count.
    pub fn set_element_count(&mut self, count: usize) {
        self.element_count = count;
    }
}

impl DbTraceObjectInterface for DbTraceObjectAggregate {
    fn path(&self) -> &KeyPath {
        &self.path
    }
}

/// Database-backed implementation of `TraceEnvironment`.
///
/// Environment objects describe the debugging target's OS, architecture,
/// debugger, and endianness.
#[derive(Debug, Clone)]
pub struct DbTraceObjectEnvironment {
    path: KeyPath,
    os: String,
    arch: String,
    debugger_name: Option<String>,
    endian: Option<String>,
}

impl DbTraceObjectEnvironment {
    /// Create a new environment DB object wrapper.
    pub fn new(path: KeyPath, os: impl Into<String>, arch: impl Into<String>) -> Self {
        Self {
            path,
            os: os.into(),
            arch: arch.into(),
            debugger_name: None,
            endian: None,
        }
    }

    /// Create from an existing `TraceEnvironment` model object.
    pub fn from_model(model: &TraceEnvironment) -> Self {
        Self {
            path: model.path.clone(),
            os: model.os.clone(),
            arch: model.arch.clone(),
            debugger_name: None,
            endian: None,
        }
    }

    /// Get the operating system name.
    pub fn os(&self) -> &str {
        &self.os
    }

    /// Get the architecture name.
    pub fn arch(&self) -> &str {
        &self.arch
    }

    /// Get the debugger name, if set.
    pub fn debugger_name(&self) -> Option<&str> {
        self.debugger_name.as_deref()
    }

    /// Set the debugger name.
    pub fn set_debugger_name(&mut self, name: impl Into<String>) {
        self.debugger_name = Some(name.into());
    }

    /// Get the endianness, if set.
    pub fn endian(&self) -> Option<&str> {
        self.endian.as_deref()
    }

    /// Set the endianness.
    pub fn set_endian(&mut self, endian: impl Into<String>) {
        self.endian = Some(endian.into());
    }
}

impl DbTraceObjectInterface for DbTraceObjectEnvironment {
    fn path(&self) -> &KeyPath {
        &self.path
    }
}

/// Database-backed implementation of `TraceEventScope`.
///
/// The event scope is the root object that can emit events affecting
/// the debug session.
#[derive(Debug, Clone)]
pub struct DbTraceObjectEventScope {
    path: KeyPath,
    event_thread: Option<u64>,
    time_support: Option<String>,
}

impl DbTraceObjectEventScope {
    /// Create a new event scope DB object wrapper.
    pub fn new(path: KeyPath) -> Self {
        Self {
            path,
            event_thread: None,
            time_support: None,
        }
    }

    /// Get the event thread ID, if set.
    pub fn event_thread(&self) -> Option<u64> {
        self.event_thread
    }

    /// Set the event thread ID.
    pub fn set_event_thread(&mut self, tid: Option<u64>) {
        self.event_thread = tid;
    }

    /// Get the time support mode.
    pub fn time_support(&self) -> Option<&str> {
        self.time_support.as_deref()
    }

    /// Set the time support mode.
    pub fn set_time_support(&mut self, mode: impl Into<String>) {
        self.time_support = Some(mode.into());
    }
}

impl DbTraceObjectInterface for DbTraceObjectEventScope {
    fn path(&self) -> &KeyPath {
        &self.path
    }
}

/// Database-backed implementation of `TraceExecutionStateful`.
///
/// Objects that have execution state (running, stopped, terminated, etc.)
/// are wrapped in this type at the database layer.
#[derive(Debug, Clone)]
pub struct DbTraceObjectExecutionStateful {
    path: KeyPath,
    state: ExecutionState,
}

impl DbTraceObjectExecutionStateful {
    /// Create a new execution-stateful DB object wrapper.
    pub fn new(path: KeyPath) -> Self {
        Self {
            path,
            state: ExecutionState::Unknown,
        }
    }

    /// Create from an existing `TraceExecutionStateful` model object.
    pub fn from_model(model: &TraceExecutionStateful) -> Self {
        Self {
            path: model.path.clone(),
            state: model.state,
        }
    }

    /// Get the current execution state.
    pub fn state(&self) -> ExecutionState {
        self.state
    }

    /// Set the execution state.
    pub fn set_state(&mut self, state: ExecutionState) {
        self.state = state;
    }

    /// Whether the object is running.
    pub fn is_running(&self) -> bool {
        self.state == ExecutionState::Running
    }

    /// Whether the object is stopped.
    pub fn is_stopped(&self) -> bool {
        self.state == ExecutionState::Stopped
    }
}

impl DbTraceObjectInterface for DbTraceObjectExecutionStateful {
    fn path(&self) -> &KeyPath {
        &self.path
    }
}

/// Database-backed implementation of `TraceFocusScope`.
///
/// The focus scope tracks which object is currently "in focus" for
/// debugging operations.
#[derive(Debug, Clone)]
pub struct DbTraceObjectFocusScope {
    path: KeyPath,
    focus_path: Option<KeyPath>,
}

impl DbTraceObjectFocusScope {
    /// Create a new focus scope DB object wrapper.
    pub fn new(path: KeyPath) -> Self {
        Self {
            path,
            focus_path: None,
        }
    }

    /// Create from an existing `TraceFocusScope` model object.
    pub fn from_model(model: &TraceFocusScope) -> Self {
        Self {
            path: model.path.clone(),
            focus_path: model.focus_path.clone(),
        }
    }

    /// Get the focused path, if any.
    pub fn focused(&self) -> Option<&KeyPath> {
        self.focus_path.as_ref()
    }

    /// Set the focus path.
    pub fn set_focus(&mut self, path: Option<KeyPath>) {
        self.focus_path = path;
    }
}

impl DbTraceObjectInterface for DbTraceObjectFocusScope {
    fn path(&self) -> &KeyPath {
        &self.path
    }
}

/// Database-backed implementation of `TraceMethod`.
///
/// Method objects represent callable functions in the debug target.
#[derive(Debug, Clone)]
pub struct DbTraceObjectMethod {
    path: KeyPath,
    name: String,
    entry_point: u64,
}

impl DbTraceObjectMethod {
    /// Create a new method DB object wrapper.
    pub fn new(path: KeyPath, name: impl Into<String>, entry_point: u64) -> Self {
        Self {
            path,
            name: name.into(),
            entry_point,
        }
    }

    /// Create from an existing `TraceMethod` model object.
    pub fn from_model(model: &TraceMethod) -> Self {
        Self {
            path: model.path.clone(),
            name: model.name.clone(),
            entry_point: model.entry_point,
        }
    }

    /// Get the method name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the entry point address.
    pub fn entry_point(&self) -> u64 {
        self.entry_point
    }
}

impl DbTraceObjectInterface for DbTraceObjectMethod {
    fn path(&self) -> &KeyPath {
        &self.path
    }
}

/// Database-backed implementation of `TraceTogglable`.
///
/// Togglable objects (e.g., breakpoints) can be enabled or disabled.
#[derive(Debug, Clone)]
pub struct DbTraceObjectTogglable {
    path: KeyPath,
    enabled: bool,
}

impl DbTraceObjectTogglable {
    /// Create a new togglable DB object wrapper.
    pub fn new(path: KeyPath) -> Self {
        Self {
            path,
            enabled: true,
        }
    }

    /// Create from an existing `TraceTogglable` model object.
    pub fn from_model(model: &TraceTogglable) -> Self {
        Self {
            path: model.path.clone(),
            enabled: model.enabled,
        }
    }

    /// Whether this object is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Toggle the enabled state.
    pub fn toggle(&mut self) {
        self.enabled = !self.enabled;
    }
}

impl DbTraceObjectInterface for DbTraceObjectTogglable {
    fn path(&self) -> &KeyPath {
        &self.path
    }
}

/// A union type that can hold any of the DB target interface implementations.
///
/// This is the Rust equivalent of the Java factory pattern used in
/// `BuiltinTraceObjectInterfaceFactory`. It allows uniform handling of
/// all interface implementations through a single enum.
#[derive(Debug, Clone)]
pub enum DbTraceObjectIface {
    /// Activatable interface.
    Activatable(DbTraceObjectActivatable),
    /// Aggregate interface.
    Aggregate(DbTraceObjectAggregate),
    /// Environment interface.
    Environment(DbTraceObjectEnvironment),
    /// Event scope interface.
    EventScope(DbTraceObjectEventScope),
    /// Execution-stateful interface.
    ExecutionStateful(DbTraceObjectExecutionStateful),
    /// Focus scope interface.
    FocusScope(DbTraceObjectFocusScope),
    /// Method interface.
    Method(DbTraceObjectMethod),
    /// Togglable interface.
    Togglable(DbTraceObjectTogglable),
}

impl DbTraceObjectIface {
    /// Get the path for this interface object.
    pub fn path(&self) -> &KeyPath {
        match self {
            Self::Activatable(i) => i.path(),
            Self::Aggregate(i) => i.path(),
            Self::Environment(i) => i.path(),
            Self::EventScope(i) => i.path(),
            Self::ExecutionStateful(i) => i.path(),
            Self::FocusScope(i) => i.path(),
            Self::Method(i) => i.path(),
            Self::Togglable(i) => i.path(),
        }
    }

    /// Get the schema name for this interface.
    pub fn schema_name(&self) -> &'static str {
        match self {
            Self::Activatable(_) => "Activatable",
            Self::Aggregate(_) => "Aggregate",
            Self::Environment(_) => "Environment",
            Self::EventScope(_) => "EventScope",
            Self::ExecutionStateful(_) => "ExecutionStateful",
            Self::FocusScope(_) => "FocusScope",
            Self::Method(_) => "Method",
            Self::Togglable(_) => "Togglable",
        }
    }

    /// Get the short name for this interface.
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Activatable(_) => "activatable",
            Self::Aggregate(_) => "aggregate",
            Self::Environment(_) => "environment",
            Self::EventScope(_) => "event scope",
            Self::ExecutionStateful(_) => "exec stateful",
            Self::FocusScope(_) => "focus scope",
            Self::Method(_) => "method",
            Self::Togglable(_) => "togglable",
        }
    }
}

impl DbTraceObjectInterface for DbTraceObjectIface {
    fn path(&self) -> &KeyPath {
        self.path()
    }
}

/// A factory for creating DB target interface implementations.
///
/// This mirrors Ghidra's `BuiltinTraceObjectInterfaceFactory`. Given a
/// schema name and a path, it creates the appropriate DB interface wrapper.
pub struct BuiltinDbInterfaceFactory;

impl BuiltinDbInterfaceFactory {
    /// Create a DB interface implementation for the given schema name.
    pub fn create(schema_name: &str, path: KeyPath) -> Option<DbTraceObjectIface> {
        match schema_name {
            "Activatable" => Some(DbTraceObjectIface::Activatable(
                DbTraceObjectActivatable::new(path),
            )),
            "Aggregate" => Some(DbTraceObjectIface::Aggregate(
                DbTraceObjectAggregate::new(path),
            )),
            "Environment" => Some(DbTraceObjectIface::Environment(
                DbTraceObjectEnvironment::new(path, "", ""),
            )),
            "EventScope" => Some(DbTraceObjectIface::EventScope(
                DbTraceObjectEventScope::new(path),
            )),
            "ExecutionStateful" => Some(DbTraceObjectIface::ExecutionStateful(
                DbTraceObjectExecutionStateful::new(path),
            )),
            "FocusScope" => Some(DbTraceObjectIface::FocusScope(
                DbTraceObjectFocusScope::new(path),
            )),
            "Method" => Some(DbTraceObjectIface::Method(DbTraceObjectMethod::new(
                path, "", 0,
            ))),
            "Togglable" => Some(DbTraceObjectIface::Togglable(
                DbTraceObjectTogglable::new(path),
            )),
            _ => None,
        }
    }

    /// Get the list of all supported schema names.
    pub fn supported_schemas() -> &'static [&'static str] {
        &[
            "Activatable",
            "Aggregate",
            "Environment",
            "EventScope",
            "ExecutionStateful",
            "FocusScope",
            "Method",
            "Togglable",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_activatable() {
        let path = KeyPath::parse("Processes[0].Threads[1]");
        let mut obj = DbTraceObjectActivatable::new(path.clone());
        assert!(!obj.is_active());
        obj.set_active(true);
        assert!(obj.is_active());
        assert_eq!(obj.path(), &path);
    }

    #[test]
    fn test_db_activatable_from_model() {
        let model = TraceActivatable::new(KeyPath::parse("Threads[0]"));
        let db = DbTraceObjectActivatable::from_model(&model);
        assert!(!db.is_active());
    }

    #[test]
    fn test_db_aggregate() {
        let path = KeyPath::parse("Processes");
        let mut obj = DbTraceObjectAggregate::new(path);
        assert_eq!(obj.element_count(), 0);
        obj.set_element_count(5);
        assert_eq!(obj.element_count(), 5);
    }

    #[test]
    fn test_db_environment() {
        let path = KeyPath::parse("Environment");
        let mut env = DbTraceObjectEnvironment::new(path, "linux", "x86_64");
        assert_eq!(env.os(), "linux");
        assert_eq!(env.arch(), "x86_64");
        assert!(env.debugger_name().is_none());

        env.set_debugger_name("gdb");
        env.set_endian("little");
        assert_eq!(env.debugger_name(), Some("gdb"));
        assert_eq!(env.endian(), Some("little"));
    }

    #[test]
    fn test_db_event_scope() {
        let path = KeyPath::parse("");
        let mut scope = DbTraceObjectEventScope::new(path);
        assert!(scope.event_thread().is_none());

        scope.set_event_thread(Some(42));
        assert_eq!(scope.event_thread(), Some(42));

        scope.set_time_support("linear");
        assert_eq!(scope.time_support(), Some("linear"));
    }

    #[test]
    fn test_db_execution_stateful() {
        let path = KeyPath::parse("Threads[0]");
        let mut obj = DbTraceObjectExecutionStateful::new(path);
        assert!(!obj.is_running());
        assert!(!obj.is_stopped());

        obj.set_state(ExecutionState::Running);
        assert!(obj.is_running());
        obj.set_state(ExecutionState::Stopped);
        assert!(obj.is_stopped());
    }

    #[test]
    fn test_db_focus_scope() {
        let path = KeyPath::parse("");
        let mut scope = DbTraceObjectFocusScope::new(path);
        assert!(scope.focused().is_none());

        scope.set_focus(Some(KeyPath::parse("Threads[0]")));
        assert!(scope.focused().is_some());
    }

    #[test]
    fn test_db_method() {
        let path = KeyPath::parse("Functions[0]");
        let method = DbTraceObjectMethod::new(path, "main", 0x401000);
        assert_eq!(method.name(), "main");
        assert_eq!(method.entry_point(), 0x401000);
    }

    #[test]
    fn test_db_method_from_model() {
        let model = TraceMethod::new(KeyPath::parse("F[0]"), "printf", 0x402000);
        let db = DbTraceObjectMethod::from_model(&model);
        assert_eq!(db.name(), "printf");
        assert_eq!(db.entry_point(), 0x402000);
    }

    #[test]
    fn test_db_togglable() {
        let path = KeyPath::parse("Breakpoints[0]");
        let mut obj = DbTraceObjectTogglable::new(path);
        assert!(obj.is_enabled());
        obj.toggle();
        assert!(!obj.is_enabled());
        obj.toggle();
        assert!(obj.is_enabled());
    }

    #[test]
    fn test_db_togglable_from_model() {
        let model = TraceTogglable::new(KeyPath::parse("BP[0]"));
        let db = DbTraceObjectTogglable::from_model(&model);
        assert!(db.is_enabled());
    }

    #[test]
    fn test_db_iface_union() {
        let iface = DbTraceObjectIface::Activatable(DbTraceObjectActivatable::new(
            KeyPath::parse("Threads[0]"),
        ));
        assert_eq!(iface.schema_name(), "Activatable");
        assert_eq!(iface.short_name(), "activatable");
    }

    #[test]
    fn test_db_iface_all_variants() {
        let variants = vec![
            DbTraceObjectIface::Activatable(DbTraceObjectActivatable::new(KeyPath::parse("a"))),
            DbTraceObjectIface::Aggregate(DbTraceObjectAggregate::new(KeyPath::parse("b"))),
            DbTraceObjectIface::Environment(DbTraceObjectEnvironment::new(
                KeyPath::parse("c"),
                "os",
                "arch",
            )),
            DbTraceObjectIface::EventScope(DbTraceObjectEventScope::new(KeyPath::parse("d"))),
            DbTraceObjectIface::ExecutionStateful(DbTraceObjectExecutionStateful::new(
                KeyPath::parse("e"),
            )),
            DbTraceObjectIface::FocusScope(DbTraceObjectFocusScope::new(KeyPath::parse("f"))),
            DbTraceObjectIface::Method(DbTraceObjectMethod::new(KeyPath::parse("g"), "m", 0)),
            DbTraceObjectIface::Togglable(DbTraceObjectTogglable::new(KeyPath::parse("h"))),
        ];
        let names: Vec<&str> = variants.iter().map(|v| v.schema_name()).collect();
        assert_eq!(names.len(), 8);
        assert!(names.contains(&"Activatable"));
        assert!(names.contains(&"Method"));
    }

    #[test]
    fn test_builtin_factory_create() {
        let path = KeyPath::parse("test");
        let iface = BuiltinDbInterfaceFactory::create("Activatable", path);
        assert!(iface.is_some());
        assert_eq!(iface.unwrap().schema_name(), "Activatable");

        let missing = BuiltinDbInterfaceFactory::create("NonExistent", KeyPath::parse("x"));
        assert!(missing.is_none());
    }

    #[test]
    fn test_builtin_factory_supported_schemas() {
        let schemas = BuiltinDbInterfaceFactory::supported_schemas();
        assert_eq!(schemas.len(), 8);
        assert!(schemas.contains(&"Activatable"));
        assert!(schemas.contains(&"Togglable"));
    }

    #[test]
    fn test_event_translation_returns_none() {
        let obj = DbTraceObjectActivatable::new(KeyPath::parse("x"));
        let record = TraceEventRecord {
            kind: "value_changed".to_string(),
            path: KeyPath::parse("x"),
        };
        assert!(obj.translate_event(&record).is_none());
    }
}
