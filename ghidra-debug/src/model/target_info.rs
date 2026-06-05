//! TraceObjectInfo - metadata about trace object interfaces.
//!
//! Ported from Ghidra's `ghidra.trace.model.target.info` package.
//! Provides annotations and factories for registering object interfaces
//! in the target tree.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::target_schema::SchemaName;

/// Information about a trace object interface type.
///
/// Each interface that objects in the target tree can implement is described
/// by a `TraceObjectInfo`, which specifies the schema name, display name,
/// required attributes, and fixed keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceObjectInfo {
    /// The schema name for this type of object (e.g., "Thread", "Process", "Module").
    pub schema_name: String,
    /// A short human-readable name for the type (e.g., "thread", "process").
    pub short_name: String,
    /// The attribute names this interface contributes.
    pub attributes: Vec<String>,
    /// The fixed (required) keys for this interface.
    pub fixed_keys: Vec<String>,
}

impl TraceObjectInfo {
    /// Create a new object info.
    pub fn new(
        schema_name: impl Into<String>,
        short_name: impl Into<String>,
    ) -> Self {
        Self {
            schema_name: schema_name.into(),
            short_name: short_name.into(),
            attributes: Vec::new(),
            fixed_keys: Vec::new(),
        }
    }

    /// Add an attribute.
    pub fn with_attribute(mut self, attr: impl Into<String>) -> Self {
        self.attributes.push(attr.into());
        self
    }

    /// Add a fixed key.
    pub fn with_fixed_key(mut self, key: impl Into<String>) -> Self {
        self.fixed_keys.push(key.into());
        self
    }

    /// Convert to a SchemaName.
    pub fn schema_name(&self) -> SchemaName {
        SchemaName::new(&self.schema_name)
    }
}

/// A factory for creating trace object interface bindings.
///
/// Implementations of this trait create the appropriate interface structs
/// (e.g., TraceActivatable, TraceThread, etc.) from a TraceObject.
pub trait TraceObjectInterfaceFactory: std::fmt::Debug {
    /// The schema name this factory handles.
    fn schema_name(&self) -> &str;

    /// Get the object info for this factory.
    fn info(&self) -> &TraceObjectInfo;
}

/// Registry of all known object interface factories.
#[derive(Debug, Default)]
pub struct TraceObjectInterfaceRegistry {
    factories: HashMap<String, TraceObjectInfo>,
}

impl TraceObjectInterfaceRegistry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an object info.
    pub fn register(&mut self, info: TraceObjectInfo) {
        self.factories.insert(info.schema_name.clone(), info);
    }

    /// Get object info by schema name.
    pub fn get(&self, schema_name: &str) -> Option<&TraceObjectInfo> {
        self.factories.get(schema_name)
    }

    /// Get all registered schema names.
    pub fn schema_names(&self) -> Vec<&str> {
        self.factories.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of registered types.
    pub fn len(&self) -> usize {
        self.factories.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }
}

/// Built-in object interface types, matching Ghidra's standard target schema.
pub mod builtin {
    use super::TraceObjectInfo;

    /// Process object info.
    pub fn process() -> TraceObjectInfo {
        TraceObjectInfo::new("Process", "process")
            .with_attribute("_display")
            .with_attribute("_pid")
            .with_fixed_key("_pid")
    }

    /// Thread object info.
    pub fn thread() -> TraceObjectInfo {
        TraceObjectInfo::new("Thread", "thread")
            .with_attribute("_display")
            .with_attribute("_tid")
            .with_attribute("_state")
            .with_fixed_key("_tid")
    }

    /// Module object info.
    pub fn module() -> TraceObjectInfo {
        TraceObjectInfo::new("Module", "module")
            .with_attribute("_display")
            .with_attribute("_path")
            .with_attribute("_base")
            .with_fixed_key("_path")
    }

    /// Register object info.
    pub fn register() -> TraceObjectInfo {
        TraceObjectInfo::new("Register", "register")
            .with_attribute("_length")
            .with_attribute("_value")
            .with_attribute("_state")
            .with_fixed_key("_length")
    }

    /// Register container object info.
    pub fn register_container() -> TraceObjectInfo {
        TraceObjectInfo::new("RegisterContainer", "register container")
    }

    /// Memory region object info.
    pub fn memory_region() -> TraceObjectInfo {
        TraceObjectInfo::new("MemoryRegion", "memory region")
            .with_attribute("_display")
            .with_attribute("_range")
            .with_attribute("_read")
            .with_attribute("_write")
            .with_attribute("_execute")
            .with_attribute("_volatile")
    }

    /// Breakpoint spec object info.
    pub fn breakpoint_spec() -> TraceObjectInfo {
        TraceObjectInfo::new("BreakpointSpec", "breakpoint specification")
            .with_attribute("_display")
            .with_attribute("_enabled")
            .with_attribute("_kind")
    }

    /// Environment object info.
    pub fn environment() -> TraceObjectInfo {
        TraceObjectInfo::new("Environment", "environment")
            .with_attribute("_os")
            .with_attribute("_arch")
    }

    /// Stack frame object info.
    pub fn stack_frame() -> TraceObjectInfo {
        TraceObjectInfo::new("StackFrame", "stack frame")
            .with_attribute("_display")
            .with_attribute("_level")
            .with_attribute("_sp")
            .with_attribute("_pc")
    }

    /// Activatable object info (objects that can be activated/deactivated).
    pub fn activatable() -> TraceObjectInfo {
        TraceObjectInfo::new("Activatable", "activatable")
            .with_attribute("_active")
    }

    /// Aggregate object info (objects that group children).
    pub fn aggregate() -> TraceObjectInfo {
        TraceObjectInfo::new("Aggregate", "aggregate")
            .with_attribute("_display")
    }

    /// Event scope object info (objects that define event scopes).
    pub fn event_scope() -> TraceObjectInfo {
        TraceObjectInfo::new("EventScope", "event scope")
            .with_attribute("_display")
    }

    /// Execution stateful object info (objects with execution state).
    pub fn execution_stateful() -> TraceObjectInfo {
        TraceObjectInfo::new("ExecutionStateful", "execution stateful")
            .with_attribute("_state")
    }

    /// Focus scope object info (objects that define focus scopes).
    pub fn focus_scope() -> TraceObjectInfo {
        TraceObjectInfo::new("FocusScope", "focus scope")
            .with_attribute("_display")
    }

    /// Method object info (objects representing methods).
    pub fn method() -> TraceObjectInfo {
        TraceObjectInfo::new("Method", "method")
            .with_attribute("_display")
            .with_attribute("_name")
            .with_attribute("_parameters")
    }

    /// Togglable object info (objects that can be toggled on/off).
    pub fn togglable() -> TraceObjectInfo {
        TraceObjectInfo::new("Togglable", "togglable")
            .with_attribute("_enabled")
    }

    /// Stack object info (call stack).
    pub fn stack() -> TraceObjectInfo {
        TraceObjectInfo::new("Stack", "stack")
            .with_attribute("_display")
            .with_attribute("_depth")
    }

    /// Section object info (binary section within a module).
    pub fn section() -> TraceObjectInfo {
        TraceObjectInfo::new("Section", "section")
            .with_attribute("_display")
            .with_attribute("_name")
            .with_attribute("_range")
    }

    /// Breakpoint location object info.
    pub fn breakpoint_location() -> TraceObjectInfo {
        TraceObjectInfo::new("BreakpointLocation", "breakpoint location")
            .with_attribute("_display")
            .with_attribute("_range")
            .with_attribute("_enabled")
    }

    /// Register register object info (register value in the target tree).
    pub fn register_value() -> TraceObjectInfo {
        TraceObjectInfo::new("RegisterValue", "register value")
            .with_attribute("_length")
            .with_attribute("_value")
            .with_attribute("_state")
    }

    /// Get all built-in object infos.
    pub fn all_builtins() -> Vec<TraceObjectInfo> {
        vec![
            process(),
            thread(),
            module(),
            register(),
            register_container(),
            memory_region(),
            breakpoint_spec(),
            environment(),
            stack_frame(),
            activatable(),
            aggregate(),
            event_scope(),
            execution_stateful(),
            focus_scope(),
            method(),
            togglable(),
            stack(),
            section(),
            breakpoint_location(),
            register_value(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::builtin;

    #[test]
    fn test_object_info_basic() {
        let info = TraceObjectInfo::new("Thread", "thread")
            .with_attribute("_display")
            .with_attribute("_tid")
            .with_fixed_key("_tid");

        assert_eq!(info.schema_name, "Thread");
        assert_eq!(info.short_name, "thread");
        assert_eq!(info.attributes, vec!["_display", "_tid"]);
        assert_eq!(info.fixed_keys, vec!["_tid"]);
    }

    #[test]
    fn test_object_info_schema_name() {
        let info = TraceObjectInfo::new("Process", "process");
        assert_eq!(info.schema_name(), SchemaName::new("Process"));
    }

    #[test]
    fn test_registry_basic() {
        let mut registry = TraceObjectInterfaceRegistry::new();
        assert!(registry.is_empty());

        registry.register(builtin::process());
        registry.register(builtin::thread());
        assert_eq!(registry.len(), 2);
        assert!(!registry.is_empty());

        let names = registry.schema_names();
        assert!(names.contains(&"Process"));
        assert!(names.contains(&"Thread"));
    }

    #[test]
    fn test_registry_get() {
        let mut registry = TraceObjectInterfaceRegistry::new();
        registry.register(builtin::thread());

        let info = registry.get("Thread").unwrap();
        assert_eq!(info.short_name, "thread");

        assert!(registry.get("NonExistent").is_none());
    }

    #[test]
    fn test_builtin_process() {
        let info = builtin::process();
        assert_eq!(info.schema_name, "Process");
        assert!(info.attributes.contains(&"_pid".to_string()));
        assert!(info.fixed_keys.contains(&"_pid".to_string()));
    }

    #[test]
    fn test_builtin_thread() {
        let info = builtin::thread();
        assert_eq!(info.schema_name, "Thread");
        assert!(info.attributes.contains(&"_tid".to_string()));
        assert!(info.attributes.contains(&"_state".to_string()));
    }

    #[test]
    fn test_builtin_module() {
        let info = builtin::module();
        assert_eq!(info.schema_name, "Module");
        assert!(info.attributes.contains(&"_path".to_string()));
        assert!(info.attributes.contains(&"_base".to_string()));
    }

    #[test]
    fn test_builtin_register() {
        let info = builtin::register();
        assert_eq!(info.schema_name, "Register");
        assert!(info.attributes.contains(&"_length".to_string()));
        assert!(info.attributes.contains(&"_value".to_string()));
    }

    #[test]
    fn test_builtin_memory_region() {
        let info = builtin::memory_region();
        assert_eq!(info.schema_name, "MemoryRegion");
        assert!(info.attributes.contains(&"_read".to_string()));
        assert!(info.attributes.contains(&"_write".to_string()));
        assert!(info.attributes.contains(&"_execute".to_string()));
    }

    #[test]
    fn test_builtin_breakpoint_spec() {
        let info = builtin::breakpoint_spec();
        assert_eq!(info.schema_name, "BreakpointSpec");
        assert!(info.attributes.contains(&"_enabled".to_string()));
        assert!(info.attributes.contains(&"_kind".to_string()));
    }

    #[test]
    fn test_object_info_serde() {
        let info = builtin::thread();
        let json = serde_json::to_string(&info).unwrap();
        let back: TraceObjectInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_name, "Thread");
    }

    #[test]
    fn test_builtin_activatable() {
        let info = builtin::activatable();
        assert_eq!(info.schema_name, "Activatable");
        assert!(info.attributes.contains(&"_active".to_string()));
    }

    #[test]
    fn test_builtin_aggregate() {
        let info = builtin::aggregate();
        assert_eq!(info.schema_name, "Aggregate");
    }

    #[test]
    fn test_builtin_event_scope() {
        let info = builtin::event_scope();
        assert_eq!(info.schema_name, "EventScope");
    }

    #[test]
    fn test_builtin_execution_stateful() {
        let info = builtin::execution_stateful();
        assert_eq!(info.schema_name, "ExecutionStateful");
        assert!(info.attributes.contains(&"_state".to_string()));
    }

    #[test]
    fn test_builtin_focus_scope() {
        let info = builtin::focus_scope();
        assert_eq!(info.schema_name, "FocusScope");
    }

    #[test]
    fn test_builtin_method() {
        let info = builtin::method();
        assert_eq!(info.schema_name, "Method");
        assert!(info.attributes.contains(&"_name".to_string()));
        assert!(info.attributes.contains(&"_parameters".to_string()));
    }

    #[test]
    fn test_builtin_togglable() {
        let info = builtin::togglable();
        assert_eq!(info.schema_name, "Togglable");
        assert!(info.attributes.contains(&"_enabled".to_string()));
    }

    #[test]
    fn test_builtin_stack() {
        let info = builtin::stack();
        assert_eq!(info.schema_name, "Stack");
        assert!(info.attributes.contains(&"_depth".to_string()));
    }

    #[test]
    fn test_builtin_section() {
        let info = builtin::section();
        assert_eq!(info.schema_name, "Section");
        assert!(info.attributes.contains(&"_name".to_string()));
        assert!(info.attributes.contains(&"_range".to_string()));
    }

    #[test]
    fn test_builtin_breakpoint_location() {
        let info = builtin::breakpoint_location();
        assert_eq!(info.schema_name, "BreakpointLocation");
        assert!(info.attributes.contains(&"_range".to_string()));
    }

    #[test]
    fn test_builtin_register_value() {
        let info = builtin::register_value();
        assert_eq!(info.schema_name, "RegisterValue");
        assert!(info.attributes.contains(&"_value".to_string()));
    }

    #[test]
    fn test_all_builtins_count() {
        let all = builtin::all_builtins();
        assert!(all.len() >= 20);
        // Verify no duplicates
        let mut names: Vec<&str> = all.iter().map(|i| i.schema_name.as_str()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), all.len());
    }

    #[test]
    fn test_registry_with_all_builtins() {
        let mut registry = TraceObjectInterfaceRegistry::new();
        for info in builtin::all_builtins() {
            registry.register(info);
        }
        assert!(registry.len() >= 20);
        assert!(registry.get("Process").is_some());
        assert!(registry.get("Thread").is_some());
        assert!(registry.get("Activatable").is_some());
        assert!(registry.get("Method").is_some());
        assert!(registry.get("NonExistent").is_none());
    }
}
