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
}
