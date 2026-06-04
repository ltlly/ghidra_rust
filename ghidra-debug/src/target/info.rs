//! Trace object info, interface factories, and utilities.
//!
//! Ported from Ghidra's `ghidra.trace.model.target.info` package.
//! Provides metadata about trace object interfaces, including schema names,
//! short names, required attributes, and factory registration.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::model::target_schema::SchemaName;

/// Metadata describing a trace object interface.
///
/// In Ghidra this is a Java annotation; here it is a struct that can be
/// registered in a global registry.
#[derive(Debug, Clone)]
pub struct TraceObjectInfo {
    /// The schema name for this interface.
    pub schema_name: String,
    /// A short name for this interface type.
    pub short_name: String,
    /// The attributes expected or required by this interface.
    pub attributes: Vec<String>,
    /// Keys intrinsic to this interface, whose values are fixed during the object's lifespan.
    pub fixed_keys: Vec<String>,
}

impl TraceObjectInfo {
    /// Create a new trace object info.
    pub fn new(
        schema_name: impl Into<String>,
        short_name: impl Into<String>,
        attributes: Vec<String>,
        fixed_keys: Vec<String>,
    ) -> Self {
        Self {
            schema_name: schema_name.into(),
            short_name: short_name.into(),
            attributes,
            fixed_keys,
        }
    }

    /// Get the schema name.
    pub fn schema_name(&self) -> &str {
        &self.schema_name
    }

    /// Get the short name.
    pub fn short_name(&self) -> &str {
        &self.short_name
    }

    /// Get the required attributes.
    pub fn attributes(&self) -> &[String] {
        &self.attributes
    }

    /// Get the fixed keys.
    pub fn fixed_keys(&self) -> &[String] {
        &self.fixed_keys
    }
}

/// A constructor entry for a trace object interface.
#[derive(Debug, Clone)]
pub struct InterfaceConstructor {
    /// The interface info.
    pub info: TraceObjectInfo,
}

/// Registry of trace object interface constructors.
///
/// Ported from `TraceObjectInterfaceUtils`. Manages the mapping from
/// schema names and Rust type names to interface constructors.
#[derive(Debug)]
pub struct InterfaceRegistry {
    by_schema_name: HashMap<String, InterfaceConstructor>,
    by_short_name: HashMap<String, InterfaceConstructor>,
}

impl InterfaceRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            by_schema_name: HashMap::new(),
            by_short_name: HashMap::new(),
        }
    }

    /// Register an interface constructor.
    pub fn register(&mut self, ctor: InterfaceConstructor) {
        self.by_schema_name
            .insert(ctor.info.schema_name.clone(), ctor.clone());
        self.by_short_name
            .insert(ctor.info.short_name.clone(), ctor);
    }

    /// Look up by schema name.
    pub fn get_by_schema_name(&self, name: &str) -> Option<&InterfaceConstructor> {
        self.by_schema_name.get(name)
    }

    /// Look up by short name.
    pub fn get_by_short_name(&self, name: &str) -> Option<&InterfaceConstructor> {
        self.by_short_name.get(name)
    }

    /// Get all registered constructors.
    pub fn all(&self) -> &HashMap<String, InterfaceConstructor> {
        &self.by_schema_name
    }

    /// Get all schema names.
    pub fn schema_names(&self) -> Vec<&str> {
        self.by_schema_name.keys().map(|s| s.as_str()).collect()
    }

    /// Number of registered interfaces.
    pub fn len(&self) -> usize {
        self.by_schema_name.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.by_schema_name.is_empty()
    }
}

impl Default for InterfaceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global interface registry, thread-safe.
///
/// This is the Rust equivalent of the `ClassSearcher`-based
/// `TraceObjectInterfaceUtils` in Ghidra.
static GLOBAL_REGISTRY: once_cell::sync::Lazy<Arc<RwLock<InterfaceRegistry>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(InterfaceRegistry::new())));

/// Get a reference to the global interface registry.
pub fn global_registry() -> Arc<RwLock<InterfaceRegistry>> {
    GLOBAL_REGISTRY.clone()
}

/// Register an interface in the global registry.
pub fn register_interface(info: TraceObjectInfo) {
    let mut reg = GLOBAL_REGISTRY.write().unwrap();
    reg.register(InterfaceConstructor { info });
}

/// Look up an interface by schema name in the global registry.
pub fn get_interface_by_schema_name(name: &str) -> Option<InterfaceConstructor> {
    let reg = GLOBAL_REGISTRY.read().unwrap();
    reg.get_by_schema_name(name).cloned()
}

/// Look up an interface by short name in the global registry.
pub fn get_interface_by_short_name(name: &str) -> Option<InterfaceConstructor> {
    let reg = GLOBAL_REGISTRY.read().unwrap();
    reg.get_by_short_name(name).cloned()
}

/// Whether the given class name represents a trace object type.
pub fn is_trace_object_type(name: &str) -> bool {
    name == "TraceObject" || get_interface_by_short_name(name).is_some()
}

/// Register the built-in trace object interfaces.
///
/// These correspond to the interfaces defined in the `target_iface` model module.
pub fn register_builtin_interfaces() {
    let builtins = vec![
        TraceObjectInfo::new("OBJECT", "TraceObject", vec![], vec![]),
        TraceObjectInfo::new(
            "AGGREGATE",
            "TraceAggregate",
            vec![],
            vec![],
        ),
        TraceObjectInfo::new(
            "ACTIVATABLE",
            "TraceActivatable",
            vec!["active".to_string()],
            vec![],
        ),
        TraceObjectInfo::new(
            "ENVIRONMENT",
            "TraceEnvironment",
            vec![],
            vec![],
        ),
        TraceObjectInfo::new(
            "EVENT_SCOPE",
            "TraceEventScope",
            vec![],
            vec![],
        ),
        TraceObjectInfo::new(
            "EXECUTION_STATEFUL",
            "TraceExecutionStateful",
            vec!["state".to_string()],
            vec![],
        ),
        TraceObjectInfo::new(
            "FOCUS_SCOPE",
            "TraceFocusScope",
            vec![],
            vec![],
        ),
        TraceObjectInfo::new(
            "METHOD",
            "TraceMethod",
            vec!["entry".to_string(), "name".to_string()],
            vec![],
        ),
        TraceObjectInfo::new(
            "TOGGLABLE",
            "TraceTogglable",
            vec!["enabled".to_string()],
            vec![],
        ),
    ];

    for info in builtins {
        register_interface(info);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_object_info() {
        let info = TraceObjectInfo::new(
            "PROCESS",
            "TraceProcess",
            vec!["pid".to_string(), "name".to_string()],
            vec!["pid".to_string()],
        );
        assert_eq!(info.schema_name(), "PROCESS");
        assert_eq!(info.short_name(), "TraceProcess");
        assert_eq!(info.attributes().len(), 2);
        assert_eq!(info.fixed_keys().len(), 1);
    }

    #[test]
    fn test_interface_registry() {
        let mut reg = InterfaceRegistry::new();
        reg.register(InterfaceConstructor {
            info: TraceObjectInfo::new("PROC", "Process", vec![], vec![]),
        });
        assert!(reg.get_by_schema_name("PROC").is_some());
        assert!(reg.get_by_short_name("Process").is_some());
        assert!(reg.get_by_schema_name("MISSING").is_none());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn test_register_and_lookup() {
        // Note: This test modifies global state; in production code, tests
        // should use isolated registries. For now, we just verify the mechanism works.
        let info = TraceObjectInfo::new(
            "TEST_IFACE",
            "TestIface",
            vec!["attr1".to_string()],
            vec![],
        );
        register_interface(info);
        let found = get_interface_by_schema_name("TEST_IFACE");
        assert!(found.is_some());
        assert_eq!(found.unwrap().info.short_name, "TestIface");
    }

    #[test]
    fn test_is_trace_object_type() {
        assert!(is_trace_object_type("TraceObject"));
    }

    #[test]
    fn test_builtin_registration() {
        register_builtin_interfaces();
        assert!(get_interface_by_schema_name("OBJECT").is_some());
        assert!(get_interface_by_schema_name("ACTIVATABLE").is_some());
        assert!(get_interface_by_schema_name("TOGGLABLE").is_some());
    }
}
