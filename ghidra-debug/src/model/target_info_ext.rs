//! Extended TraceObjectInterfaceUtils - utility helpers for object interface management.
//!
//! Ported from Ghidra's `ghidra.trace.model.target.info.TraceObjectInterfaceUtils` and
//! `ghidra.trace.model.target.info.BuiltinTraceObjectInterfaceFactory`.
//!
//! Provides utility methods for querying interface metadata, looking up
//! constructors by class or schema name, and checking interface hierarchies.

use std::collections::HashMap;

use super::target_info::{TraceObjectInfo, TraceObjectInterfaceRegistry};
use super::target_schema::{SchemaName, TraceObjectSchemaDef};

/// Utility methods for working with trace object interfaces.
///
/// This mirrors the Java `TraceObjectInterfaceUtils` enum, providing
/// static utility methods for the interface registration system.
pub struct TraceObjectInterfaceUtils;

impl TraceObjectInterfaceUtils {
    /// Get the schema name for a given TraceObjectInfo.
    pub fn get_schema_name(info: &TraceObjectInfo) -> SchemaName {
        info.schema_name()
    }

    /// Get the short name for a given TraceObjectInfo.
    pub fn get_short_name(info: &TraceObjectInfo) -> &str {
        &info.short_name
    }

    /// Get the fixed keys for a given TraceObjectInfo.
    pub fn get_fixed_keys(info: &TraceObjectInfo) -> &[String] {
        &info.fixed_keys
    }

    /// Get the attributes for a given TraceObjectInfo.
    pub fn get_attributes(info: &TraceObjectInfo) -> &[String] {
        &info.attributes
    }

    /// Find all interfaces in a registry that match a given schema definition.
    pub fn find_interfaces_for_schema<'a>(
        registry: &'a TraceObjectInterfaceRegistry,
        schema: &TraceObjectSchemaDef,
    ) -> Vec<&'a TraceObjectInfo> {
        schema
            .interfaces
            .iter()
            .filter_map(|iface_name| registry.get(iface_name))
            .collect()
    }

    /// Build a name-to-info map from a registry.
    pub fn build_name_map(registry: &TraceObjectInterfaceRegistry) -> HashMap<String, &TraceObjectInfo> {
        registry
            .schema_names()
            .into_iter()
            .filter_map(|name| registry.get(name).map(|info| (name.to_string(), info)))
            .collect()
    }

    /// Check if a schema definition includes a specific interface.
    pub fn schema_implements(schema: &TraceObjectSchemaDef, iface_name: &str) -> bool {
        schema.interfaces.contains(iface_name)
    }

    /// Get all schema names that a given interface is part of.
    pub fn find_schemas_for_interface<'a>(
        schemas: &'a [TraceObjectSchemaDef],
        iface_name: &str,
    ) -> Vec<&'a TraceObjectSchemaDef> {
        schemas
            .iter()
            .filter(|s| s.interfaces.contains(iface_name))
            .collect()
    }

    /// Compute the union of attributes from all interfaces in a schema.
    pub fn collect_attributes_for_schema(
        registry: &TraceObjectInterfaceRegistry,
        schema: &TraceObjectSchemaDef,
    ) -> Vec<String> {
        let mut attrs = Vec::new();
        for iface_name in &schema.interfaces {
            if let Some(info) = registry.get(iface_name) {
                for attr in &info.attributes {
                    if !attrs.contains(attr) {
                        attrs.push(attr.clone());
                    }
                }
            }
        }
        attrs
    }

    /// Compute the union of fixed keys from all interfaces in a schema.
    pub fn collect_fixed_keys_for_schema(
        registry: &TraceObjectInterfaceRegistry,
        schema: &TraceObjectSchemaDef,
    ) -> Vec<String> {
        let mut keys = Vec::new();
        for iface_name in &schema.interfaces {
            if let Some(info) = registry.get(iface_name) {
                for key in &info.fixed_keys {
                    if !keys.contains(key) {
                        keys.push(key.clone());
                    }
                }
            }
        }
        keys
    }
}

/// Builtin trace object interface factory.
///
/// Creates and registers all the standard Ghidra target object interfaces.
/// This corresponds to Ghidra's `BuiltinTraceObjectInterfaceFactory`.
pub struct BuiltinTraceObjectInterfaceFactory {
    registry: TraceObjectInterfaceRegistry,
}

impl BuiltinTraceObjectInterfaceFactory {
    /// Create a new factory with all built-in interfaces registered.
    pub fn new() -> Self {
        let mut registry = TraceObjectInterfaceRegistry::new();
        for info in super::target_info::builtin::all_builtins() {
            registry.register(info);
        }
        Self { registry }
    }

    /// Get the registry.
    pub fn registry(&self) -> &TraceObjectInterfaceRegistry {
        &self.registry
    }

    /// Get all interface constructors (info objects).
    pub fn get_interface_infos(&self) -> Vec<&TraceObjectInfo> {
        self.registry
            .schema_names()
            .into_iter()
            .filter_map(|name| self.registry.get(name))
            .collect()
    }

    /// Look up an interface info by schema name.
    pub fn get_by_schema_name(&self, name: &str) -> Option<&TraceObjectInfo> {
        self.registry.get(name)
    }

    /// Look up an interface info by short name.
    pub fn get_by_short_name(&self, short_name: &str) -> Option<&TraceObjectInfo> {
        self.registry
            .schema_names()
            .into_iter()
            .find(|&name| {
                self.registry
                    .get(name)
                    .map_or(false, |info| info.short_name == short_name)
            })
            .and_then(|name| self.registry.get(name))
    }
}

impl Default for BuiltinTraceObjectInterfaceFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BuiltinTraceObjectInterfaceFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltinTraceObjectInterfaceFactory")
            .field("count", &self.registry.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::target_info::builtin;

    #[test]
    fn test_get_schema_name() {
        let info = builtin::thread();
        let name = TraceObjectInterfaceUtils::get_schema_name(&info);
        assert_eq!(name.name, "Thread");
    }

    #[test]
    fn test_get_short_name() {
        let info = builtin::process();
        assert_eq!(TraceObjectInterfaceUtils::get_short_name(&info), "process");
    }

    #[test]
    fn test_get_fixed_keys() {
        let info = builtin::thread();
        let keys = TraceObjectInterfaceUtils::get_fixed_keys(&info);
        assert!(keys.contains(&"_tid".to_string()));
    }

    #[test]
    fn test_get_attributes() {
        let info = builtin::module();
        let attrs = TraceObjectInterfaceUtils::get_attributes(&info);
        assert!(attrs.contains(&"_path".to_string()));
        assert!(attrs.contains(&"_base".to_string()));
    }

    #[test]
    fn test_find_interfaces_for_schema() {
        let mut registry = TraceObjectInterfaceRegistry::new();
        registry.register(builtin::process());
        registry.register(builtin::thread());

        let mut schema = TraceObjectSchemaDef::new("PROCESS", "TraceObject");
        schema.interfaces.insert("Process".to_string());
        schema.interfaces.insert("Thread".to_string());

        let found = TraceObjectInterfaceUtils::find_interfaces_for_schema(&registry, &schema);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_build_name_map() {
        let mut registry = TraceObjectInterfaceRegistry::new();
        registry.register(builtin::thread());
        registry.register(builtin::process());

        let map = TraceObjectInterfaceUtils::build_name_map(&registry);
        assert!(map.contains_key("Thread"));
        assert!(map.contains_key("Process"));
    }

    #[test]
    fn test_schema_implements() {
        let mut schema = TraceObjectSchemaDef::new("PROCESS", "TraceObject");
        schema.interfaces.insert("TraceProcess".to_string());

        assert!(TraceObjectInterfaceUtils::schema_implements(&schema, "TraceProcess"));
        assert!(!TraceObjectInterfaceUtils::schema_implements(&schema, "TraceThread"));
    }

    #[test]
    fn test_find_schemas_for_interface() {
        let mut s1 = TraceObjectSchemaDef::new("PROCESS", "TraceObject");
        s1.interfaces.insert("TraceAggregate".to_string());
        let mut s2 = TraceObjectSchemaDef::new("THREAD", "TraceObject");
        s2.interfaces.insert("TraceAggregate".to_string());
        let mut s3 = TraceObjectSchemaDef::new("MODULE", "TraceObject");
        s3.interfaces.insert("TraceModule".to_string());

        let schemas = vec![s1, s2, s3];
        let found = TraceObjectInterfaceUtils::find_schemas_for_interface(&schemas, "TraceAggregate");
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_collect_attributes_for_schema() {
        let mut registry = TraceObjectInterfaceRegistry::new();
        registry.register(builtin::thread());

        let mut schema = TraceObjectSchemaDef::new("THREAD", "TraceObject");
        schema.interfaces.insert("Thread".to_string());

        let attrs = TraceObjectInterfaceUtils::collect_attributes_for_schema(&registry, &schema);
        assert!(attrs.contains(&"_display".to_string()));
        assert!(attrs.contains(&"_tid".to_string()));
        assert!(attrs.contains(&"_state".to_string()));
    }

    #[test]
    fn test_collect_fixed_keys_for_schema() {
        let mut registry = TraceObjectInterfaceRegistry::new();
        registry.register(builtin::process());

        let mut schema = TraceObjectSchemaDef::new("PROCESS", "TraceObject");
        schema.interfaces.insert("Process".to_string());

        let keys = TraceObjectInterfaceUtils::collect_fixed_keys_for_schema(&registry, &schema);
        assert!(keys.contains(&"_pid".to_string()));
    }

    #[test]
    fn test_builtin_factory_new() {
        let factory = BuiltinTraceObjectInterfaceFactory::new();
        assert!(factory.registry().len() >= 20);
    }

    #[test]
    fn test_builtin_factory_get_by_schema_name() {
        let factory = BuiltinTraceObjectInterfaceFactory::new();
        let info = factory.get_by_schema_name("Thread").unwrap();
        assert_eq!(info.short_name, "thread");
        assert!(factory.get_by_schema_name("NonExistent").is_none());
    }

    #[test]
    fn test_builtin_factory_get_by_short_name() {
        let factory = BuiltinTraceObjectInterfaceFactory::new();
        let info = factory.get_by_short_name("process").unwrap();
        assert_eq!(info.schema_name, "Process");
        assert!(factory.get_by_short_name("nonexistent").is_none());
    }

    #[test]
    fn test_builtin_factory_get_interface_infos() {
        let factory = BuiltinTraceObjectInterfaceFactory::new();
        let infos = factory.get_interface_infos();
        assert!(infos.len() >= 20);
    }

    #[test]
    fn test_builtin_factory_debug() {
        let factory = BuiltinTraceObjectInterfaceFactory::new();
        let debug_str = format!("{:?}", factory);
        assert!(debug_str.contains("BuiltinTraceObjectInterfaceFactory"));
    }
}
