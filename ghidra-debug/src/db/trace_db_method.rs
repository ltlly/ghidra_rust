//! Database-level Method (function) implementation.
//!
//! Ported from Ghidra's `DBTraceObjectMethod` in Framework-TraceModeling.
//! Represents a function/method in the debug target object tree, backed
//! by the trace database.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// Database implementation of the Method interface.
///
/// Represents a function/method discovered in the debug target. Methods
/// are stored in the target object tree and associated with an address
/// range (entry point to end). They carry metadata like name, size,
/// calling convention, and parameter information.
///
/// Ported from Ghidra's `DBTraceObjectMethod`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbObjectMethod {
    /// The object key in the database.
    pub object_key: i64,
    /// The method/function name.
    pub name: String,
    /// The entry point address.
    pub entry_point: u64,
    /// The size of the method in bytes (0 if unknown).
    pub size: u64,
    /// The return type name.
    pub return_type: Option<String>,
    /// Parameter names and types.
    pub parameters: Vec<MethodParameter>,
    /// The calling convention.
    pub calling_convention: Option<String>,
    /// Whether this is a library function.
    pub is_library: bool,
    /// Whether this is a thunk/trampoline.
    pub is_thunk: bool,
    /// The lifespan (snap range) during which this method exists.
    pub lifespan: Lifespan,
    /// The namespace (e.g., "std::vector<int>").
    pub namespace: Option<String>,
}

/// A method parameter descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodParameter {
    /// The parameter name.
    pub name: String,
    /// The parameter type.
    pub param_type: String,
    /// The ordinal position (0-based).
    pub ordinal: usize,
    /// Whether this is a varargs parameter.
    pub is_varargs: bool,
}

impl MethodParameter {
    /// Create a new parameter.
    pub fn new(
        name: impl Into<String>,
        param_type: impl Into<String>,
        ordinal: usize,
    ) -> Self {
        Self {
            name: name.into(),
            param_type: param_type.into(),
            ordinal,
            is_varargs: false,
        }
    }

    /// Mark as varargs.
    pub fn with_varargs(mut self) -> Self {
        self.is_varargs = true;
        self
    }
}

impl DbObjectMethod {
    /// Create a new method.
    pub fn new(
        object_key: i64,
        name: impl Into<String>,
        entry_point: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            object_key,
            name: name.into(),
            entry_point,
            size: 0,
            return_type: None,
            parameters: Vec::new(),
            calling_convention: None,
            is_library: false,
            is_thunk: false,
            lifespan,
            namespace: None,
        }
    }

    /// Set the method size.
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    /// Set the return type.
    pub fn with_return_type(mut self, ret_type: impl Into<String>) -> Self {
        self.return_type = Some(ret_type.into());
        self
    }

    /// Set the calling convention.
    pub fn with_calling_convention(mut self, cc: impl Into<String>) -> Self {
        self.calling_convention = Some(cc.into());
        self
    }

    /// Mark as a library function.
    pub fn as_library(mut self) -> Self {
        self.is_library = true;
        self
    }

    /// Mark as a thunk.
    pub fn as_thunk(mut self) -> Self {
        self.is_thunk = true;
        self
    }

    /// Set the namespace.
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// Add a parameter.
    pub fn add_parameter(&mut self, param: MethodParameter) {
        self.parameters.push(param);
    }

    /// Whether the method has a known size.
    pub fn has_known_size(&self) -> bool {
        self.size > 0
    }

    /// Get the end address (entry + size), if size is known.
    pub fn end_address(&self) -> Option<u64> {
        if self.size > 0 {
            Some(self.entry_point + self.size)
        } else {
            None
        }
    }

    /// Whether this method contains the given address.
    pub fn contains_address(&self, addr: u64) -> bool {
        if self.size == 0 {
            return addr == self.entry_point;
        }
        addr >= self.entry_point && addr < self.entry_point + self.size
    }

    /// The fully qualified name (namespace::name).
    pub fn qualified_name(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}::{}", ns, self.name),
            None => self.name.clone(),
        }
    }

    /// The number of parameters.
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }
}

/// Manager for methods in a trace database.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DbMethodManager {
    methods: Vec<DbObjectMethod>,
}

impl DbMethodManager {
    /// Create a new method manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a method.
    pub fn add_method(&mut self, method: DbObjectMethod) {
        self.methods.push(method);
    }

    /// Find a method by entry point.
    pub fn find_by_entry(&self, entry: u64) -> Option<&DbObjectMethod> {
        self.methods.iter().find(|m| m.entry_point == entry)
    }

    /// Find a method by name.
    pub fn find_by_name(&self, name: &str) -> Vec<&DbObjectMethod> {
        self.methods.iter().filter(|m| m.name == name).collect()
    }

    /// Find the method containing the given address.
    pub fn find_containing(&self, addr: u64, snap: i64) -> Option<&DbObjectMethod> {
        self.methods
            .iter()
            .filter(|m| m.lifespan.contains(snap) && m.contains_address(addr))
            .min_by_key(|m| m.size)
    }

    /// All methods at a given snap.
    pub fn methods_at_snap(&self, snap: i64) -> Vec<&DbObjectMethod> {
        self.methods
            .iter()
            .filter(|m| m.lifespan.contains(snap))
            .collect()
    }

    /// Get all methods.
    pub fn methods(&self) -> &[DbObjectMethod] {
        &self.methods
    }

    /// The number of methods.
    pub fn len(&self) -> usize {
        self.methods.len()
    }

    /// Whether there are no methods.
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }

    /// Remove a method by object key.
    pub fn remove(&mut self, object_key: i64) -> bool {
        let before = self.methods.len();
        self.methods.retain(|m| m.object_key != object_key);
        self.methods.len() < before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_method() -> DbObjectMethod {
        DbObjectMethod::new(1, "main", 0x400000, Lifespan::now_on(0))
            .with_size(0x100)
            .with_return_type("int")
            .with_calling_convention("cdecl")
            .with_namespace("MyApp")
    }

    #[test]
    fn test_method_creation() {
        let m = sample_method();
        assert_eq!(m.name, "main");
        assert_eq!(m.entry_point, 0x400000);
        assert_eq!(m.size, 0x100);
        assert_eq!(m.return_type.as_deref(), Some("int"));
        assert_eq!(m.calling_convention.as_deref(), Some("cdecl"));
        assert_eq!(m.namespace.as_deref(), Some("MyApp"));
    }

    #[test]
    fn test_method_end_address() {
        let m = sample_method();
        assert_eq!(m.end_address(), Some(0x400100));
        assert!(m.has_known_size());

        let m2 = DbObjectMethod::new(2, "unknown", 0x500000, Lifespan::now_on(0));
        assert_eq!(m2.end_address(), None);
        assert!(!m2.has_known_size());
    }

    #[test]
    fn test_method_contains_address() {
        let m = sample_method();
        assert!(m.contains_address(0x400000));
        assert!(m.contains_address(0x400050));
        assert!(!m.contains_address(0x400100));
        assert!(!m.contains_address(0x300000));
    }

    #[test]
    fn test_method_contains_address_unknown_size() {
        let m = DbObjectMethod::new(1, "func", 0x400000, Lifespan::now_on(0));
        assert!(m.contains_address(0x400000));
        assert!(!m.contains_address(0x400001));
    }

    #[test]
    fn test_method_qualified_name() {
        let m = sample_method();
        assert_eq!(m.qualified_name(), "MyApp::main");

        let m2 = DbObjectMethod::new(2, "func", 0x500000, Lifespan::now_on(0));
        assert_eq!(m2.qualified_name(), "func");
    }

    #[test]
    fn test_method_parameters() {
        let mut m = sample_method();
        m.add_parameter(MethodParameter::new("argc", "int", 0));
        m.add_parameter(MethodParameter::new("argv", "char**", 1).with_varargs());
        assert_eq!(m.parameter_count(), 2);
        assert!(m.parameters[1].is_varargs);
    }

    #[test]
    fn test_method_flags() {
        let m = sample_method().as_library().as_thunk();
        assert!(m.is_library);
        assert!(m.is_thunk);
    }

    #[test]
    fn test_method_manager() {
        let mut mgr = DbMethodManager::new();
        mgr.add_method(sample_method());
        mgr.add_method(DbObjectMethod::new(2, "printf", 0x600000, Lifespan::now_on(0)));

        assert_eq!(mgr.len(), 2);
        assert!(mgr.find_by_entry(0x400000).is_some());
        assert!(mgr.find_by_entry(0x999999).is_none());
        assert_eq!(mgr.find_by_name("main").len(), 1);
    }

    #[test]
    fn test_method_manager_containing() {
        let mut mgr = DbMethodManager::new();
        mgr.add_method(sample_method());
        mgr.add_method(
            DbObjectMethod::new(2, "helper", 0x400100, Lifespan::now_on(0)).with_size(0x50),
        );

        // The smallest method containing 0x400120 is "helper" (0x400100..0x400150)
        let found = mgr.find_containing(0x400120, 0);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "helper");
    }

    #[test]
    fn test_method_manager_remove() {
        let mut mgr = DbMethodManager::new();
        mgr.add_method(sample_method());
        assert!(mgr.remove(1));
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_method_serde() {
        let m = sample_method();
        let json = serde_json::to_string(&m).unwrap();
        let back: DbObjectMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "main");
        assert_eq!(back.entry_point, 0x400000);
    }

    #[test]
    fn test_method_parameter_serde() {
        let p = MethodParameter::new("x", "int", 0);
        let json = serde_json::to_string(&p).unwrap();
        let back: MethodParameter = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "x");
    }

    #[test]
    fn test_method_at_snap() {
        let mut mgr = DbMethodManager::new();
        mgr.add_method(DbObjectMethod::new(1, "f1", 0x100, Lifespan::span(0, 5)));
        mgr.add_method(DbObjectMethod::new(2, "f2", 0x200, Lifespan::span(3, 10)));

        assert_eq!(mgr.methods_at_snap(0).len(), 1);
        assert_eq!(mgr.methods_at_snap(5).len(), 2);
        assert_eq!(mgr.methods_at_snap(4).len(), 2);
    }
}
