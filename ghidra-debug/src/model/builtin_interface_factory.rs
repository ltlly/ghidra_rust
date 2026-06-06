//! Builtin trace object interface factory.
//!
//! Ported from Ghidra's Framework-TraceModeling `BuiltinTraceObjectInterfaceFactory`.
//! Provides the registry and factory for builtin trace object interfaces
//! (process, thread, memory, register, etc.) that define the schema and
//! behavior of trace objects.

use std::collections::BTreeMap;
use std::sync::RwLock;

use once_cell::sync::Lazy;

use super::target_iface::TraceObjectInterface;

/// The set of builtin interface categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum InterfaceCategory {
    /// Process-level interfaces.
    Process,
    /// Thread-level interfaces.
    Thread,
    /// Memory region interfaces.
    Memory,
    /// Register container interfaces.
    Register,
    /// Module/library interfaces.
    Module,
    /// Section interfaces.
    Section,
    /// Breakpoint interfaces.
    Breakpoint,
    /// Environment/configuration interfaces.
    Environment,
    /// Platform-specific extensions.
    Extension,
}

/// Metadata about a registered builtin interface.
#[derive(Debug, Clone)]
pub struct InterfaceRegistration {
    /// The interface name (e.g., "ghidra.trace.target.TraceProcess").
    pub name: String,
    /// The category this interface belongs to.
    pub category: InterfaceCategory,
    /// A brief description.
    pub description: String,
    /// The schema name this interface uses.
    pub schema_name: String,
    /// Whether this interface is enabled by default.
    pub enabled_by_default: bool,
}

impl InterfaceRegistration {
    /// Create a new registration.
    pub fn new(
        name: impl Into<String>,
        category: InterfaceCategory,
        description: impl Into<String>,
        schema_name: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            category,
            description: description.into(),
            schema_name: schema_name.into(),
            enabled_by_default: true,
        }
    }
}

/// Factory and registry for builtin trace object interfaces.
///
/// This manages the set of interfaces that define what kinds of objects
/// can exist in a trace and how they behave.
pub struct BuiltinInterfaceFactory {
    /// Registered interfaces.
    registrations: BTreeMap<String, InterfaceRegistration>,
}

impl BuiltinInterfaceFactory {
    /// Create a new factory with all builtin interfaces registered.
    pub fn new() -> Self {
        let mut factory = Self {
            registrations: BTreeMap::new(),
        };
        factory.register_builtins();
        factory
    }

    /// Register the standard builtin interfaces.
    fn register_builtins(&mut self) {
        self.register(InterfaceRegistration::new(
            "ghidra.trace.target.TraceProcess",
            InterfaceCategory::Process,
            "Represents an OS process in the trace",
            "Process",
        ));
        self.register(InterfaceRegistration::new(
            "ghidra.trace.target.TraceThread",
            InterfaceCategory::Thread,
            "Represents a thread within a process",
            "Thread",
        ));
        self.register(InterfaceRegistration::new(
            "ghidra.trace.target.TraceMemoryRegion",
            InterfaceCategory::Memory,
            "Represents a mapped memory region",
            "MemoryRegion",
        ));
        self.register(InterfaceRegistration::new(
            "ghidra.trace.target.TraceRegisterBank",
            InterfaceCategory::Register,
            "Represents a bank of CPU registers",
            "RegisterBank",
        ));
        self.register(InterfaceRegistration::new(
            "ghidra.trace.target.TraceModule",
            InterfaceCategory::Module,
            "Represents a loaded module/library",
            "Module",
        ));
        self.register(InterfaceRegistration::new(
            "ghidra.trace.target.TraceSection",
            InterfaceCategory::Section,
            "Represents a section within a module",
            "Section",
        ));
        self.register(InterfaceRegistration::new(
            "ghidra.trace.target.TraceBreakpointSpec",
            InterfaceCategory::Breakpoint,
            "Represents a breakpoint specification",
            "BreakpointSpec",
        ));
        self.register(InterfaceRegistration::new(
            "ghidra.trace.target.TraceEnvironment",
            InterfaceCategory::Environment,
            "Represents the trace environment/configuration",
            "Environment",
        ));
    }

    /// Register a new interface.
    pub fn register(&mut self, registration: InterfaceRegistration) {
        self.registrations
            .insert(registration.name.clone(), registration);
    }

    /// Get a registration by name.
    pub fn get(&self, name: &str) -> Option<&InterfaceRegistration> {
        self.registrations.get(name)
    }

    /// Get all registrations for a category.
    pub fn by_category(&self, category: InterfaceCategory) -> Vec<&InterfaceRegistration> {
        self.registrations
            .values()
            .filter(|r| r.category == category)
            .collect()
    }

    /// Get all registration names.
    pub fn names(&self) -> Vec<&str> {
        self.registrations.keys().map(|s| s.as_str()).collect()
    }

    /// Get all registrations.
    pub fn all(&self) -> Vec<&InterfaceRegistration> {
        self.registrations.values().collect()
    }

    /// Check if a given interface name is registered.
    pub fn is_registered(&self, name: &str) -> bool {
        self.registrations.contains_key(name)
    }

    /// Get the number of registered interfaces.
    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    /// Check if the factory has no registrations.
    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }
}

impl Default for BuiltinInterfaceFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// Global singleton for the builtin interface factory.
static GLOBAL_FACTORY: Lazy<RwLock<BuiltinInterfaceFactory>> =
    Lazy::new(|| RwLock::new(BuiltinInterfaceFactory::new()));

/// Get the global builtin interface factory.
pub fn global_factory() -> &'static RwLock<BuiltinInterfaceFactory> {
    &GLOBAL_FACTORY
}

/// Check if an interface name is a known builtin.
pub fn is_builtin_interface(name: &str) -> bool {
    GLOBAL_FACTORY
        .read()
        .map(|f| f.is_registered(name))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_factory_has_process() {
        let factory = BuiltinInterfaceFactory::new();
        assert!(factory.is_registered("ghidra.trace.target.TraceProcess"));
        let reg = factory.get("ghidra.trace.target.TraceProcess").unwrap();
        assert_eq!(reg.category, InterfaceCategory::Process);
    }

    #[test]
    fn test_builtin_factory_has_all_core() {
        let factory = BuiltinInterfaceFactory::new();
        let names = factory.names();
        assert!(names.contains(&"ghidra.trace.target.TraceProcess"));
        assert!(names.contains(&"ghidra.trace.target.TraceThread"));
        assert!(names.contains(&"ghidra.trace.target.TraceMemoryRegion"));
        assert!(names.contains(&"ghidra.trace.target.TraceRegisterBank"));
        assert!(names.contains(&"ghidra.trace.target.TraceModule"));
        assert!(names.contains(&"ghidra.trace.target.TraceBreakpointSpec"));
    }

    #[test]
    fn test_by_category() {
        let factory = BuiltinInterfaceFactory::new();
        let process_ifaces = factory.by_category(InterfaceCategory::Process);
        assert!(!process_ifaces.is_empty());
        assert!(process_ifaces.iter().all(|r| r.category == InterfaceCategory::Process));
    }

    #[test]
    fn test_custom_registration() {
        let mut factory = BuiltinInterfaceFactory::new();
        factory.register(InterfaceRegistration::new(
            "custom.MyInterface",
            InterfaceCategory::Extension,
            "Custom extension interface",
            "MySchema",
        ));
        assert!(factory.is_registered("custom.MyInterface"));
    }

    #[test]
    fn test_global_factory() {
        assert!(is_builtin_interface("ghidra.trace.target.TraceProcess"));
        assert!(!is_builtin_interface("nonexistent.Interface"));
    }
}
