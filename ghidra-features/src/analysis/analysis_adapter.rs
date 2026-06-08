//! Analyzer adapter and wrapper types.
//!
//! Ported from `ghidra.app.plugin.core.analysis.AnalyzerAdapter`.
//!
//! Provides adapter types that wrap analyzer functionality for use in
//! different contexts, such as headless analysis, background processing,
//! and test harnesses.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// AnalyzerDescriptor -- lightweight analyzer metadata
// ---------------------------------------------------------------------------

/// Metadata describing an analyzer without holding a reference to the
/// analyzer itself.
///
/// This is useful for serialization, option registration, and UI display
/// where the analyzer implementation may not be available.
#[derive(Debug, Clone)]
pub struct AnalyzerDescriptor {
    /// Unique analyzer name (must not contain periods).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Whether the analyzer is enabled by default.
    pub default_enabled: bool,
    /// Whether this is a prototype (experimental) analyzer.
    pub is_prototype: bool,
    /// The analysis type classification.
    pub analyzer_type: AnalyzerType,
    /// Priority (lower = higher priority).
    pub priority: i32,
    /// Whether the analyzer supports one-time analysis.
    pub supports_one_time: bool,
    /// Registered option names and their default values.
    pub options: HashMap<String, AnalyzerOptionValue>,
}

/// Classification of analyzer by what kind of analysis it performs.
///
/// Ported from `AnalyzerType` enum in Ghidra's analysis framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnalyzerType {
    /// Analyzes raw bytes in memory.
    ByteAnalyzer,
    /// Analyzes disassembled instructions.
    InstructionAnalyzer,
    /// Analyzes defined functions.
    FunctionAnalyzer,
    /// Analyzes function modifier changes.
    FunctionModifiersAnalyzer,
    /// Analyzes function signature changes.
    FunctionSignaturesAnalyzer,
    /// Analyzes defined data.
    DataAnalyzer,
}

impl fmt::Display for AnalyzerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ByteAnalyzer => write!(f, "Byte Analyzer"),
            Self::InstructionAnalyzer => write!(f, "Instruction Analyzer"),
            Self::FunctionAnalyzer => write!(f, "Function Analyzer"),
            Self::FunctionModifiersAnalyzer => write!(f, "Function Modifiers Analyzer"),
            Self::FunctionSignaturesAnalyzer => write!(f, "Function Signatures Analyzer"),
            Self::DataAnalyzer => write!(f, "Data Analyzer"),
        }
    }
}

/// Possible option value types for analyzer options.
#[derive(Debug, Clone)]
pub enum AnalyzerOptionValue {
    /// Boolean option.
    Bool(bool),
    /// Integer option.
    Int(i64),
    /// String option.
    String(String),
    /// Enum/choice option with a list of valid values.
    Choice { selected: String, choices: Vec<String> },
}

impl AnalyzerDescriptor {
    /// Create a new analyzer descriptor.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        analyzer_type: AnalyzerType,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            default_enabled: true,
            is_prototype: false,
            analyzer_type,
            priority: 100,
            supports_one_time: false,
            options: HashMap::new(),
        }
    }

    /// Set the default enabled state.
    pub fn with_default_enabled(mut self, enabled: bool) -> Self {
        self.default_enabled = enabled;
        self
    }

    /// Mark as a prototype analyzer.
    pub fn with_prototype(mut self, is_prototype: bool) -> Self {
        self.is_prototype = is_prototype;
        self
    }

    /// Set the priority.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Mark as supporting one-time analysis.
    pub fn with_one_time_support(mut self, supports: bool) -> Self {
        self.supports_one_time = supports;
        self
    }

    /// Add an option with a default value.
    pub fn with_option(
        mut self,
        name: impl Into<String>,
        default: AnalyzerOptionValue,
    ) -> Self {
        self.options.insert(name.into(), default);
        self
    }

    /// Validate the analyzer name (must not contain periods).
    pub fn validate_name(&self) -> Result<(), String> {
        if self.name.contains('.') {
            Err(format!(
                "Analyzer name may not contain a period: {}",
                self.name
            ))
        } else if self.name.is_empty() {
            Err("Analyzer name may not be empty".to_string())
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// AnalyzerAdapter -- wraps an AnalyzerDescriptor for scheduling
// ---------------------------------------------------------------------------

/// Wraps an [`AnalyzerDescriptor`] for use with the analysis scheduling
/// infrastructure.
///
/// The adapter manages the mutable state associated with an analyzer
/// during an analysis session: the set of addresses to add, the set
/// to remove, and the scheduled/running state.
///
/// Ported from the scheduling logic in `AnalysisScheduler.java`.
#[derive(Debug)]
pub struct AnalyzerAdapter {
    /// The analyzer descriptor.
    descriptor: AnalyzerDescriptor,
    /// Addresses to add (analyze).
    add_set: Vec<(u64, u64)>,
    /// Addresses to remove.
    remove_set: Vec<(u64, u64)>,
    /// Whether this analyzer is currently scheduled for execution.
    scheduled: bool,
    /// Whether this analyzer is enabled.
    enabled: bool,
    /// Cumulative analysis time in milliseconds.
    total_time_ms: u64,
}

impl AnalyzerAdapter {
    /// Create a new adapter from a descriptor.
    pub fn new(descriptor: AnalyzerDescriptor) -> Self {
        let enabled = descriptor.default_enabled;
        Self {
            descriptor,
            add_set: Vec::new(),
            remove_set: Vec::new(),
            scheduled: false,
            enabled,
            total_time_ms: 0,
        }
    }

    /// Get the analyzer name.
    pub fn name(&self) -> &str {
        &self.descriptor.name
    }

    /// Get the analyzer descriptor.
    pub fn descriptor(&self) -> &AnalyzerDescriptor {
        &self.descriptor
    }

    /// Get the analyzer type.
    pub fn analyzer_type(&self) -> AnalyzerType {
        self.descriptor.analyzer_type
    }

    /// Get the priority.
    pub fn priority(&self) -> i32 {
        self.descriptor.priority
    }

    /// Whether this analyzer is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether this adapter has pending work (add or remove sets non-empty).
    pub fn has_pending_work(&self) -> bool {
        !self.add_set.is_empty() || !self.remove_set.is_empty()
    }

    /// Whether the analyzer is currently scheduled.
    pub fn is_scheduled(&self) -> bool {
        self.scheduled
    }

    /// Add an address range to the analysis set.
    pub fn add_address_range(&mut self, start: u64, end: u64) {
        if self.enabled {
            self.add_set.push((start, end));
            self.scheduled = true;
        }
    }

    /// Add a single address to the analysis set.
    pub fn add_address(&mut self, addr: u64) {
        self.add_address_range(addr, addr + 1);
    }

    /// Mark an address range for removal.
    pub fn remove_address_range(&mut self, start: u64, end: u64) {
        if self.enabled {
            self.remove_set.push((start, end));
            self.scheduled = true;
        }
    }

    /// Drain the pending add set, returning the ranges.
    pub fn drain_add_set(&mut self) -> Vec<(u64, u64)> {
        std::mem::take(&mut self.add_set)
    }

    /// Drain the pending remove set, returning the ranges.
    pub fn drain_remove_set(&mut self) -> Vec<(u64, u64)> {
        std::mem::take(&mut self.remove_set)
    }

    /// Mark the analyzer as no longer scheduled (after execution).
    pub fn mark_executed(&mut self) {
        self.scheduled = false;
    }

    /// Record analysis time in milliseconds.
    pub fn add_time(&mut self, ms: u64) {
        self.total_time_ms += ms;
    }

    /// Get cumulative analysis time in milliseconds.
    pub fn total_time_ms(&self) -> u64 {
        self.total_time_ms
    }

    /// Discard all pending work (add and remove sets).
    pub fn discard_pending(&mut self) {
        self.add_set.clear();
        self.remove_set.clear();
        self.scheduled = false;
    }
}

impl fmt::Display for AnalyzerAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AnalyzerAdapter({}, type={}, priority={}, enabled={})",
            self.descriptor.name, self.descriptor.analyzer_type, self.descriptor.priority, self.enabled
        )
    }
}

// ---------------------------------------------------------------------------
// AnalyzerAdapterRegistry -- manages all analyzer adapters
// ---------------------------------------------------------------------------

/// Registry of all analyzer adapters in an analysis session.
#[derive(Debug)]
pub struct AnalyzerAdapterRegistry {
    adapters: Vec<AnalyzerAdapter>,
}

impl AnalyzerAdapterRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            adapters: Vec::new(),
        }
    }

    /// Register an analyzer adapter.
    pub fn register(&mut self, adapter: AnalyzerAdapter) {
        self.adapters.push(adapter);
    }

    /// Get the number of registered adapters.
    pub fn len(&self) -> usize {
        self.adapters.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }

    /// Find an adapter by name.
    pub fn find_by_name(&self, name: &str) -> Option<&AnalyzerAdapter> {
        self.adapters.iter().find(|a| a.name() == name)
    }

    /// Find a mutable adapter by name.
    pub fn find_by_name_mut(&mut self, name: &str) -> Option<&mut AnalyzerAdapter> {
        self.adapters.iter_mut().find(|a| a.name() == name)
    }

    /// Get all adapters of a specific type.
    pub fn by_type(&self, analyzer_type: AnalyzerType) -> Vec<&AnalyzerAdapter> {
        self.adapters
            .iter()
            .filter(|a| a.analyzer_type() == analyzer_type)
            .collect()
    }

    /// Get all enabled adapters.
    pub fn enabled_adapters(&self) -> Vec<&AnalyzerAdapter> {
        self.adapters.iter().filter(|a| a.is_enabled()).collect()
    }

    /// Get all adapters that have pending work.
    pub fn pending_adapters(&self) -> Vec<&AnalyzerAdapter> {
        self.adapters.iter().filter(|a| a.has_pending_work()).collect()
    }

    /// Get all adapter names.
    pub fn names(&self) -> Vec<&str> {
        self.adapters.iter().map(|a| a.name()).collect()
    }

    /// Clear all pending work from all adapters.
    pub fn clear_all_pending(&mut self) {
        for adapter in &mut self.adapters {
            adapter.discard_pending();
        }
    }

    /// Get a slice of all adapters.
    pub fn all(&self) -> &[AnalyzerAdapter] {
        &self.adapters
    }

    /// Get a mutable slice of all adapters.
    pub fn all_mut(&mut self) -> &mut [AnalyzerAdapter] {
        &mut self.adapters
    }
}

impl Default for AnalyzerAdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_descriptor(name: &str, atype: AnalyzerType) -> AnalyzerDescriptor {
        AnalyzerDescriptor::new(name, format!("{} description", name), atype)
            .with_priority(50)
    }

    #[test]
    fn test_analyzer_descriptor_creation() {
        let desc = make_descriptor("TestAnalyzer", AnalyzerType::FunctionAnalyzer);
        assert_eq!(desc.name, "TestAnalyzer");
        assert_eq!(desc.analyzer_type, AnalyzerType::FunctionAnalyzer);
        assert!(desc.default_enabled);
        assert!(!desc.is_prototype);
        assert_eq!(desc.priority, 50);
    }

    #[test]
    fn test_analyzer_descriptor_validate_name() {
        let desc = make_descriptor("ValidName", AnalyzerType::ByteAnalyzer);
        assert!(desc.validate_name().is_ok());

        let desc = make_descriptor("Invalid.Name", AnalyzerType::ByteAnalyzer);
        assert!(desc.validate_name().is_err());

        let desc = AnalyzerDescriptor::new("", "empty", AnalyzerType::ByteAnalyzer);
        assert!(desc.validate_name().is_err());
    }

    #[test]
    fn test_analyzer_descriptor_builder() {
        let desc = AnalyzerDescriptor::new("Test", "desc", AnalyzerType::DataAnalyzer)
            .with_default_enabled(false)
            .with_prototype(true)
            .with_priority(10)
            .with_one_time_support(true)
            .with_option("max_depth", AnalyzerOptionValue::Int(100));

        assert!(!desc.default_enabled);
        assert!(desc.is_prototype);
        assert_eq!(desc.priority, 10);
        assert!(desc.supports_one_time);
        assert!(desc.options.contains_key("max_depth"));
    }

    #[test]
    fn test_analyzer_type_display() {
        assert_eq!(AnalyzerType::ByteAnalyzer.to_string(), "Byte Analyzer");
        assert_eq!(
            AnalyzerType::FunctionAnalyzer.to_string(),
            "Function Analyzer"
        );
        assert_eq!(
            AnalyzerType::DataAnalyzer.to_string(),
            "Data Analyzer"
        );
    }

    #[test]
    fn test_adapter_basic() {
        let desc = make_descriptor("Test", AnalyzerType::InstructionAnalyzer);
        let mut adapter = AnalyzerAdapter::new(desc);

        assert_eq!(adapter.name(), "Test");
        assert!(adapter.is_enabled());
        assert!(!adapter.has_pending_work());

        adapter.add_address_range(0x1000, 0x2000);
        assert!(adapter.has_pending_work());

        let add_set = adapter.drain_add_set();
        assert_eq!(add_set, vec![(0x1000, 0x2000)]);
        assert!(!adapter.has_pending_work());
    }

    #[test]
    fn test_adapter_disabled_ignores_add() {
        let desc = make_descriptor("Test", AnalyzerType::ByteAnalyzer);
        let mut adapter = AnalyzerAdapter::new(desc);
        adapter.set_enabled(false);

        adapter.add_address(0x1000);
        assert!(!adapter.has_pending_work());
    }

    #[test]
    fn test_adapter_timing() {
        let desc = make_descriptor("Test", AnalyzerType::ByteAnalyzer);
        let mut adapter = AnalyzerAdapter::new(desc);

        adapter.add_time(100);
        adapter.add_time(200);
        assert_eq!(adapter.total_time_ms(), 300);
    }

    #[test]
    fn test_adapter_discard() {
        let desc = make_descriptor("Test", AnalyzerType::ByteAnalyzer);
        let mut adapter = AnalyzerAdapter::new(desc);

        adapter.add_address(0x1000);
        adapter.remove_address_range(0x2000, 0x3000);
        assert!(adapter.has_pending_work());

        adapter.discard_pending();
        assert!(!adapter.has_pending_work());
        assert!(!adapter.is_scheduled());
    }

    #[test]
    fn test_registry() {
        let mut registry = AnalyzerAdapterRegistry::new();
        assert!(registry.is_empty());

        let desc1 = make_descriptor("Analyzer1", AnalyzerType::FunctionAnalyzer);
        let desc2 = make_descriptor("Analyzer2", AnalyzerType::DataAnalyzer);
        let desc3 = make_descriptor("Analyzer3", AnalyzerType::FunctionAnalyzer);

        registry.register(AnalyzerAdapter::new(desc1));
        registry.register(AnalyzerAdapter::new(desc2));
        registry.register(AnalyzerAdapter::new(desc3));

        assert_eq!(registry.len(), 3);
        assert!(registry.find_by_name("Analyzer1").is_some());
        assert!(registry.find_by_name("nonexistent").is_none());

        let func_analyzers = registry.by_type(AnalyzerType::FunctionAnalyzer);
        assert_eq!(func_analyzers.len(), 2);

        let enabled = registry.enabled_adapters();
        assert_eq!(enabled.len(), 3);

        let names = registry.names();
        assert_eq!(names, vec!["Analyzer1", "Analyzer2", "Analyzer3"]);
    }

    #[test]
    fn test_registry_find_mut() {
        let mut registry = AnalyzerAdapterRegistry::new();
        let desc = make_descriptor("Test", AnalyzerType::ByteAnalyzer);
        registry.register(AnalyzerAdapter::new(desc));

        let adapter = registry.find_by_name_mut("Test").unwrap();
        adapter.set_enabled(false);
        assert!(!registry.find_by_name("Test").unwrap().is_enabled());
    }

    #[test]
    fn test_registry_pending() {
        let mut registry = AnalyzerAdapterRegistry::new();
        let desc1 = make_descriptor("A", AnalyzerType::ByteAnalyzer);
        let desc2 = make_descriptor("B", AnalyzerType::ByteAnalyzer);
        registry.register(AnalyzerAdapter::new(desc1));
        registry.register(AnalyzerAdapter::new(desc2));

        registry.find_by_name_mut("A").unwrap().add_address(0x1000);
        assert_eq!(registry.pending_adapters().len(), 1);

        registry.clear_all_pending();
        assert_eq!(registry.pending_adapters().len(), 0);
    }
}
