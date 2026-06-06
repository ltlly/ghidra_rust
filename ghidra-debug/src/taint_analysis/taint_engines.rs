//! Taint engine implementations (Angr and Emulator).
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.taint` package.
//! Provides the engine-specific taint analysis state containers, SARIF
//! output writers, and key-value data extensions for the taint analysis
//! framework.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// TaintEngine -- the taint analysis engine type
// ---------------------------------------------------------------------------

/// The type of taint analysis engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintEngine {
    /// Angr binary analysis framework.
    Angr,
    /// Ghidra's built-in p-code emulator.
    Emulator,
    /// Custom engine.
    Custom,
}

impl TaintEngine {
    /// The engine name used in queries.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Angr => "angr",
            Self::Emulator => "emulator",
            Self::Custom => "custom",
        }
    }

    /// Whether this engine uses an index database.
    pub fn uses_index(&self) -> bool {
        match self {
            Self::Angr => false,
            Self::Emulator => true,
            Self::Custom => true,
        }
    }

    /// The script/interpreter used to run this engine.
    pub fn interpreter(&self) -> &'static str {
        match self {
            Self::Angr => "python",
            Self::Emulator => "ghidra",
            Self::Custom => "custom",
        }
    }
}

impl fmt::Display for TaintEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// TaintLabel -- a taint source or sink label
// ---------------------------------------------------------------------------

/// A label marking a taint source or sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintLabel {
    /// The address of the label.
    pub address: u64,
    /// The label name.
    pub name: String,
    /// Whether this is a source (true) or sink (false).
    pub is_source: bool,
    /// The label type (e.g., "parameter", "return", "memory").
    pub label_type: Option<String>,
    /// Size of the tainted region in bytes.
    pub size: Option<u64>,
}

impl TaintLabel {
    /// Create a new taint label.
    pub fn new(address: u64, name: impl Into<String>, is_source: bool) -> Self {
        Self {
            address,
            name: name.into(),
            is_source,
            label_type: None,
            size: None,
        }
    }

    /// Create a source label.
    pub fn source(address: u64, name: impl Into<String>) -> Self {
        Self::new(address, name, true)
    }

    /// Create a sink label.
    pub fn sink(address: u64, name: impl Into<String>) -> Self {
        Self::new(address, name, false)
    }

    /// Set the label type.
    pub fn with_type(mut self, label_type: impl Into<String>) -> Self {
        self.label_type = Some(label_type.into());
        self
    }

    /// Set the size.
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }
}

// ---------------------------------------------------------------------------
// TaintQuery -- parameters for a taint analysis query
// ---------------------------------------------------------------------------

/// Parameters for building a taint analysis query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintQuery {
    /// The engine to use.
    pub engine: TaintEngine,
    /// Path to the engine executable/script.
    pub engine_path: Option<String>,
    /// Path to the index database file.
    pub index_db_path: Option<String>,
    /// Path to the index directory.
    pub index_directory: Option<String>,
    /// The binary file path.
    pub binary_file: Option<String>,
    /// The base address of the binary.
    pub base_address: Option<u64>,
    /// Source labels.
    pub sources: Vec<TaintLabel>,
    /// Sink labels.
    pub sinks: Vec<TaintLabel>,
    /// Additional parameters.
    pub parameters: Vec<String>,
    /// Engine-specific options.
    pub options: HashMap<String, String>,
}

impl TaintQuery {
    /// Create a new taint query.
    pub fn new(engine: TaintEngine) -> Self {
        Self {
            engine,
            engine_path: None,
            index_db_path: None,
            index_directory: None,
            binary_file: None,
            base_address: None,
            sources: Vec::new(),
            sinks: Vec::new(),
            parameters: Vec::new(),
            options: HashMap::new(),
        }
    }

    /// Set the engine path.
    pub fn with_engine_path(mut self, path: impl Into<String>) -> Self {
        self.engine_path = Some(path.into());
        self
    }

    /// Set the binary file.
    pub fn with_binary_file(mut self, path: impl Into<String>) -> Self {
        self.binary_file = Some(path.into());
        self
    }

    /// Set the base address.
    pub fn with_base_address(mut self, addr: u64) -> Self {
        self.base_address = Some(addr);
        self
    }

    /// Add a source label.
    pub fn add_source(&mut self, label: TaintLabel) {
        self.sources.push(label);
    }

    /// Add a sink label.
    pub fn add_sink(&mut self, label: TaintLabel) {
        self.sinks.push(label);
    }

    /// Add a parameter.
    pub fn add_param(&mut self, param: impl Into<String>) {
        self.parameters.push(param.into());
    }

    /// Build the command-line parameters for this query.
    pub fn build_params(&self) -> Vec<String> {
        let mut params = vec![self.engine.interpreter().to_string()];
        if let Some(ref path) = self.engine_path {
            params.push(path.clone());
        }
        params.extend(self.parameters.clone());
        params
    }

    /// Number of source labels.
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Number of sink labels.
    pub fn sink_count(&self) -> usize {
        self.sinks.len()
    }
}

// ---------------------------------------------------------------------------
// AngrTaintState -- Angr-specific taint analysis state
// ---------------------------------------------------------------------------

/// Container for Angr taint analysis configuration and state.
///
/// Angr is a binary analysis framework that performs symbolic execution
/// to identify taint flows in binaries. This struct holds the configuration
/// and state for running an Angr-based taint analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AngrTaintState {
    /// The engine name (always "angr").
    pub engine_name: String,
    /// Whether the engine uses an index.
    pub uses_index: bool,
    /// The start address for analysis.
    pub start_address: Option<u64>,
    /// The binary file path.
    pub binary_file: Option<String>,
    /// The base address.
    pub base_address: Option<u64>,
    /// Source taint labels.
    pub sources: Vec<TaintLabel>,
    /// Sink taint labels.
    pub sinks: Vec<TaintLabel>,
    /// The executable path.
    pub executable_path: Option<String>,
    /// Additional query parameters.
    pub query_params: Vec<String>,
    /// Engine path override.
    pub engine_path: Option<String>,
}

impl AngrTaintState {
    /// Create a new Angr taint state.
    pub fn new() -> Self {
        Self {
            engine_name: "angr".to_string(),
            uses_index: false,
            start_address: None,
            binary_file: None,
            base_address: None,
            sources: Vec::new(),
            sinks: Vec::new(),
            executable_path: None,
            query_params: Vec::new(),
            engine_path: None,
        }
    }

    /// Build the query parameters for Angr.
    pub fn build_query(&self) -> Vec<String> {
        let mut params = vec!["python".to_string()];
        if let Some(ref path) = self.engine_path {
            params.push(path.clone());
        }
        params.extend(self.query_params.clone());
        params
    }

    /// Add a source label.
    pub fn add_source(&mut self, label: TaintLabel) {
        self.sources.push(label);
    }

    /// Add a sink label.
    pub fn add_sink(&mut self, label: TaintLabel) {
        self.sinks.push(label);
    }

    /// Write the JSON preamble for the Angr query.
    pub fn write_preamble_json(&self) -> String {
        let binary = self
            .binary_file
            .as_deref()
            .unwrap_or("unknown");
        let base = self
            .base_address
            .map(|a| format!("0x{:x}", a))
            .unwrap_or_else(|| "0x0".to_string());
        format!(
            "{{\n\t\"binary_file\":\"{}\",\n\t\"base_address\":\"{}\",\n}}",
            binary, base
        )
    }
}

impl Default for AngrTaintState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EmulatorTaintState -- Emulator-specific taint analysis state
// ---------------------------------------------------------------------------

/// Container for emulator-based taint analysis configuration and state.
///
/// This uses Ghidra's built-in p-code emulator to perform taint analysis
/// by tracking data flow through the program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulatorTaintState {
    /// The engine name (always "emulator").
    pub engine_name: String,
    /// Whether the engine uses an index.
    pub uses_index: bool,
    /// Path to the index database.
    pub index_db_path: Option<String>,
    /// Path to the index directory.
    pub index_directory: Option<String>,
    /// Source taint labels.
    pub sources: Vec<TaintLabel>,
    /// Sink taint labels.
    pub sinks: Vec<TaintLabel>,
    /// The trace key.
    pub trace_key: Option<i64>,
    /// The snap to analyze.
    pub snap: i64,
    /// Maximum steps to execute.
    pub max_steps: u64,
    /// Additional query parameters.
    pub query_params: Vec<String>,
}

impl EmulatorTaintState {
    /// Create a new emulator taint state.
    pub fn new() -> Self {
        Self {
            engine_name: "emulator".to_string(),
            uses_index: true,
            index_db_path: None,
            index_directory: None,
            sources: Vec::new(),
            sinks: Vec::new(),
            trace_key: None,
            snap: 0,
            max_steps: 10000,
            query_params: Vec::new(),
        }
    }

    /// Build the query parameters.
    pub fn build_query(&self) -> Vec<String> {
        let mut params = vec!["ghidra".to_string()];
        params.extend(self.query_params.clone());
        params
    }

    /// Add a source label.
    pub fn add_source(&mut self, label: TaintLabel) {
        self.sources.push(label);
    }

    /// Add a sink label.
    pub fn add_sink(&mut self, label: TaintLabel) {
        self.sinks.push(label);
    }
}

impl Default for EmulatorTaintState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ExtKeyValue -- key-value pair for engine configuration
// ---------------------------------------------------------------------------

/// A key-value pair for engine-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtKeyValue {
    /// The key.
    pub key: String,
    /// The value.
    pub value: String,
    /// Whether this is a required parameter.
    pub required: bool,
    /// Description of the parameter.
    pub description: Option<String>,
}

impl ExtKeyValue {
    /// Create a new key-value pair.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            required: false,
            description: None,
        }
    }

    /// Mark as required.
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

// ---------------------------------------------------------------------------
// SarifLogicalLocation -- SARIF output location
// ---------------------------------------------------------------------------

/// A logical location in SARIF format for taint analysis results.
///
/// SARIF (Static Analysis Results Interchange Format) is used to
/// standardize the output of static analysis tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLogicalLocation {
    /// The kind of logical location (e.g., "function", "module").
    pub kind: String,
    /// The fully qualified name.
    pub name: String,
    /// The parent logical location index.
    pub parent_index: Option<usize>,
    /// Decorated name (e.g., with namespace).
    pub decorated_name: Option<String>,
}

impl SarifLogicalLocation {
    /// Create a new SARIF logical location.
    pub fn new(kind: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            name: name.into(),
            parent_index: None,
            decorated_name: None,
        }
    }

    /// Set the parent index.
    pub fn with_parent(mut self, index: usize) -> Self {
        self.parent_index = Some(index);
        self
    }

    /// Set the decorated name.
    pub fn with_decorated_name(mut self, name: impl Into<String>) -> Self {
        self.decorated_name = Some(name.into());
        self
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> String {
        let parent = self
            .parent_index
            .map(|i| format!("{}", i))
            .unwrap_or_else(|| "null".to_string());
        let decorated = self
            .decorated_name
            .as_deref()
            .unwrap_or("");
        format!(
            "{{\"kind\":\"{}\",\"name\":\"{}\",\"parentIndex\":{},\"decoratedName\":\"{}\"}}",
            self.kind, self.name, parent, decorated
        )
    }
}

// ---------------------------------------------------------------------------
// SarifKeyValueWriter -- writer for SARIF key-value pairs
// ---------------------------------------------------------------------------

/// Writer for producing SARIF key-value output for taint analysis results.
#[derive(Debug, Clone)]
pub struct SarifKeyValueWriter {
    /// The properties being written.
    properties: Vec<(String, String)>,
}

impl SarifKeyValueWriter {
    /// Create a new writer.
    pub fn new() -> Self {
        Self {
            properties: Vec::new(),
        }
    }

    /// Add a key-value property.
    pub fn add(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.properties.push((key.into(), value.into()));
    }

    /// Write to a JSON string.
    pub fn to_json(&self) -> String {
        let entries: Vec<String> = self
            .properties
            .iter()
            .map(|(k, v)| format!("\"{}\":\"{}\"", k, v))
            .collect();
        format!("{{{}}}", entries.join(","))
    }

    /// Get the number of properties.
    pub fn len(&self) -> usize {
        self.properties.len()
    }

    /// Whether the writer has any properties.
    pub fn is_empty(&self) -> bool {
        self.properties.is_empty()
    }
}

impl Default for SarifKeyValueWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_engine() {
        assert_eq!(TaintEngine::Angr.name(), "angr");
        assert_eq!(TaintEngine::Emulator.name(), "emulator");
        assert!(!TaintEngine::Angr.uses_index());
        assert!(TaintEngine::Emulator.uses_index());
        assert_eq!(TaintEngine::Angr.interpreter(), "python");
        assert_eq!(TaintEngine::Emulator.interpreter(), "ghidra");
    }

    #[test]
    fn test_taint_engine_display() {
        assert_eq!(format!("{}", TaintEngine::Angr), "angr");
        assert_eq!(format!("{}", TaintEngine::Emulator), "emulator");
    }

    #[test]
    fn test_taint_label() {
        let src = TaintLabel::source(0x401000, "user_input")
            .with_type("parameter")
            .with_size(4);
        assert!(src.is_source);
        assert_eq!(src.address, 0x401000);
        assert_eq!(src.name, "user_input");
        assert_eq!(src.label_type.as_deref(), Some("parameter"));
        assert_eq!(src.size, Some(4));

        let sink = TaintLabel::sink(0x402000, "strcpy_call");
        assert!(!sink.is_source);
    }

    #[test]
    fn test_taint_query() {
        let mut query = TaintQuery::new(TaintEngine::Angr)
            .with_binary_file("/tmp/test")
            .with_base_address(0x400000);

        query.add_source(TaintLabel::source(0x401000, "src"));
        query.add_sink(TaintLabel::sink(0x402000, "sink"));

        assert_eq!(query.source_count(), 1);
        assert_eq!(query.sink_count(), 1);

        let params = query.build_params();
        assert_eq!(params[0], "python");
    }

    #[test]
    fn test_angr_taint_state() {
        let mut state = AngrTaintState::new();
        assert_eq!(state.engine_name, "angr");
        assert!(!state.uses_index);

        state.add_source(TaintLabel::source(0x401000, "src"));
        state.add_sink(TaintLabel::sink(0x402000, "sink"));
        assert_eq!(state.sources.len(), 1);
        assert_eq!(state.sinks.len(), 1);
    }

    #[test]
    fn test_angr_taint_state_preamble() {
        let state = AngrTaintState {
            binary_file: Some("/tmp/test.elf".to_string()),
            base_address: Some(0x400000),
            ..AngrTaintState::new()
        };
        let json = state.write_preamble_json();
        assert!(json.contains("test.elf"));
        assert!(json.contains("0x400000"));
    }

    #[test]
    fn test_angr_taint_state_build_query() {
        let mut state = AngrTaintState::new();
        state.engine_path = Some("/usr/bin/angr_script.py".to_string());
        state.query_params.push("--verbose".to_string());

        let params = state.build_query();
        assert_eq!(params[0], "python");
        assert_eq!(params[1], "/usr/bin/angr_script.py");
        assert_eq!(params[2], "--verbose");
    }

    #[test]
    fn test_emulator_taint_state() {
        let mut state = EmulatorTaintState::new();
        assert_eq!(state.engine_name, "emulator");
        assert!(state.uses_index);
        assert_eq!(state.max_steps, 10000);

        state.trace_key = Some(42);
        state.snap = 5;
        state.add_source(TaintLabel::source(0x401000, "input"));

        assert_eq!(state.sources.len(), 1);
        assert_eq!(state.trace_key, Some(42));
    }

    #[test]
    fn test_emulator_taint_state_build_query() {
        let state = EmulatorTaintState::new();
        let params = state.build_query();
        assert_eq!(params[0], "ghidra");
    }

    #[test]
    fn test_ext_key_value() {
        let kv = ExtKeyValue::new("timeout", "30")
            .required()
            .with_description("Analysis timeout in seconds");
        assert_eq!(kv.key, "timeout");
        assert_eq!(kv.value, "30");
        assert!(kv.required);
        assert!(kv.description.is_some());
    }

    #[test]
    fn test_sarif_logical_location() {
        let loc = SarifLogicalLocation::new("function", "main")
            .with_parent(0)
            .with_decorated_name("main(int, char**)");

        let json = loc.to_json();
        assert!(json.contains("function"));
        assert!(json.contains("main"));
        assert!(json.contains("main(int, char**)"));
    }

    #[test]
    fn test_sarif_key_value_writer() {
        let mut writer = SarifKeyValueWriter::new();
        assert!(writer.is_empty());

        writer.add("ruleId", "TAINT_FLOW");
        writer.add("level", "warning");
        assert_eq!(writer.len(), 2);

        let json = writer.to_json();
        assert!(json.contains("ruleId"));
        assert!(json.contains("TAINT_FLOW"));
        assert!(json.contains("level"));
        assert!(json.contains("warning"));
    }

    #[test]
    fn test_taint_query_no_engine_path() {
        let query = TaintQuery::new(TaintEngine::Emulator);
        let params = query.build_params();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], "ghidra");
    }

    #[test]
    fn test_angr_taint_state_default() {
        let state = AngrTaintState::default();
        assert_eq!(state.engine_name, "angr");
        assert!(state.sources.is_empty());
        assert!(state.sinks.is_empty());
    }

    #[test]
    fn test_emulator_taint_state_default() {
        let state = EmulatorTaintState::default();
        assert_eq!(state.engine_name, "emulator");
        assert!(state.sources.is_empty());
        assert!(state.sinks.is_empty());
    }

    #[test]
    fn test_sarif_location_no_optional() {
        let loc = SarifLogicalLocation::new("module", "libc.so");
        let json = loc.to_json();
        assert!(json.contains("module"));
        assert!(json.contains("libc.so"));
        assert!(json.contains("null"));
    }

    #[test]
    fn test_taint_label_without_optional() {
        let label = TaintLabel::source(0x1000, "basic");
        assert!(label.label_type.is_none());
        assert!(label.size.is_none());
    }
}
