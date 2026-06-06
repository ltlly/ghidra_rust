//! Taint analysis state types and SARIF output.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.taint` package.
//! Provides emulator taint state tracking (for angr and custom analyses)
//! and SARIF format output for taint analysis results.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from taint analysis.
#[derive(Debug, Error)]
pub enum TaintError {
    /// Error during taint propagation.
    #[error("Taint propagation error: {0}")]
    Propagation(String),
    /// Error reading/writing taint state.
    #[error("Taint state error: {0}")]
    State(String),
    /// Error writing SARIF output.
    #[error("SARIF output error: {0}")]
    SarifOutput(String),
}

// ---------------------------------------------------------------------------
// EmulatorTaintState
// ---------------------------------------------------------------------------

/// Taint state for a single memory location or register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintLevel {
    /// Not tainted (clean).
    Clean,
    /// Tainted by user input.
    UserInput,
    /// Tainted by network data.
    Network,
    /// Tainted by file input.
    FileInput,
    /// Tainted by environment variable.
    Environment,
    /// Taint level is unknown.
    Unknown,
}

impl TaintLevel {
    /// Whether this taint level indicates tainted data.
    pub fn is_tainted(&self) -> bool {
        !matches!(self, TaintLevel::Clean)
    }

    /// Combine two taint levels (takes the more severe one).
    pub fn combine(self, other: Self) -> Self {
        match (self, other) {
            (TaintLevel::Clean, x) | (x, TaintLevel::Clean) => x,
            (TaintLevel::Unknown, _) | (_, TaintLevel::Unknown) => TaintLevel::Unknown,
            _ => self, // Keep the first non-clean, non-unknown taint
        }
    }
}

/// Taint state for a memory or register address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintEntry {
    /// The address (memory or register offset).
    pub address: u64,
    /// The taint level.
    pub level: TaintLevel,
    /// Number of bytes tainted from this address.
    pub size: u64,
    /// Source of the taint (e.g., "read from stdin").
    pub source: Option<String>,
}

/// Emulator taint state tracking tainted values across execution.
///
/// Ported from Ghidra's `EmulatorTaintState`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmulatorTaintState {
    /// Per-address taint entries.
    entries: BTreeMap<u64, TaintEntry>,
    /// Execution step counter.
    step_count: u64,
    /// Total number of tainted operations.
    tainted_ops: u64,
}

impl EmulatorTaintState {
    /// Create a new empty taint state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark an address as tainted.
    pub fn set_taint(&mut self, address: u64, level: TaintLevel, size: u64, source: Option<String>) {
        self.entries.insert(address, TaintEntry { address, level, size, source });
    }

    /// Get the taint level at an address.
    pub fn get_taint(&self, address: u64) -> TaintLevel {
        self.entries
            .get(&address)
            .map(|e| e.level)
            .unwrap_or(TaintLevel::Clean)
    }

    /// Check if an address is tainted.
    pub fn is_tainted(&self, address: u64) -> bool {
        self.get_taint(address).is_tainted()
    }

    /// Get all tainted entries.
    pub fn tainted_entries(&self) -> Vec<&TaintEntry> {
        self.entries.values().filter(|e| e.level.is_tainted()).collect()
    }

    /// Record a step.
    pub fn record_step(&mut self) {
        self.step_count += 1;
    }

    /// Record a tainted operation.
    pub fn record_tainted_op(&mut self) {
        self.tainted_ops += 1;
    }

    /// Get the step count.
    pub fn step_count(&self) -> u64 {
        self.step_count
    }

    /// Get the number of tainted operations.
    pub fn tainted_ops(&self) -> u64 {
        self.tainted_ops
    }

    /// Clear all taint state.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.step_count = 0;
        self.tainted_ops = 0;
    }

    /// Get the total number of tainted bytes.
    pub fn total_tainted_bytes(&self) -> u64 {
        self.entries
            .values()
            .filter(|e| e.level.is_tainted())
            .map(|e| e.size)
            .sum()
    }
}

// ---------------------------------------------------------------------------
// AngrTaintState
// ---------------------------------------------------------------------------

/// Angr-compatible taint state for symbolic/taint analysis integration.
///
/// Ported from Ghidra's `AngrTaintState`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AngrTaintState {
    /// Base emulator taint state.
    pub base: EmulatorTaintState,
    /// Symbolic memory map (address -> symbolic variable name).
    symbolic_vars: BTreeMap<u64, String>,
    /// Constraints collected during analysis.
    constraints: Vec<String>,
}

impl AngrTaintState {
    /// Create a new angr taint state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark an address as a symbolic variable.
    pub fn set_symbolic(&mut self, address: u64, var_name: impl Into<String>) {
        self.symbolic_vars.insert(address, var_name.into());
    }

    /// Check if an address is symbolic.
    pub fn is_symbolic(&self, address: u64) -> bool {
        self.symbolic_vars.contains_key(&address)
    }

    /// Get the symbolic variable name at an address.
    pub fn symbolic_name(&self, address: u64) -> Option<&str> {
        self.symbolic_vars.get(&address).map(|s| s.as_str())
    }

    /// Add a constraint.
    pub fn add_constraint(&mut self, constraint: impl Into<String>) {
        self.constraints.push(constraint.into());
    }

    /// Get all constraints.
    pub fn constraints(&self) -> &[String] {
        &self.constraints
    }

    /// Get all symbolic variable mappings.
    pub fn symbolic_vars(&self) -> &BTreeMap<u64, String> {
        &self.symbolic_vars
    }
}

// ---------------------------------------------------------------------------
// SARIF Output
// ---------------------------------------------------------------------------

/// A key-value pair for SARIF output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtKeyValue {
    /// The key.
    pub key: String,
    /// The value.
    pub value: String,
}

/// SARIF key-value writer for taint analysis results.
///
/// Ported from Ghidra's `SarifKeyValueWriter`.
#[derive(Debug, Default)]
pub struct SarifKeyValueWriter {
    entries: Vec<ExtKeyValue>,
}

impl SarifKeyValueWriter {
    /// Create a new writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key-value entry.
    pub fn add(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.entries.push(ExtKeyValue {
            key: key.into(),
            value: value.into(),
        });
    }

    /// Get all entries.
    pub fn entries(&self) -> &[ExtKeyValue] {
        &self.entries
    }

    /// Serialize entries to JSON.
    pub fn to_json(&self) -> Result<String, TaintError> {
        serde_json::to_string_pretty(&self.entries).map_err(|e| TaintError::SarifOutput(e.to_string()))
    }
}

/// A logical location entry for SARIF output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalLocation {
    /// The kind of logical location (e.g., "function", "block").
    pub kind: String,
    /// The fully qualified name.
    pub name: String,
    /// Optional parent index.
    pub parent_index: Option<usize>,
}

/// SARIF logical location writer.
///
/// Ported from Ghidra's `SarifLogicalLocationWriter`.
#[derive(Debug, Default)]
pub struct SarifLogicalLocationWriter {
    locations: Vec<LogicalLocation>,
}

impl SarifLogicalLocationWriter {
    /// Create a new writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a logical location.
    pub fn add_location(
        &mut self,
        kind: impl Into<String>,
        name: impl Into<String>,
        parent_index: Option<usize>,
    ) -> usize {
        let index = self.locations.len();
        self.locations.push(LogicalLocation {
            kind: kind.into(),
            name: name.into(),
            parent_index,
        });
        index
    }

    /// Get all locations.
    pub fn locations(&self) -> &[LogicalLocation] {
        &self.locations
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, TaintError> {
        serde_json::to_string_pretty(&self.locations).map_err(|e| TaintError::SarifOutput(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_level_combine() {
        assert_eq!(TaintLevel::Clean.combine(TaintLevel::UserInput), TaintLevel::UserInput);
        assert_eq!(TaintLevel::UserInput.combine(TaintLevel::Clean), TaintLevel::UserInput);
        assert_eq!(TaintLevel::Clean.combine(TaintLevel::Clean), TaintLevel::Clean);
        assert_eq!(TaintLevel::Unknown.combine(TaintLevel::UserInput), TaintLevel::Unknown);
    }

    #[test]
    fn test_taint_level_is_tainted() {
        assert!(!TaintLevel::Clean.is_tainted());
        assert!(TaintLevel::UserInput.is_tainted());
        assert!(TaintLevel::Network.is_tainted());
        assert!(TaintLevel::Unknown.is_tainted());
    }

    #[test]
    fn test_emulator_taint_state() {
        let mut state = EmulatorTaintState::new();
        state.set_taint(0x1000, TaintLevel::UserInput, 4, Some("stdin".to_string()));
        assert!(state.is_tainted(0x1000));
        assert!(!state.is_tainted(0x2000));

        state.record_step();
        state.record_tainted_op();
        assert_eq!(state.step_count(), 1);
        assert_eq!(state.tainted_ops(), 1);
        assert_eq!(state.total_tainted_bytes(), 4);
    }

    #[test]
    fn test_emulator_taint_state_entries() {
        let mut state = EmulatorTaintState::new();
        state.set_taint(0x1000, TaintLevel::Network, 8, None);
        state.set_taint(0x2000, TaintLevel::Clean, 4, None);

        let tainted = state.tainted_entries();
        assert_eq!(tainted.len(), 1);
        assert_eq!(tainted[0].address, 0x1000);
    }

    #[test]
    fn test_emulator_taint_clear() {
        let mut state = EmulatorTaintState::new();
        state.set_taint(0x1000, TaintLevel::UserInput, 4, None);
        state.record_step();
        state.clear();
        assert!(!state.is_tainted(0x1000));
        assert_eq!(state.step_count(), 0);
    }

    #[test]
    fn test_angr_taint_state() {
        let mut angr = AngrTaintState::new();
        angr.base.set_taint(0x1000, TaintLevel::UserInput, 8, None);
        angr.set_symbolic(0x1000, "input_0");
        angr.add_constraint("input_0 > 0");

        assert!(angr.is_symbolic(0x1000));
        assert_eq!(angr.symbolic_name(0x1000), Some("input_0"));
        assert_eq!(angr.constraints().len(), 1);
    }

    #[test]
    fn test_sarif_key_value_writer() {
        let mut writer = SarifKeyValueWriter::new();
        writer.add("tool", "ghidra-taint");
        writer.add("version", "1.0");
        assert_eq!(writer.entries().len(), 2);

        let json = writer.to_json().unwrap();
        assert!(json.contains("ghidra-taint"));
    }

    #[test]
    fn test_sarif_logical_location_writer() {
        let mut writer = SarifLogicalLocationWriter::new();
        let func_idx = writer.add_location("function", "main", None);
        writer.add_location("block", "bb_0x1000", Some(func_idx));

        assert_eq!(writer.locations().len(), 2);
        assert_eq!(writer.locations()[1].parent_index, Some(0));

        let json = writer.to_json().unwrap();
        assert!(json.contains("main"));
    }
}
