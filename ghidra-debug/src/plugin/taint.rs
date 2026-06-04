//! Taint analysis types for trace-backed emulation.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.taint` package.
//! Provides types for taint tracking in emulated execution, including
//! integration with external tools like angr.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A key-value pair used in taint analysis metadata.
///
/// Ported from Ghidra's `ExtKeyValue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtKeyValue {
    /// The key.
    pub key: String,
    /// The value (JSON).
    pub value: serde_json::Value,
}

impl ExtKeyValue {
    /// Create a new key-value pair.
    pub fn new(key: impl Into<String>, value: serde_json::Value) -> Self {
        Self {
            key: key.into(),
            value,
        }
    }

    /// Create a string-valued pair.
    pub fn string(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: serde_json::Value::String(value.into()),
        }
    }

    /// Create an integer-valued pair.
    pub fn integer(key: impl Into<String>, value: i64) -> Self {
        Self {
            key: key.into(),
            value: serde_json::Value::Number(value.into()),
        }
    }
}

/// The taint state of a memory location or register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintStatus {
    /// Not tainted (clean).
    Clean,
    /// Tainted (derived from a tainted source).
    Tainted,
    /// Taint status is unknown.
    Unknown,
}

impl TaintStatus {
    /// Whether this location is tainted.
    pub fn is_tainted(&self) -> bool {
        matches!(self, Self::Tainted)
    }
}

/// A taint record for a specific memory location or register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintRecord {
    /// The address or register name.
    pub location: String,
    /// The taint status.
    pub status: TaintStatus,
    /// The source of the taint (e.g., "read from stdin").
    pub source: Option<String>,
    /// Additional metadata.
    pub metadata: Vec<ExtKeyValue>,
}

impl TaintRecord {
    /// Create a new taint record.
    pub fn new(location: impl Into<String>, status: TaintStatus) -> Self {
        Self {
            location: location.into(),
            status,
            source: None,
            metadata: Vec::new(),
        }
    }

    /// Set the taint source.
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Add metadata.
    pub fn with_metadata(mut self, kv: ExtKeyValue) -> Self {
        self.metadata.push(kv);
        self
    }
}

/// Taint state for a pcode emulation session.
///
/// Ported from Ghidra's `EmulatorTaintState`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmulatorTaintState {
    /// Taint records for memory locations.
    pub memory_taint: BTreeMap<u64, TaintStatus>,
    /// Taint records for registers (by name).
    pub register_taint: BTreeMap<String, TaintStatus>,
    /// The current instruction count.
    pub instruction_count: u64,
    /// External metadata.
    pub ext_metadata: Vec<ExtKeyValue>,
}

impl EmulatorTaintState {
    /// Create a new taint state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Taint a memory address.
    pub fn taint_memory(&mut self, addr: u64, source: Option<&str>) {
        self.memory_taint.insert(addr, TaintStatus::Tainted);
        if let Some(s) = source {
            self.ext_metadata.push(ExtKeyValue::string(
                format!("mem_taint_source_{:x}", addr),
                s,
            ));
        }
    }

    /// Clean a memory address.
    pub fn clean_memory(&mut self, addr: u64) {
        self.memory_taint.insert(addr, TaintStatus::Clean);
    }

    /// Get the taint status of a memory address.
    pub fn memory_status(&self, addr: u64) -> TaintStatus {
        self.memory_taint
            .get(&addr)
            .copied()
            .unwrap_or(TaintStatus::Unknown)
    }

    /// Taint a register.
    pub fn taint_register(&mut self, name: impl Into<String>, source: Option<&str>) {
        let name = name.into();
        self.register_taint.insert(name.clone(), TaintStatus::Tainted);
        if let Some(s) = source {
            self.ext_metadata.push(ExtKeyValue::string(
                format!("reg_taint_source_{}", name),
                s,
            ));
        }
    }

    /// Clean a register.
    pub fn clean_register(&mut self, name: &str) {
        self.register_taint
            .insert(name.to_string(), TaintStatus::Clean);
    }

    /// Get the taint status of a register.
    pub fn register_status(&self, name: &str) -> TaintStatus {
        self.register_taint
            .get(name)
            .copied()
            .unwrap_or(TaintStatus::Unknown)
    }

    /// Get all tainted memory addresses.
    pub fn tainted_memory(&self) -> Vec<u64> {
        self.memory_taint
            .iter()
            .filter(|(_, s)| s.is_tainted())
            .map(|(a, _)| *a)
            .collect()
    }

    /// Get all tainted registers.
    pub fn tainted_registers(&self) -> Vec<&str> {
        self.register_taint
            .iter()
            .filter(|(_, s)| s.is_tainted())
            .map(|(n, _)| n.as_str())
            .collect()
    }

    /// Increment instruction count.
    pub fn step(&mut self) {
        self.instruction_count += 1;
    }
}

/// Taint state for angr-based analysis.
///
/// Ported from Ghidra's `AngrTaintState`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AngrTaintState {
    /// The base emulator taint state.
    pub base: EmulatorTaintState,
    /// The angr project path.
    pub project_path: String,
    /// The angr analysis entry state address.
    pub entry_address: u64,
    /// Whether the angr session is running.
    pub running: bool,
    /// Additional angr-specific metadata.
    pub angr_metadata: BTreeMap<String, String>,
}

impl AngrTaintState {
    /// Create a new angr taint state.
    pub fn new(
        project_path: impl Into<String>,
        entry_address: u64,
    ) -> Self {
        Self {
            base: EmulatorTaintState::new(),
            project_path: project_path.into(),
            entry_address,
            running: false,
            angr_metadata: BTreeMap::new(),
        }
    }
}

/// SARIF (Static Analysis Results Interchange Format) key-value writer.
///
/// Ported from Ghidra's `SarifKeyValueWriter`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SarifKeyValueWriter {
    entries: Vec<ExtKeyValue>,
}

impl SarifKeyValueWriter {
    /// Create a new writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry.
    pub fn add(&mut self, entry: ExtKeyValue) {
        self.entries.push(entry);
    }

    /// Get all entries.
    pub fn entries(&self) -> &[ExtKeyValue] {
        &self.entries
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.entries).unwrap_or_default()
    }
}

/// SARIF logical location writer.
///
/// Ported from Ghidra's `SarifLogicalLocationWriter`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SarifLogicalLocationWriter {
    locations: Vec<SarifLogicalLocation>,
}

impl SarifLogicalLocationWriter {
    /// Create a new writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a logical location.
    pub fn add(&mut self, location: SarifLogicalLocation) {
        self.locations.push(location);
    }

    /// Get all locations.
    pub fn locations(&self) -> &[SarifLogicalLocation] {
        &self.locations
    }
}

/// A SARIF logical location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLogicalLocation {
    /// The location name.
    pub name: String,
    /// The fully qualified name.
    pub fully_qualified_name: String,
    /// The kind of location.
    pub kind: String,
    /// The parent index.
    pub parent_index: Option<usize>,
}

impl SarifLogicalLocation {
    /// Create a new logical location.
    pub fn new(
        name: impl Into<String>,
        fqn: impl Into<String>,
        kind: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            fully_qualified_name: fqn.into(),
            kind: kind.into(),
            parent_index: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_status() {
        assert!(TaintStatus::Tainted.is_tainted());
        assert!(!TaintStatus::Clean.is_tainted());
        assert!(!TaintStatus::Unknown.is_tainted());
    }

    #[test]
    fn test_taint_record() {
        let record = TaintRecord::new("RAX", TaintStatus::Tainted)
            .with_source("read from stdin")
            .with_metadata(ExtKeyValue::integer("offset", 0));
        assert!(record.status.is_tainted());
        assert_eq!(record.source.as_deref(), Some("read from stdin"));
    }

    #[test]
    fn test_emulator_taint_state() {
        let mut state = EmulatorTaintState::new();
        state.taint_memory(0x400000, Some("user input"));
        state.taint_register("RAX", Some("derived from tainted mem"));

        assert!(state.memory_status(0x400000).is_tainted());
        assert!(state.register_status("RAX").is_tainted());
        assert!(!state.memory_status(0x500000).is_tainted()); // Unknown

        let tainted_mem = state.tainted_memory();
        assert_eq!(tainted_mem.len(), 1);

        let tainted_regs = state.tainted_registers();
        assert_eq!(tainted_regs.len(), 1);

        state.clean_memory(0x400000);
        assert!(!state.memory_status(0x400000).is_tainted());
    }

    #[test]
    fn test_emulator_taint_step() {
        let mut state = EmulatorTaintState::new();
        assert_eq!(state.instruction_count, 0);
        state.step();
        state.step();
        assert_eq!(state.instruction_count, 2);
    }

    #[test]
    fn test_angr_taint_state() {
        let mut state = AngrTaintState::new("/path/to/binary", 0x400000);
        assert_eq!(state.entry_address, 0x400000);
        assert!(!state.running);
        state.running = true;
        assert!(state.running);
    }

    #[test]
    fn test_ext_key_value() {
        let kv = ExtKeyValue::string("type", "tainted");
        assert_eq!(kv.key, "type");

        let kv = ExtKeyValue::integer("count", 42);
        assert_eq!(kv.value, serde_json::json!(42));
    }

    #[test]
    fn test_sarif_key_value_writer() {
        let mut writer = SarifKeyValueWriter::new();
        writer.add(ExtKeyValue::string("key1", "value1"));
        writer.add(ExtKeyValue::integer("key2", 42));
        assert_eq!(writer.entries().len(), 2);

        let json = writer.to_json();
        assert!(json.contains("key1"));
    }

    #[test]
    fn test_sarif_logical_location() {
        let mut writer = SarifLogicalLocationWriter::new();
        writer.add(SarifLogicalLocation::new("main", "main.elf::main", "function"));
        assert_eq!(writer.locations().len(), 1);
        assert_eq!(writer.locations()[0].kind, "function");
    }

    #[test]
    fn test_emulator_taint_state_serde() {
        let mut state = EmulatorTaintState::new();
        state.taint_memory(0x400000, None);
        let json = serde_json::to_string(&state).unwrap();
        let back: EmulatorTaintState = serde_json::from_str(&json).unwrap();
        assert!(back.memory_status(0x400000).is_tainted());
    }
}
