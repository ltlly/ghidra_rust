//! Checksum table model, plugin, provider, and task.
//!
//! Ported from `ghidra.app.plugin.core.checksums.ChecksumTableModel`,
//! `ComputeChecksumsPlugin`, `ComputeChecksumsProvider`, and
//! `ComputeChecksumTask`.

use super::{ChecksumRegistry, format_checksum};
use super::commands::ChecksumResult;

// ---------------------------------------------------------------------------
// ChecksumTableModel
// ---------------------------------------------------------------------------

/// Table model for displaying checksum results.
///
/// Ported from `ghidra.app.plugin.core.checksums.ChecksumTableModel`.
#[derive(Debug)]
pub struct ChecksumTableModel {
    /// The checksum results to display.
    results: Vec<ChecksumDisplayRow>,
    /// Whether to display in hex format.
    hex_display: bool,
}

/// A display row in the checksum table.
#[derive(Debug, Clone)]
pub struct ChecksumDisplayRow {
    /// The algorithm name.
    pub name: String,
    /// The formatted checksum value.
    pub value: String,
    /// The raw checksum bytes.
    pub raw_bytes: Vec<u8>,
    /// Whether this algorithm supports decimal display.
    pub supports_decimal: bool,
}

impl ChecksumTableModel {
    /// Column index for the algorithm name.
    pub const NAME_COL: usize = 0;
    /// Column index for the checksum value.
    pub const VALUE_COL: usize = 1;

    /// Create a new table model.
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            hex_display: true,
        }
    }

    /// Add a result to the table.
    pub fn add_result(&mut self, name: impl Into<String>, raw: Vec<u8>, supports_decimal: bool) {
        let name = name.into();
        let value = format_checksum(&raw, self.hex_display, supports_decimal);
        self.results.push(ChecksumDisplayRow {
            name,
            value,
            raw_bytes: raw,
            supports_decimal,
        });
    }

    /// Set the display format (hex or decimal).
    pub fn set_hex_display(&mut self, hex: bool) {
        self.hex_display = hex;
        for row in &mut self.results {
            row.value = format_checksum(&row.raw_bytes, self.hex_display, row.supports_decimal);
        }
    }

    /// Whether display is hex.
    pub fn is_hex_display(&self) -> bool {
        self.hex_display
    }

    /// Get the number of rows.
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Get a row by index.
    pub fn get(&self, index: usize) -> Option<&ChecksumDisplayRow> {
        self.results.get(index)
    }

    /// Find a result by algorithm name.
    pub fn find_by_name(&self, name: &str) -> Option<&ChecksumDisplayRow> {
        self.results.iter().find(|r| r.name == name)
    }

    /// Get all results.
    pub fn results(&self) -> &[ChecksumDisplayRow] {
        &self.results
    }

    /// Get a cell value for display.
    pub fn cell_value(&self, row: usize, col: usize) -> Option<String> {
        let r = self.results.get(row)?;
        Some(match col {
            Self::NAME_COL => r.name.clone(),
            Self::VALUE_COL => r.value.clone(),
            _ => return None,
        })
    }

    /// Get column names.
    pub fn column_names() -> &'static [&'static str] {
        &["Name", "Value"]
    }

    /// Get preferred column widths.
    pub fn column_widths() -> &'static [usize] {
        &[280, 280]
    }

    /// Clear all results.
    pub fn clear(&mut self) {
        self.results.clear();
    }
}

impl Default for ChecksumTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ComputeChecksumsPlugin
// ---------------------------------------------------------------------------

/// Plugin providing the "Compute Checksums" action.
///
/// Ported from `ghidra.app.plugin.core.checksums.ComputeChecksumsPlugin`.
#[derive(Debug)]
pub struct ComputeChecksumsPlugin {
    /// The checksum registry.
    registry: ChecksumRegistry,
    /// Whether the plugin is active.
    active: bool,
}

impl ComputeChecksumsPlugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        Self {
            registry: ChecksumRegistry::with_defaults(),
            active: true,
        }
    }

    /// Get the registry.
    pub fn registry(&self) -> &ChecksumRegistry {
        &self.registry
    }

    /// Get a mutable registry.
    pub fn registry_mut(&mut self) -> &mut ChecksumRegistry {
        &mut self.registry
    }

    /// Whether the plugin is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for ComputeChecksumsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ComputeChecksumsProvider
// ---------------------------------------------------------------------------

/// Provider that computes checksums and populates the table.
///
/// Ported from `ghidra.app.plugin.core.checksums.ComputeChecksumsProvider`.
#[derive(Debug)]
pub struct ComputeChecksumsProvider {
    /// The table model.
    table_model: ChecksumTableModel,
    /// Ones complement option.
    ones_complement: bool,
    /// Twos complement option.
    twos_complement: bool,
    /// XOR option (for basic checksums).
    xor: bool,
    /// Carry option (for basic checksums).
    carry: bool,
}

impl ComputeChecksumsProvider {
    /// Create a new provider.
    pub fn new() -> Self {
        Self {
            table_model: ChecksumTableModel::new(),
            ones_complement: false,
            twos_complement: false,
            xor: false,
            carry: false,
        }
    }

    /// Get the table model.
    pub fn table_model(&self) -> &ChecksumTableModel {
        &self.table_model
    }

    /// Get a mutable table model.
    pub fn table_model_mut(&mut self) -> &mut ChecksumTableModel {
        &mut self.table_model
    }

    /// Set ones complement.
    pub fn set_ones_complement(&mut self, ones: bool) {
        self.ones_complement = ones;
    }

    /// Whether ones complement is enabled.
    pub fn is_ones(&self) -> bool {
        self.ones_complement
    }

    /// Set twos complement.
    pub fn set_twos_complement(&mut self, twos: bool) {
        self.twos_complement = twos;
    }

    /// Whether twos complement is enabled.
    pub fn is_twos(&self) -> bool {
        self.twos_complement
    }

    /// Set XOR mode.
    pub fn set_xor(&mut self, xor: bool) {
        self.xor = xor;
    }

    /// Whether XOR is enabled.
    pub fn is_xor(&self) -> bool {
        self.xor
    }

    /// Set carry mode.
    pub fn set_carry(&mut self, carry: bool) {
        self.carry = carry;
    }

    /// Whether carry is enabled.
    pub fn is_carry(&self) -> bool {
        self.carry
    }

    /// Compute checksums for the given data using all registered algorithms.
    pub fn compute(&mut self, data: &[u8], registry: &ChecksumRegistry) {
        self.table_model.clear();
        for algo_name in registry.names() {
            if let Some(algo) = registry.find(algo_name) {
                let checksum = algo.compute(data);
                self.table_model
                    .add_result(algo_name, checksum, algo.supports_decimal());
            }
        }
    }
}

impl Default for ComputeChecksumsProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ComputeChecksumTask
// ---------------------------------------------------------------------------

/// Background task for computing checksums.
///
/// Ported from `ghidra.app.plugin.core.checksums.ComputeChecksumTask`.
#[derive(Debug)]
pub struct ComputeChecksumTask {
    /// The data to compute checksums over.
    data: Vec<u8>,
    /// The algorithms to use.
    algorithm_names: Vec<String>,
    /// Results after computation.
    results: Vec<ChecksumResult>,
    /// Whether the task is complete.
    complete: bool,
}

impl ComputeChecksumTask {
    /// Create a new task.
    pub fn new(data: Vec<u8>, algorithm_names: Vec<String>) -> Self {
        Self {
            data,
            algorithm_names,
            results: Vec::new(),
            complete: false,
        }
    }

    /// Execute the task using the given registry.
    pub fn execute(&mut self, registry: &ChecksumRegistry) {
        self.results.clear();
        for name in &self.algorithm_names {
            if let Some(algo) = registry.find(name) {
                let checksum = algo.compute(&self.data);
                self.results.push(ChecksumResult::success(
                    name,
                    checksum.clone(),
                    super::format_hex(&checksum),
                    self.data.len(),
                ));
            } else {
                self.results.push(ChecksumResult::failure(
                    name,
                    format!("Algorithm '{}' not found", name),
                    0,
                ));
            }
        }
        self.complete = true;
    }

    /// Whether the task is complete.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Get the results.
    pub fn results(&self) -> &[ChecksumResult] {
        &self.results
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_table_model() {
        let mut model = ChecksumTableModel::new();
        assert!(model.is_empty());

        model.add_result("CRC-32", vec![0x26, 0x39, 0xF4, 0xCB], true);
        model.add_result("MD5", vec![0xd4, 0x1d, 0x8c], false);
        assert_eq!(model.len(), 2);

        let row = model.get(0).unwrap();
        assert_eq!(row.name, "CRC-32");
        assert!(row.supports_decimal);
    }

    #[test]
    fn test_checksum_table_model_hex_decimal_toggle() {
        let mut model = ChecksumTableModel::new();
        model.add_result("CRC-32", vec![0x00, 0x00, 0x01, 0x00], true);

        assert!(model.is_hex_display());
        let hex_val = model.cell_value(0, ChecksumTableModel::VALUE_COL).unwrap();
        assert!(hex_val.contains("00"));

        model.set_hex_display(false);
        let dec_val = model.cell_value(0, ChecksumTableModel::VALUE_COL).unwrap();
        assert_eq!(dec_val, "256");
    }

    #[test]
    fn test_checksum_table_model_find_by_name() {
        let mut model = ChecksumTableModel::new();
        model.add_result("SHA-256", vec![0x01, 0x02], false);
        model.add_result("CRC-32", vec![0x03, 0x04], true);

        assert!(model.find_by_name("SHA-256").is_some());
        assert!(model.find_by_name("CRC-32").is_some());
        assert!(model.find_by_name("NONEXISTENT").is_none());
    }

    #[test]
    fn test_compute_checksums_plugin() {
        let plugin = ComputeChecksumsPlugin::new();
        assert!(plugin.is_active());
        assert!(plugin.registry().len() >= 13);
    }

    #[test]
    fn test_compute_checksums_provider() {
        let mut provider = ComputeChecksumsProvider::new();
        assert!(!provider.is_ones());
        assert!(!provider.is_twos());
        assert!(!provider.is_xor());
        assert!(!provider.is_carry());

        provider.set_ones_complement(true);
        assert!(provider.is_ones());

        let registry = ChecksumRegistry::with_defaults();
        provider.compute(b"hello", &registry);
        assert!(!provider.table_model().is_empty());
    }

    #[test]
    fn test_compute_checksum_task() {
        let mut task = ComputeChecksumTask::new(
            b"test data".to_vec(),
            vec!["CRC-32".to_string(), "MD5".to_string()],
        );
        assert!(!task.is_complete());

        let registry = ChecksumRegistry::with_defaults();
        task.execute(&registry);
        assert!(task.is_complete());
        assert_eq!(task.results().len(), 2);
    }

    #[test]
    fn test_compute_checksum_task_missing_algorithm() {
        let mut task = ComputeChecksumTask::new(
            b"test".to_vec(),
            vec!["NONEXISTENT".to_string()],
        );
        let registry = ChecksumRegistry::with_defaults();
        task.execute(&registry);
        assert_eq!(task.results().len(), 1);
        assert!(!task.results()[0].is_success());
    }

    #[test]
    fn test_column_names_and_widths() {
        assert_eq!(ChecksumTableModel::column_names(), &["Name", "Value"]);
        assert_eq!(ChecksumTableModel::column_widths(), &[280, 280]);
    }
}
