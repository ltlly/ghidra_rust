//! FindPossibleReferencesPlugin and FindReferencesTableModel.
//!
//! Ported from Ghidra's:
//! - `ghidra.app.plugin.core.analysis.FindPossibleReferencesPlugin`
//! - `ghidra.app.plugin.core.analysis.FindReferencesTableModel`
//!
//! Provides functionality for finding potential references in code that
//! were not discovered by automatic analysis, and displaying results in
//! a table model.

use std::collections::HashMap;

use crate::base::analyzer::{Address, AddressSet, Program, TaskMonitor};

// ---------------------------------------------------------------------------
// FindPossibleReferencesPlugin
// ---------------------------------------------------------------------------

/// Plugin for finding possible references that were not discovered by analysis.
///
/// Ported from Ghidra's `FindPossibleReferencesPlugin`. This plugin allows
/// users to search for addresses that look like they could be references
/// but were not found by automatic analysis. This is useful for finding
/// indirect references, computed addresses, and other non-obvious references.
///
/// # Workflow
///
/// 1. User selects a code region
/// 2. Plugin scans for address-like values in the listing
/// 3. Values are checked against known memory regions
/// 4. Results are displayed in a table for user review
pub struct FindPossibleReferencesPlugin {
    /// The maximum number of results to collect.
    max_results: usize,
    /// Whether to search only within the current selection.
    selection_only: bool,
}

impl FindPossibleReferencesPlugin {
    /// Create a new find possible references plugin.
    pub fn new() -> Self {
        Self {
            max_results: 1000,
            selection_only: false,
        }
    }

    /// Create with specific configuration.
    pub fn with_config(max_results: usize, selection_only: bool) -> Self {
        Self {
            max_results,
            selection_only,
        }
    }

    /// Maximum number of results to collect.
    pub fn max_results(&self) -> usize {
        self.max_results
    }

    /// Whether to search only within the current selection.
    pub fn selection_only(&self) -> bool {
        self.selection_only
    }

    /// Set whether to search only within the current selection.
    pub fn set_selection_only(&mut self, selection_only: bool) {
        self.selection_only = selection_only;
    }

    /// Find possible references in the given address set.
    pub fn find_references(
        &self,
        program: &Program,
        search_set: &AddressSet,
        monitor: &dyn TaskMonitor,
    ) -> Vec<ReferenceCandidate> {
        let mut candidates = Vec::new();

        for addr in search_set.get_addresses(true) {
            if candidates.len() >= self.max_results {
                break;
            }
            if monitor.is_cancelled() {
                break;
            }
            // In the full implementation, this would read bytes at each
            // address and check if they form valid address references
            let _ = (addr, &program.memory);
        }

        candidates
    }
}

impl Default for FindPossibleReferencesPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ReferenceCandidate
// ---------------------------------------------------------------------------

/// A potential reference found by the find references plugin.
#[derive(Debug, Clone)]
pub struct ReferenceCandidate {
    /// The address where the reference was found.
    pub from_address: Address,
    /// The target address of the reference.
    pub to_address: Address,
    /// The confidence level (0.0 to 1.0).
    pub confidence: f64,
    /// Description of why this looks like a reference.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// FindReferencesTableModel
// ---------------------------------------------------------------------------

/// Table model for displaying reference search results.
///
/// Ported from Ghidra's `FindReferencesTableModel`. Provides a data model
/// for displaying found references in a table, with columns for source
/// address, target address, confidence, and reason.
///
/// # Columns
///
/// | Index | Name       | Type     | Description               |
/// |-------|------------|----------|---------------------------|
/// | 0     | From       | Address  | Source address             |
/// | 1     | To         | Address  | Target address             |
/// | 2     | Confidence | f64      | Confidence (0.0-1.0)       |
/// | 3     | Reason     | String   | Why it looks like a ref    |
#[derive(Debug, Clone)]
pub struct FindReferencesTableModel {
    /// Column names.
    column_names: Vec<String>,
    /// The collected reference candidates.
    results: Vec<ReferenceCandidate>,
}

impl FindReferencesTableModel {
    /// Column index for the "From" address.
    pub const COL_FROM: usize = 0;
    /// Column index for the "To" address.
    pub const COL_TO: usize = 1;
    /// Column index for the confidence value.
    pub const COL_CONFIDENCE: usize = 2;
    /// Column index for the reason string.
    pub const COL_REASON: usize = 3;

    /// Create a new table model.
    pub fn new() -> Self {
        Self {
            column_names: vec![
                "From".to_string(),
                "To".to_string(),
                "Confidence".to_string(),
                "Reason".to_string(),
            ],
            results: Vec::new(),
        }
    }

    /// Get the number of columns.
    pub fn column_count(&self) -> usize {
        self.column_names.len()
    }

    /// Get a column name by index.
    pub fn column_name(&self, index: usize) -> &str {
        &self.column_names[index]
    }

    /// Get the number of rows (results).
    pub fn row_count(&self) -> usize {
        self.results.len()
    }

    /// Get a reference candidate by row index.
    pub fn get_row(&self, row: usize) -> Option<&ReferenceCandidate> {
        self.results.get(row)
    }

    /// Get the value at a specific cell.
    pub fn get_value_at(&self, row: usize, col: usize) -> Option<String> {
        let candidate = self.results.get(row)?;
        match col {
            Self::COL_FROM => Some(format!("{}", candidate.from_address)),
            Self::COL_TO => Some(format!("{}", candidate.to_address)),
            Self::COL_CONFIDENCE => Some(format!("{:.2}", candidate.confidence)),
            Self::COL_REASON => Some(candidate.reason.clone()),
            _ => None,
        }
    }

    /// Add a result to the table.
    pub fn add_result(&mut self, candidate: ReferenceCandidate) {
        self.results.push(candidate);
    }

    /// Add multiple results to the table.
    pub fn add_results(&mut self, candidates: Vec<ReferenceCandidate>) {
        self.results.extend(candidates);
    }

    /// Clear all results.
    pub fn clear(&mut self) {
        self.results.clear();
    }

    /// Get all results as a slice.
    pub fn results(&self) -> &[ReferenceCandidate] {
        &self.results
    }
}

impl Default for FindReferencesTableModel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_references_plugin_creation() {
        let plugin = FindPossibleReferencesPlugin::new();
        assert_eq!(plugin.max_results(), 1000);
        assert!(!plugin.selection_only());
    }

    #[test]
    fn test_find_references_plugin_config() {
        let plugin = FindPossibleReferencesPlugin::with_config(500, true);
        assert_eq!(plugin.max_results(), 500);
        assert!(plugin.selection_only());
    }

    #[test]
    fn test_table_model_empty() {
        let model = FindReferencesTableModel::new();
        assert_eq!(model.column_count(), 4);
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.column_name(0), "From");
        assert_eq!(model.column_name(1), "To");
        assert_eq!(model.column_name(2), "Confidence");
        assert_eq!(model.column_name(3), "Reason");
    }

    #[test]
    fn test_table_model_add_result() {
        let mut model = FindReferencesTableModel::new();
        model.add_result(ReferenceCandidate {
            from_address: Address::new(0x401000),
            to_address: Address::new(0x402000),
            confidence: 0.85,
            reason: "Address-like value in operand".to_string(),
        });
        assert_eq!(model.row_count(), 1);
        assert_eq!(model.get_value_at(0, 0).unwrap(), "0x00401000");
        assert_eq!(model.get_value_at(0, 1).unwrap(), "0x00402000");
        assert_eq!(model.get_value_at(0, 2).unwrap(), "0.85");
        assert_eq!(model.get_value_at(0, 3).unwrap(), "Address-like value in operand");
    }

    #[test]
    fn test_table_model_add_results() {
        let mut model = FindReferencesTableModel::new();
        model.add_results(vec![
            ReferenceCandidate {
                from_address: Address::new(0x1000),
                to_address: Address::new(0x2000),
                confidence: 0.9,
                reason: "test1".to_string(),
            },
            ReferenceCandidate {
                from_address: Address::new(0x3000),
                to_address: Address::new(0x4000),
                confidence: 0.5,
                reason: "test2".to_string(),
            },
        ]);
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_table_model_clear() {
        let mut model = FindReferencesTableModel::new();
        model.add_result(ReferenceCandidate {
            from_address: Address::new(0x1000),
            to_address: Address::new(0x2000),
            confidence: 0.9,
            reason: "test".to_string(),
        });
        assert_eq!(model.row_count(), 1);
        model.clear();
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_table_model_invalid_column() {
        let model = FindReferencesTableModel::new();
        assert!(model.get_value_at(0, 99).is_none());
    }

    #[test]
    fn test_reference_candidate_clone() {
        let candidate = ReferenceCandidate {
            from_address: Address::new(0x1000),
            to_address: Address::new(0x2000),
            confidence: 0.75,
            reason: "test".to_string(),
        };
        let cloned = candidate.clone();
        assert_eq!(cloned.confidence, 0.75);
    }
}
