//! AnalyzerEnablementState and AnalysisEnablementTableModel.
//!
//! Re-exports [`AnalyzerEnablementState`] from `base::analyzer::worker`
//! and adds the [`AnalysisEnablementTableModel`] for displaying analyzer
//! enablement in a UI.

pub use crate::base::analyzer::AnalyzerEnablementState;

// ---------------------------------------------------------------------------
// AnalysisEnablementTableModel
// ---------------------------------------------------------------------------

/// Table model for displaying analyzer enablement in a UI.
///
/// Ported from Ghidra's `AnalysisEnablementTableModel`. Provides a data
/// model for a table showing each analyzer's name, description, type,
/// and enabled state.
///
/// # Columns
///
/// | Index | Name        | Type   | Description                |
/// |-------|-------------|--------|----------------------------|
/// | 0     | Enabled     | bool   | Whether analyzer is on     |
/// | 1     | Name        | String | Analyzer display name      |
/// | 2     | Description | String | Analyzer description       |
/// | 3     | Type        | String | Analyzer type              |
/// | 4     | Default     | bool   | Default enablement         |
#[derive(Debug, Clone)]
pub struct AnalysisEnablementTableModel {
    /// Column names.
    column_names: Vec<String>,
    /// Analyzer entries (name, description, type, enabled, default).
    entries: Vec<EnablementEntry>,
}

/// A single analyzer entry in the enablement table.
#[derive(Debug, Clone)]
pub struct EnablementEntry {
    /// Analyzer name.
    pub name: String,
    /// Analyzer description.
    pub description: String,
    /// Analyzer type string.
    pub analyzer_type: String,
    /// Whether the analyzer is currently enabled.
    pub enabled: bool,
    /// Default enablement state.
    pub default_enabled: bool,
}

impl AnalysisEnablementTableModel {
    /// Column index for the "Enabled" checkbox.
    pub const COL_ENABLED: usize = 0;
    /// Column index for the analyzer name.
    pub const COL_NAME: usize = 1;
    /// Column index for the analyzer description.
    pub const COL_DESCRIPTION: usize = 2;
    /// Column index for the analyzer type.
    pub const COL_TYPE: usize = 3;
    /// Column index for the default enablement.
    pub const COL_DEFAULT: usize = 4;

    /// Create a new table model.
    pub fn new() -> Self {
        Self {
            column_names: vec![
                "Enabled".to_string(),
                "Name".to_string(),
                "Description".to_string(),
                "Type".to_string(),
                "Default".to_string(),
            ],
            entries: Vec::new(),
        }
    }

    /// Build a table model from analyzer metadata.
    pub fn from_entries(
        analyzer_info: &[(&str, &str, &str, bool, bool)], // (name, desc, type, enabled, default)
    ) -> Self {
        let mut model = Self::new();
        for &(name, description, analyzer_type, enabled, default_enabled) in analyzer_info {
            model.entries.push(EnablementEntry {
                name: name.to_string(),
                description: description.to_string(),
                analyzer_type: analyzer_type.to_string(),
                enabled,
                default_enabled,
            });
        }
        model
    }

    /// Get the number of columns.
    pub fn column_count(&self) -> usize {
        self.column_names.len()
    }

    /// Get a column name by index.
    pub fn column_name(&self, index: usize) -> &str {
        &self.column_names[index]
    }

    /// Get the number of rows (analyzers).
    pub fn row_count(&self) -> usize {
        self.entries.len()
    }

    /// Get an entry by row index.
    pub fn get_entry(&self, row: usize) -> Option<&EnablementEntry> {
        self.entries.get(row)
    }

    /// Toggle the enabled state of an analyzer at the given row.
    pub fn toggle_enabled(&mut self, row: usize) {
        if let Some(entry) = self.entries.get_mut(row) {
            entry.enabled = !entry.enabled;
        }
    }

    /// Check if the entry at the given row has been changed from default.
    pub fn is_changed_from_default(&self, row: usize) -> bool {
        self.entries
            .get(row)
            .map_or(false, |e| e.enabled != e.default_enabled)
    }
}

impl Default for AnalysisEnablementTableModel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_model_creation() {
        let model = AnalysisEnablementTableModel::new();
        assert_eq!(model.column_count(), 5);
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_table_model_from_entries() {
        let info = vec![
            ("A", "Analyzer A", "Function", true, true),
            ("B", "Analyzer B", "Data", false, false),
        ];
        let model = AnalysisEnablementTableModel::from_entries(&info);
        assert_eq!(model.row_count(), 2);
        assert!(model.get_entry(0).unwrap().enabled);
        assert!(!model.get_entry(1).unwrap().enabled);
    }

    #[test]
    fn test_table_model_toggle() {
        let info = vec![("A", "desc", "type", true, true)];
        let mut model = AnalysisEnablementTableModel::from_entries(&info);
        assert!(model.get_entry(0).unwrap().enabled);
        model.toggle_enabled(0);
        assert!(!model.get_entry(0).unwrap().enabled);
    }

    #[test]
    fn test_table_model_is_changed() {
        let info = vec![("A", "desc", "type", true, true)];
        let mut model = AnalysisEnablementTableModel::from_entries(&info);
        assert!(!model.is_changed_from_default(0));
        model.toggle_enabled(0);
        assert!(model.is_changed_from_default(0));
    }
}
