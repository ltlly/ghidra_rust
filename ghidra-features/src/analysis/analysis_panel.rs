//! Analysis panel -- UI model for configuring and managing analyzers.
//!
//! Ported from `ghidra.app.plugin.core.analysis.AnalysisPanel` in Ghidra's
//! Features/Base.
//!
//! This module provides the data model behind the "Analysis" options panel
//! where users can enable/disable individual analyzers and configure their
//! options.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// AnalysisPanel -- analyzer configuration state
// ---------------------------------------------------------------------------

/// Model for the Analysis options panel.
///
/// Tracks the enabled/disabled state and options for all registered analyzers.
/// Users can toggle individual analyzers, change their priority, and modify
/// their option values.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisPanel {
    /// Analyzer entries keyed by analyzer name.
    pub entries: HashMap<String, AnalyzerEntry>,
    /// The current program ID (if any).
    pub program_id: Option<u64>,
}

/// An entry for a single analyzer in the configuration panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerEntry {
    /// Analyzer unique name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Whether the analyzer is currently enabled.
    pub enabled: bool,
    /// Default enablement (what the analyzer defaults to for the current program).
    pub default_enabled: bool,
    /// Whether the analyzer's enabled state has been manually changed from default.
    pub overridden: bool,
    /// The analyzer type (instruction, data, function, etc.).
    pub analyzer_type: AnalyzerType,
    /// Configuration options for this analyzer.
    pub options: HashMap<String, ConfigOption>,
}

/// Types of analyzers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnalyzerType {
    /// Analyzes instructions.
    Instruction,
    /// Analyzes data.
    Data,
    /// Analyzes functions.
    Function,
    /// Analyzes the entire binary.
    Binary,
    /// Analyzes byte-level patterns.
    Byte,
    /// Analyzes function signatures.
    FunctionSignature,
    /// One-shot analyzer (runs once, never again).
    OneShot,
}

/// A single configurable option for an analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigOption {
    /// Option name.
    pub name: String,
    /// Option description.
    pub description: String,
    /// Current value.
    pub value: ConfigOptionValue,
    /// Default value.
    pub default_value: ConfigOptionValue,
}

/// Value types for analyzer configuration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigOptionValue {
    /// Boolean value.
    Bool(bool),
    /// Integer value.
    Int(i64),
    /// String value.
    String(String),
    /// Enum/choice value (index into a list of choices).
    Choice(usize, Vec<String>),
}

impl AnalysisPanel {
    /// Create a new empty analysis panel.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an analyzer entry to the panel.
    pub fn add_analyzer(&mut self, entry: AnalyzerEntry) {
        self.entries.insert(entry.name.clone(), entry);
    }

    /// Get an analyzer entry by name.
    pub fn get_analyzer(&self, name: &str) -> Option<&AnalyzerEntry> {
        self.entries.get(name)
    }

    /// Get a mutable reference to an analyzer entry by name.
    pub fn get_analyzer_mut(&mut self, name: &str) -> Option<&mut AnalyzerEntry> {
        self.entries.get_mut(name)
    }

    /// Enable or disable an analyzer.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> bool {
        if let Some(entry) = self.entries.get_mut(name) {
            entry.enabled = enabled;
            entry.overridden = enabled != entry.default_enabled;
            true
        } else {
            false
        }
    }

    /// Set an analyzer option value.
    pub fn set_option(&mut self, analyzer_name: &str, option_name: &str, value: ConfigOptionValue) -> bool {
        if let Some(entry) = self.entries.get_mut(analyzer_name) {
            if let Some(opt) = entry.options.get_mut(option_name) {
                opt.value = value;
                return true;
            }
        }
        false
    }

    /// Get the names of all enabled analyzers.
    pub fn enabled_analyzers(&self) -> Vec<&str> {
        self.entries
            .values()
            .filter(|e| e.enabled)
            .map(|e| e.name.as_str())
            .collect()
    }

    /// Get the number of analyzers.
    pub fn analyzer_count(&self) -> usize {
        self.entries.len()
    }

    /// Get the number of enabled analyzers.
    pub fn enabled_count(&self) -> usize {
        self.entries.values().filter(|e| e.enabled).count()
    }

    /// Reset all analyzers to their default enablement.
    pub fn reset_to_defaults(&mut self) {
        for entry in self.entries.values_mut() {
            entry.enabled = entry.default_enabled;
            entry.overridden = false;
            for opt in entry.options.values_mut() {
                opt.value = opt.default_value.clone();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AnalysisEnablementState
// ---------------------------------------------------------------------------

/// Tracks the enablement state of analyzers across program sessions.
///
/// This allows the application to remember which analyzers were enabled/disabled
/// when a program is reopened.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisEnablementState {
    /// Per-analyzer enablement overrides (name -> enabled).
    pub overrides: HashMap<String, bool>,
    /// Per-analyzer option overrides (analyzer_name, option_name) -> value.
    pub option_overrides: HashMap<(String, String), ConfigOptionValue>,
}

impl AnalysisEnablementState {
    /// Create a new empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an enablement override.
    pub fn set_override(&mut self, name: String, enabled: bool) {
        self.overrides.insert(name, enabled);
    }

    /// Get the enablement override for an analyzer, if any.
    pub fn get_override(&self, name: &str) -> Option<bool> {
        self.overrides.get(name).copied()
    }

    /// Record an option override.
    pub fn set_option_override(&mut self, analyzer: String, option: String, value: ConfigOptionValue) {
        self.option_overrides.insert((analyzer, option), value);
    }

    /// Get an option override, if any.
    pub fn get_option_override(&self, analyzer: &str, option: &str) -> Option<&ConfigOptionValue> {
        self.option_overrides.get(&(analyzer.to_string(), option.to_string()))
    }
}

// ---------------------------------------------------------------------------
// AnalysisTableModel
// ---------------------------------------------------------------------------

/// Table model for the analyzers list.
///
/// Supports sorting by name, type, and enabled state.
#[derive(Debug, Clone)]
pub struct AnalysisTableModel {
    /// Sorted list of analyzer entries.
    pub entries: Vec<AnalyzerEntry>,
    /// Current sort column.
    pub sort_column: SortColumn,
    /// Sort ascending.
    pub sort_ascending: bool,
}

/// Column indices for sorting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortColumn {
    /// Sort by analyzer name.
    Name,
    /// Sort by analyzer type.
    Type,
    /// Sort by enabled state.
    Enabled,
}

impl Default for AnalysisTableModel {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            sort_column: SortColumn::Enabled,
            sort_ascending: true,
        }
    }
}

impl AnalysisTableModel {
    /// Create a new table model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry to the table model.
    pub fn add_entry(&mut self, entry: AnalyzerEntry) {
        self.entries.push(entry);
    }

    /// Sort the entries by the current sort column.
    pub fn sort(&mut self) {
        match self.sort_column {
            SortColumn::Name => {
                if self.sort_ascending {
                    self.entries.sort_by(|a, b| a.name.cmp(&b.name));
                } else {
                    self.entries.sort_by(|a, b| b.name.cmp(&a.name));
                }
            }
            SortColumn::Type => {
                if self.sort_ascending {
                    self.entries.sort_by(|a, b| a.analyzer_type.cmp(&b.analyzer_type));
                } else {
                    self.entries.sort_by(|a, b| b.analyzer_type.cmp(&a.analyzer_type));
                }
            }
            SortColumn::Enabled => {
                if self.sort_ascending {
                    self.entries.sort_by(|a, b| a.enabled.cmp(&b.enabled));
                } else {
                    self.entries.sort_by(|a, b| b.enabled.cmp(&a.enabled));
                }
            }
        }
    }

    /// Toggle the sort direction.
    pub fn toggle_sort_direction(&mut self) {
        self.sort_ascending = !self.sort_ascending;
    }

    /// Set the sort column and re-sort.
    pub fn set_sort_column(&mut self, column: SortColumn) {
        if self.sort_column == column {
            self.toggle_sort_direction();
        } else {
            self.sort_column = column;
            self.sort_ascending = true;
        }
        self.sort();
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_entry(name: &str, enabled: bool) -> AnalyzerEntry {
        AnalyzerEntry {
            name: name.to_string(),
            description: format!("Test analyzer {name}"),
            enabled,
            default_enabled: enabled,
            overridden: false,
            analyzer_type: AnalyzerType::Instruction,
            options: HashMap::new(),
        }
    }

    #[test]
    fn test_analysis_panel() {
        let mut panel = AnalysisPanel::new();
        assert_eq!(panel.analyzer_count(), 0);

        panel.add_analyzer(make_test_entry("A", true));
        panel.add_analyzer(make_test_entry("B", false));
        panel.add_analyzer(make_test_entry("C", true));

        assert_eq!(panel.analyzer_count(), 3);
        assert_eq!(panel.enabled_count(), 2);
        let mut enabled: Vec<&str> = panel.enabled_analyzers();
        enabled.sort();
        assert_eq!(enabled, vec!["A", "C"]);
    }

    #[test]
    fn test_set_enabled() {
        let mut panel = AnalysisPanel::new();
        panel.add_analyzer(make_test_entry("Test", false));

        assert!(panel.set_enabled("Test", true));
        assert_eq!(panel.enabled_count(), 1);

        let entry = panel.get_analyzer("Test").unwrap();
        assert!(entry.overridden);
    }

    #[test]
    fn test_reset_to_defaults() {
        let mut panel = AnalysisPanel::new();
        panel.add_analyzer(make_test_entry("A", true));
        panel.set_enabled("A", false);
        assert_eq!(panel.enabled_count(), 0);

        panel.reset_to_defaults();
        assert_eq!(panel.enabled_count(), 1);
    }

    #[test]
    fn test_enablement_state() {
        let mut state = AnalysisEnablementState::new();
        assert!(state.get_override("foo").is_none());

        state.set_override("foo".to_string(), false);
        assert_eq!(state.get_override("foo"), Some(false));
    }

    #[test]
    fn test_analysis_table_model_sort() {
        let mut model = AnalysisTableModel::new();
        model.add_entry(make_test_entry("Charlie", true));
        model.add_entry(make_test_entry("Alpha", false));
        model.add_entry(make_test_entry("Bravo", true));

        model.set_sort_column(SortColumn::Name);
        assert_eq!(model.entries[0].name, "Alpha");
        assert_eq!(model.entries[1].name, "Bravo");
        assert_eq!(model.entries[2].name, "Charlie");

        // Toggle sort direction
        model.set_sort_column(SortColumn::Name);
        assert_eq!(model.entries[0].name, "Charlie");
    }
}
