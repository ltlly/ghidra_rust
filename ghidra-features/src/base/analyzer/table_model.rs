//! AnalysisEnablementTableModel -- data model for analyzer enablement UI.
//!
//! Ported from `ghidra.app.plugin.core.analysis.AnalysisEnablementTableModel`.
//! Provides a table model for displaying and toggling analyzer enablement states.

use std::collections::HashMap;

use crate::base::analyzer::core::*;
use crate::base::analyzer::worker::AnalyzerEnablementState;

/// Column definitions for the analysis enablement table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnablementColumn {
    /// Whether the analyzer is enabled (checkbox).
    Enabled = 0,
    /// The analyzer name.
    Name = 1,
}

impl EnablementColumn {
    /// Returns all columns in display order.
    pub fn all() -> &'static [EnablementColumn] {
        &[EnablementColumn::Enabled, EnablementColumn::Name]
    }

    /// Returns the column name.
    pub fn name(&self) -> &'static str {
        match self {
            EnablementColumn::Enabled => "Enabled",
            EnablementColumn::Name => "Analyzer",
        }
    }

    /// Returns the column index.
    pub fn index(&self) -> usize {
        *self as usize
    }
}

/// Table model for analyzer enablement state.
///
/// Manages the display and editing of analyzer enablement states.
/// Each row represents an analyzer with its current enablement status.
///
/// # Example
///
/// ```
/// use ghidra_features::base::analyzer::*;
///
/// let mut model = AnalysisEnablementTableModel::new();
/// model.add_state(AnalyzerEnablementState::new("Function Start", true, false));
/// model.add_state(AnalyzerEnablementState::new("Code Boundary", true, false));
/// assert_eq!(model.row_count(), 2);
/// assert_eq!(model.column_count(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct AnalysisEnablementTableModel {
    /// Analyzer enablement states (rows).
    states: Vec<AnalyzerEnablementState>,
    /// Mapping from analyzer name to index.
    name_to_index: HashMap<String, usize>,
}

impl AnalysisEnablementTableModel {
    /// Creates a new empty table model.
    pub fn new() -> Self {
        Self {
            states: Vec::new(),
            name_to_index: HashMap::new(),
        }
    }

    /// Creates a table model from a list of analyzer states.
    pub fn from_states(states: Vec<AnalyzerEnablementState>) -> Self {
        let name_to_index: HashMap<String, usize> = states
            .iter()
            .enumerate()
            .map(|(i, s)| (s.name().to_string(), i))
            .collect();

        Self {
            states,
            name_to_index,
        }
    }

    /// Returns the number of rows (analyzers).
    pub fn row_count(&self) -> usize {
        self.states.len()
    }

    /// Returns the number of columns.
    pub fn column_count(&self) -> usize {
        2 // Enabled + Name
    }

    /// Returns the column name at the given index.
    pub fn column_name(&self, col: usize) -> &str {
        match col {
            0 => "Enabled",
            1 => "Analyzer",
            _ => "",
        }
    }

    /// Returns whether a cell is editable.
    pub fn is_cell_editable(&self, row: usize, col: usize) -> bool {
        col == 0 && row < self.states.len()
    }

    /// Returns the value at the given cell.
    pub fn get_value(&self, row: usize, col: usize) -> Option<String> {
        if row >= self.states.len() {
            return None;
        }
        match col {
            0 => Some(self.states[row].is_enabled().to_string()),
            1 => {
                let name = self.states[row].name().to_string();
                if self.states[row].is_prototype() {
                    Some(format!("{} (Prototype)", name))
                } else {
                    Some(name)
                }
            }
            _ => None,
        }
    }

    /// Sets the enabled state for a row.
    pub fn set_enabled(&mut self, row: usize, enabled: bool) {
        if row < self.states.len() {
            self.states[row].set_enabled(enabled);
        }
    }

    /// Sets the enabled state for an analyzer by name.
    pub fn set_enabled_by_name(&mut self, name: &str, enabled: bool) {
        if let Some(&idx) = self.name_to_index.get(name) {
            self.states[idx].set_enabled(enabled);
        }
    }

    /// Returns a reference to the state at the given row.
    pub fn get_state(&self, row: usize) -> Option<&AnalyzerEnablementState> {
        self.states.get(row)
    }

    /// Returns a mutable reference to the state at the given row.
    pub fn get_state_mut(&mut self, row: usize) -> Option<&mut AnalyzerEnablementState> {
        self.states.get_mut(row)
    }

    /// Returns all states.
    pub fn states(&self) -> &[AnalyzerEnablementState] {
        &self.states
    }

    /// Returns a mutable reference to all states.
    pub fn states_mut(&mut self) -> &mut Vec<AnalyzerEnablementState> {
        &mut self.states
    }

    /// Replaces all states with new data.
    pub fn set_data(&mut self, states: Vec<AnalyzerEnablementState>) {
        self.name_to_index = states
            .iter()
            .enumerate()
            .map(|(i, s)| (s.name().to_string(), i))
            .collect();
        self.states = states;
    }

    /// Returns the display class for a cell (for styling).
    pub fn get_cell_display_class(&self, row: usize, col: usize) -> CellDisplayClass {
        if row >= self.states.len() {
            return CellDisplayClass::Normal;
        }

        let state = &self.states[row];

        match col {
            0 => {
                // Enabled column
                if state.is_default_enablement() {
                    CellDisplayClass::Normal
                } else {
                    CellDisplayClass::Modified
                }
            }
            1 => {
                // Name column
                if state.is_prototype() {
                    CellDisplayClass::Prototype
                } else if !state.is_default_enablement() {
                    CellDisplayClass::Modified
                } else {
                    CellDisplayClass::Normal
                }
            }
            _ => CellDisplayClass::Normal,
        }
    }

    /// Returns whether any analyzer has a non-default enablement state.
    pub fn has_changed_values(&self) -> bool {
        self.states.iter().any(|s| !s.is_default_enablement())
    }

    /// Resets all analyzers to their default enablement state.
    pub fn reset_to_defaults(&mut self) {
        for state in &mut self.states {
            state.set_enabled(state.default_enablement());
        }
    }

    /// Returns the index for a given analyzer name.
    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.name_to_index.get(name).copied()
    }

    /// Sorts states by name.
    pub fn sort_by_name(&mut self) {
        self.states.sort_by(|a, b| a.name().cmp(b.name()));
        self.rebuild_index();
    }

    /// Sorts states by enabled state (enabled first), then by name.
    pub fn sort_by_enabled(&mut self) {
        self.states.sort_by(|a, b| {
            a.is_enabled()
                .cmp(&b.is_enabled())
                .reverse()
                .then_with(|| a.name().cmp(b.name()))
        });
        self.rebuild_index();
    }

    fn rebuild_index(&mut self) {
        self.name_to_index = self
            .states
            .iter()
            .enumerate()
            .map(|(i, s)| (s.name().to_string(), i))
            .collect();
    }
}

impl Default for AnalysisEnablementTableModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Display class for table cells (for styling).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellDisplayClass {
    /// Normal display.
    Normal,
    /// Modified (differs from default).
    Modified,
    /// Prototype analyzer.
    Prototype,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_states() -> Vec<AnalyzerEnablementState> {
        vec![
            AnalyzerEnablementState::new("Function Start", true, false),
            AnalyzerEnablementState::new("Code Boundary", true, false),
            AnalyzerEnablementState::new("Prototype Analyzer", true, true),
            AnalyzerEnablementState::new("Disabled Analyzer", false, false),
        ]
    }

    #[test]
    fn test_table_model_new() {
        let model = AnalysisEnablementTableModel::new();
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.column_count(), 2);
    }

    #[test]
    fn test_table_model_from_states() {
        let model = AnalysisEnablementTableModel::from_states(make_states());
        assert_eq!(model.row_count(), 4);
    }

    #[test]
    fn test_table_model_column_names() {
        let model = AnalysisEnablementTableModel::new();
        assert_eq!(model.column_name(0), "Enabled");
        assert_eq!(model.column_name(1), "Analyzer");
        assert_eq!(model.column_name(2), "");
    }

    #[test]
    fn test_table_model_get_value() {
        let model = AnalysisEnablementTableModel::from_states(make_states());
        assert_eq!(model.get_value(0, 0), Some("true".into()));
        assert_eq!(model.get_value(0, 1), Some("Function Start".into()));
        assert_eq!(
            model.get_value(2, 1),
            Some("Prototype Analyzer (Prototype)".into())
        );
    }

    #[test]
    fn test_table_model_is_cell_editable() {
        let model = AnalysisEnablementTableModel::from_states(make_states());
        assert!(model.is_cell_editable(0, 0));
        assert!(!model.is_cell_editable(0, 1));
        assert!(!model.is_cell_editable(99, 0));
    }

    #[test]
    fn test_table_model_set_enabled() {
        let mut model = AnalysisEnablementTableModel::from_states(make_states());
        assert!(model.get_state(0).unwrap().is_enabled());
        model.set_enabled(0, false);
        assert!(!model.get_state(0).unwrap().is_enabled());
    }

    #[test]
    fn test_table_model_set_enabled_by_name() {
        let mut model = AnalysisEnablementTableModel::from_states(make_states());
        model.set_enabled_by_name("Code Boundary", false);
        let idx = model.index_of("Code Boundary").unwrap();
        assert!(!model.get_state(idx).unwrap().is_enabled());
    }

    #[test]
    fn test_table_model_has_changed_values() {
        let mut model = AnalysisEnablementTableModel::from_states(make_states());
        assert!(!model.has_changed_values());

        // Modify a default-enabled analyzer
        model.set_enabled(0, false);
        assert!(model.has_changed_values());
    }

    #[test]
    fn test_table_model_reset_to_defaults() {
        let mut model = AnalysisEnablementTableModel::from_states(make_states());
        model.set_enabled(0, false);
        assert!(model.has_changed_values());
        model.reset_to_defaults();
        assert!(!model.has_changed_values());
    }

    #[test]
    fn test_table_model_sort_by_name() {
        let mut model = AnalysisEnablementTableModel::from_states(make_states());
        model.sort_by_name();
        assert_eq!(model.get_state(0).unwrap().name(), "Code Boundary");
    }

    #[test]
    fn test_table_model_sort_by_enabled() {
        let mut model = AnalysisEnablementTableModel::from_states(make_states());
        model.sort_by_enabled();
        // Disabled analyzer should be last
        let last = model.get_state(model.row_count() - 1).unwrap();
        assert!(!last.is_enabled());
    }

    #[test]
    fn test_table_model_index_of() {
        let model = AnalysisEnablementTableModel::from_states(make_states());
        assert!(model.index_of("Function Start").is_some());
        assert!(model.index_of("Nonexistent").is_none());
    }

    #[test]
    fn test_cell_display_class() {
        let model = AnalysisEnablementTableModel::from_states(make_states());

        // Normal analyzer
        assert_eq!(
            model.get_cell_display_class(0, 0),
            CellDisplayClass::Normal
        );

        // Prototype analyzer
        assert_eq!(
            model.get_cell_display_class(2, 1),
            CellDisplayClass::Prototype
        );
    }

    #[test]
    fn test_table_model_set_data() {
        let mut model = AnalysisEnablementTableModel::new();
        assert_eq!(model.row_count(), 0);
        model.set_data(make_states());
        assert_eq!(model.row_count(), 4);
    }

    #[test]
    fn test_enablement_column() {
        assert_eq!(EnablementColumn::Enabled.name(), "Enabled");
        assert_eq!(EnablementColumn::Name.name(), "Analyzer");
        assert_eq!(EnablementColumn::all().len(), 2);
    }
}
