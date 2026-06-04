//! Watch GUI data model types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.watch`
//! package in the Debugger module. Provides watch expression panel
//! data types for variable watch windows.

use serde::{Deserialize, Serialize};

/// A watch row displayed in the watches panel.
///
/// Ported from Ghidra's `DefaultWatchRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultWatchRow {
    /// The expression being watched.
    pub expression: String,
    /// The current value, if evaluated.
    pub value: Option<String>,
    /// The data type of the value.
    pub data_type: String,
    /// Whether the expression has been successfully evaluated.
    pub evaluated: bool,
    /// Error message if evaluation failed.
    pub error: Option<String>,
    /// The number of elements if this is an array.
    pub element_count: Option<usize>,
    /// Saved settings for this watch entry.
    pub settings: SavedWatchSettings,
}

impl DefaultWatchRow {
    /// Create a new watch row.
    pub fn new(expression: impl Into<String>) -> Self {
        Self {
            expression: expression.into(),
            value: None,
            data_type: String::new(),
            evaluated: false,
            error: None,
            element_count: None,
            settings: SavedWatchSettings::default(),
        }
    }

    /// Set the evaluated value.
    pub fn set_value(&mut self, value: impl Into<String>, data_type: impl Into<String>) {
        self.value = Some(value.into());
        self.data_type = data_type.into();
        self.evaluated = true;
        self.error = None;
    }

    /// Set an evaluation error.
    pub fn set_error(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
        self.evaluated = false;
        self.value = None;
    }

    /// Clear the evaluation result.
    pub fn clear_value(&mut self) {
        self.value = None;
        self.evaluated = false;
        self.error = None;
    }

    /// The display value string.
    pub fn display_value(&self) -> &str {
        if let Some(ref err) = self.error {
            err
        } else if let Some(ref val) = self.value {
            val
        } else {
            "?"
        }
    }
}

/// Saved settings for a watch entry.
///
/// Ported from Ghidra's `SavedSettings`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedWatchSettings {
    /// Display format (hex, decimal, binary, etc.).
    pub format: WatchFormat,
    /// Number of elements to display.
    pub element_count: usize,
    /// Whether to show as array.
    pub show_as_array: bool,
    /// Whether to auto-update the value.
    pub auto_update: bool,
}

impl Default for SavedWatchSettings {
    fn default() -> Self {
        Self {
            format: WatchFormat::Hex,
            element_count: 1,
            show_as_array: false,
            auto_update: true,
        }
    }
}

/// Display format for watch values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WatchFormat {
    /// Hexadecimal format.
    Hex,
    /// Decimal format.
    Decimal,
    /// Binary format.
    Binary,
    /// Octal format.
    Octal,
    /// Floating-point format.
    Float,
    /// Character format.
    Char,
    /// String format.
    String,
    /// Address format (pointer).
    Address,
}

impl Default for WatchFormat {
    fn default() -> Self {
        Self::Hex
    }
}

/// Column definitions for the watches table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WatchColumn {
    /// Expression.
    Expression,
    /// Value.
    Value,
    /// Data type.
    DataType,
}

/// Model for the watches display panel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WatchTableModel {
    rows: Vec<DefaultWatchRow>,
}

impl WatchTableModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of watch rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get all rows.
    pub fn rows(&self) -> &[DefaultWatchRow] {
        &self.rows
    }

    /// Get a mutable reference to all rows.
    pub fn rows_mut(&mut self) -> &mut [DefaultWatchRow] {
        &mut self.rows
    }

    /// Add a watch expression.
    pub fn add_watch(&mut self, expression: impl Into<String>) -> usize {
        self.rows.push(DefaultWatchRow::new(expression));
        self.rows.len() - 1
    }

    /// Remove a watch by index.
    pub fn remove_watch(&mut self, index: usize) -> bool {
        if index < self.rows.len() {
            self.rows.remove(index);
            true
        } else {
            false
        }
    }

    /// Get a watch row by index.
    pub fn get(&self, index: usize) -> Option<&DefaultWatchRow> {
        self.rows.get(index)
    }

    /// Get a mutable watch row by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut DefaultWatchRow> {
        self.rows.get_mut(index)
    }

    /// Update the value of a watch at the given index.
    pub fn update_value(
        &mut self,
        index: usize,
        value: impl Into<String>,
        data_type: impl Into<String>,
    ) -> bool {
        if let Some(row) = self.rows.get_mut(index) {
            row.set_value(value, data_type);
            true
        } else {
            false
        }
    }

    /// Set an error on a watch at the given index.
    pub fn set_error(&mut self, index: usize, error: impl Into<String>) -> bool {
        if let Some(row) = self.rows.get_mut(index) {
            row.set_error(error);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watch_row_creation() {
        let row = DefaultWatchRow::new("RAX");
        assert_eq!(row.expression, "RAX");
        assert!(!row.evaluated);
        assert_eq!(row.display_value(), "?");
    }

    #[test]
    fn test_watch_row_set_value() {
        let mut row = DefaultWatchRow::new("RAX");
        row.set_value("0x42", "ulong");
        assert!(row.evaluated);
        assert_eq!(row.display_value(), "0x42");
        assert_eq!(row.data_type, "ulong");
    }

    #[test]
    fn test_watch_row_error() {
        let mut row = DefaultWatchRow::new("invalid_expr");
        row.set_error("Unknown register");
        assert!(!row.evaluated);
        assert_eq!(row.display_value(), "Unknown register");
    }

    #[test]
    fn test_saved_watch_settings_default() {
        let settings = SavedWatchSettings::default();
        assert_eq!(settings.format, WatchFormat::Hex);
        assert_eq!(settings.element_count, 1);
        assert!(!settings.show_as_array);
        assert!(settings.auto_update);
    }

    #[test]
    fn test_watch_table_model() {
        let mut model = WatchTableModel::new();
        model.add_watch("RAX");
        model.add_watch("[RSP]");
        assert_eq!(model.row_count(), 2);
        assert_eq!(model.get(0).unwrap().expression, "RAX");
    }

    #[test]
    fn test_watch_table_model_update() {
        let mut model = WatchTableModel::new();
        model.add_watch("RAX");
        model.update_value(0, "0xdeadbeef", "ulong");
        assert_eq!(model.get(0).unwrap().display_value(), "0xdeadbeef");
    }

    #[test]
    fn test_watch_table_model_remove() {
        let mut model = WatchTableModel::new();
        model.add_watch("RAX");
        model.add_watch("RBX");
        model.remove_watch(0);
        assert_eq!(model.row_count(), 1);
        assert_eq!(model.get(0).unwrap().expression, "RBX");
    }

    #[test]
    fn test_watch_table_model_error() {
        let mut model = WatchTableModel::new();
        model.add_watch("bad");
        model.set_error(0, "Syntax error");
        assert_eq!(model.get(0).unwrap().display_value(), "Syntax error");
    }
}
