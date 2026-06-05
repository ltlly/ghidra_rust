//! Data Window context -- action context for the data window.
//!
//! Ported from `ghidra.app.plugin.core.datawindow.DataWindowContext`.

use super::DataRowObject;

/// Action context for the data window provider.
///
/// Ported from `ghidra.app.plugin.core.datawindow.DataWindowContext`.
#[derive(Debug, Clone)]
pub struct DataWindowContext {
    /// The selected data row, if any.
    pub selected_row: Option<DataRowObject>,
    /// The row index in the table.
    pub row_index: Option<usize>,
    /// Whether there is an active selection.
    pub has_selection: bool,
}

impl DataWindowContext {
    /// Create a new empty context.
    pub fn new() -> Self {
        Self {
            selected_row: None,
            row_index: None,
            has_selection: false,
        }
    }

    /// Create a context with a selected row.
    pub fn with_row(row: DataRowObject, index: usize) -> Self {
        Self {
            selected_row: Some(row),
            row_index: Some(index),
            has_selection: true,
        }
    }

    /// Whether a row is selected.
    pub fn has_row(&self) -> bool {
        self.selected_row.is_some()
    }
}

impl Default for DataWindowContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Filter action for the data window.
///
/// Ported from `ghidra.app.plugin.core.datawindow.FilterAction`.
#[derive(Debug, Clone)]
pub struct FilterAction {
    /// Action name.
    name: String,
    /// Whether the filter is currently enabled.
    enabled: bool,
}

impl FilterAction {
    /// Create a new filter action.
    pub fn new() -> Self {
        Self {
            name: "Filter Data".to_string(),
            enabled: false,
        }
    }

    /// Action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Toggle the filter state.
    pub fn toggle(&mut self) {
        self.enabled = !self.enabled;
    }

    /// Set the filter state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Default for FilterAction {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datawindow::DataRowObject;

    #[test]
    fn test_data_window_context_empty() {
        let ctx = DataWindowContext::new();
        assert!(!ctx.has_row());
        assert!(!ctx.has_selection);
    }

    #[test]
    fn test_data_window_context_with_row() {
        let row = DataRowObject::new(0x1000, "0x1000", "int", "42", 4);
        let ctx = DataWindowContext::with_row(row, 0);
        assert!(ctx.has_row());
        assert!(ctx.has_selection);
        assert_eq!(ctx.row_index, Some(0));
        assert_eq!(ctx.selected_row.as_ref().unwrap().address_key, 0x1000);
    }

    #[test]
    fn test_filter_action_lifecycle() {
        let mut action = FilterAction::new();
        assert_eq!(action.name(), "Filter Data");
        assert!(!action.is_enabled());

        action.toggle();
        assert!(action.is_enabled());

        action.toggle();
        assert!(!action.is_enabled());
    }

    #[test]
    fn test_filter_action_set_enabled() {
        let mut action = FilterAction::new();
        action.set_enabled(true);
        assert!(action.is_enabled());
        action.set_enabled(false);
        assert!(!action.is_enabled());
    }
}
