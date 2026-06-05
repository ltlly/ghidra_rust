//! Function data view -- ported from `FunctionDataView.java` and
//! `AllFunctionsPanel.java`.
//!
//! Provides a view/panel that displays function data in a table with
//! filtering, sorting, and column customization capabilities.

use serde::{Deserialize, Serialize};

use super::table_model::{FunctionRowData, FunctionTableColumn, FunctionTableModel};

// ---------------------------------------------------------------------------
// FunctionDataView -- a filtered/sorted view over function data
// ---------------------------------------------------------------------------

/// A view over function data with filtering, sorting, and column control.
///
/// Ported from `FunctionDataView` and `AllFunctionsPanel`.
#[derive(Debug)]
pub struct FunctionDataView {
    /// The underlying table model.
    model: FunctionTableModel,
    /// Active text filter.
    filter_text: Option<String>,
    /// Active namespace filter.
    filter_namespace: Option<String>,
    /// Whether to show external functions.
    show_external: bool,
    /// Whether to show library functions.
    show_library: bool,
    /// Selected row indices.
    selected_rows: Vec<usize>,
    /// Current column widths.
    column_widths: Vec<u32>,
}

impl FunctionDataView {
    /// Create a new function data view.
    pub fn new() -> Self {
        Self {
            model: FunctionTableModel::new(),
            filter_text: None,
            filter_namespace: None,
            show_external: true,
            show_library: true,
            selected_rows: Vec::new(),
            column_widths: vec![100; FunctionTableColumn::all().len()],
        }
    }

    /// Add a function row to the view.
    pub fn add_function(&mut self, data: FunctionRowData) {
        self.model.add_row(data);
    }

    /// Set text filter.
    pub fn set_text_filter(&mut self, text: Option<String>) {
        self.filter_text = text.clone();
        self.model.set_filter(text);
    }

    /// Set namespace filter.
    pub fn set_namespace_filter(&mut self, ns: Option<String>) {
        self.filter_namespace = ns;
    }

    /// Set whether to show external functions.
    pub fn set_show_external(&mut self, show: bool) {
        self.show_external = show;
    }

    /// Set whether to show library functions.
    pub fn set_show_library(&mut self, show: bool) {
        self.show_library = show;
    }

    /// Get the number of visible rows.
    pub fn visible_row_count(&self) -> usize {
        self.model.row_count()
    }

    /// Sort by column.
    pub fn sort_by(&mut self, col: FunctionTableColumn, ascending: bool) {
        self.model.sort_by(col, ascending);
    }

    /// Select a row.
    pub fn select_row(&mut self, index: usize) {
        if !self.selected_rows.contains(&index) {
            self.selected_rows.push(index);
        }
    }

    /// Clear selection.
    pub fn clear_selection(&mut self) {
        self.selected_rows.clear();
    }

    /// Get selected row indices.
    pub fn selected_rows(&self) -> &[usize] {
        &self.selected_rows
    }

    /// Get cell value.
    pub fn cell_value(&self, row: usize, col: usize) -> Option<String> {
        self.model.cell_value(row, col)
    }

    /// Get all rows.
    pub fn rows(&self) -> &[FunctionRowData] {
        self.model.rows()
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.model.clear();
        self.selected_rows.clear();
    }

    /// Get column width for a given column index.
    pub fn column_width(&self, col: usize) -> u32 {
        self.column_widths.get(col).copied().unwrap_or(100)
    }

    /// Set column width.
    pub fn set_column_width(&mut self, col: usize, width: u32) {
        if col < self.column_widths.len() {
            self.column_widths[col] = width;
        }
    }
}

impl Default for FunctionDataView {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ParamInfo -- parameter display information
// ---------------------------------------------------------------------------

/// Information about a function parameter for display in the editor.
///
/// Ported from `ParamInfo.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamInfo {
    /// Parameter name.
    pub name: String,
    /// Parameter data type name.
    pub data_type: String,
    /// Parameter ordinal (0-indexed).
    pub ordinal: usize,
    /// Storage type (register, stack, etc.).
    pub storage_type: String,
    /// Register name or stack offset description.
    pub storage_detail: String,
    /// Whether this is a forced-indirect parameter.
    pub is_indirect: bool,
    /// Whether this parameter is a vararg.
    pub is_vararg: bool,
    /// Comment on this parameter.
    pub comment: String,
}

impl ParamInfo {
    /// Create a new parameter info.
    pub fn new(
        name: impl Into<String>,
        data_type: impl Into<String>,
        ordinal: usize,
    ) -> Self {
        Self {
            name: name.into(),
            data_type: data_type.into(),
            ordinal,
            storage_type: String::new(),
            storage_detail: String::new(),
            is_indirect: false,
            is_vararg: false,
            comment: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// ModelChangeListener -- trait for observing function model changes
// ---------------------------------------------------------------------------

/// Trait for listening to changes in function models.
///
/// Ported from `ModelChangeListener.java`.
pub trait ModelChangeListener: Send + Sync {
    /// Called when the model data has changed.
    fn data_changed(&self);

    /// Called when a row has been added.
    fn row_added(&self, index: usize);

    /// Called when a row has been removed.
    fn row_removed(&self, index: usize);

    /// Called when the model has been completely refreshed.
    fn model_refreshed(&self);
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_data_view() {
        let mut view = FunctionDataView::new();
        assert_eq!(view.visible_row_count(), 0);

        view.add_function(FunctionRowData::new(0x400000, "main"));
        view.add_function(FunctionRowData::new(0x401000, "init"));
        assert_eq!(view.visible_row_count(), 2);
    }

    #[test]
    fn test_function_data_view_filter() {
        let mut view = FunctionDataView::new();
        view.add_function(FunctionRowData::new(0x400000, "main"));
        view.add_function(FunctionRowData::new(0x401000, "init"));

        view.set_text_filter(Some("main".into()));
        assert_eq!(view.visible_row_count(), 1);

        view.set_text_filter(None);
        assert_eq!(view.visible_row_count(), 2);
    }

    #[test]
    fn test_function_data_view_selection() {
        let mut view = FunctionDataView::new();
        view.add_function(FunctionRowData::new(0x400000, "f1"));
        view.add_function(FunctionRowData::new(0x401000, "f2"));

        view.select_row(0);
        view.select_row(1);
        assert_eq!(view.selected_rows().len(), 2);

        view.clear_selection();
        assert!(view.selected_rows().is_empty());
    }

    #[test]
    fn test_function_data_view_sort() {
        let mut view = FunctionDataView::new();
        view.add_function(FunctionRowData::new(0x402000, "z"));
        view.add_function(FunctionRowData::new(0x400000, "a"));

        view.sort_by(FunctionTableColumn::Name, true);
        assert_eq!(view.cell_value(0, 1), Some("a".into()));
    }

    #[test]
    fn test_function_data_view_column_width() {
        let mut view = FunctionDataView::new();
        assert_eq!(view.column_width(0), 100);
        view.set_column_width(0, 200);
        assert_eq!(view.column_width(0), 200);
    }

    #[test]
    fn test_param_info() {
        let p = ParamInfo::new("argc", "int", 0);
        assert_eq!(p.name, "argc");
        assert_eq!(p.data_type, "int");
        assert_eq!(p.ordinal, 0);
        assert!(!p.is_indirect);
    }

    #[test]
    fn test_view_external_library_filter() {
        let mut view = FunctionDataView::new();
        view.set_show_external(false);
        view.set_show_library(false);
        assert!(!view.show_external);
        assert!(!view.show_library);
    }
}
