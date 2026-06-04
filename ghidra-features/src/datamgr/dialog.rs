//! DataTypeSyncDialog -- ported from `DataTypeSyncDialog.java`,
//! `DataTypeSyncPanel.java`, `DataTypeSyncTableModel.java`.
//!
//! The dialog that shows synchronization status between a program's
//! data types and their source archives.

use super::sync::{DataTypeSyncInfo, DataTypeSyncState};

/// The layout mode for the sync dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncDialogLayout {
    /// Show all types.
    All,
    /// Show only changed types.
    Changed,
    /// Show only conflicting types.
    Conflicting,
}

/// The data type sync dialog.
///
/// Ported from `DataTypeSyncDialog.java`.
///
/// # Example
///
/// ```
/// use ghidra_features::datamgr::dialog::*;
/// use ghidra_features::datamgr::sync::DataTypeSyncInfo;
///
/// let mut dialog = DataTypeSyncDialog::new("Sync Status");
/// dialog.add_sync_info(DataTypeSyncInfo::new("int", "program", "builtins"));
/// assert_eq!(dialog.row_count(), 1);
/// ```
#[derive(Debug)]
pub struct DataTypeSyncDialog {
    /// The dialog title.
    title: String,
    /// The sync info rows.
    rows: Vec<DataTypeSyncInfo>,
    /// The layout mode.
    layout: SyncDialogLayout,
    /// Whether the dialog is visible.
    visible: bool,
}

impl DataTypeSyncDialog {
    /// Creates a new sync dialog.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            rows: Vec::new(),
            layout: SyncDialogLayout::All,
            visible: false,
        }
    }

    /// Returns the title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Adds a sync info row.
    pub fn add_sync_info(&mut self, info: DataTypeSyncInfo) {
        self.rows.push(info);
    }

    /// Returns the sync info rows.
    pub fn rows(&self) -> &[DataTypeSyncInfo] {
        &self.rows
    }

    /// Returns the row count.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Sets the layout mode.
    pub fn set_layout(&mut self, layout: SyncDialogLayout) {
        self.layout = layout;
    }

    /// Returns the layout mode.
    pub fn layout(&self) -> SyncDialogLayout {
        self.layout
    }

    /// Returns the filtered rows based on the current layout.
    pub fn filtered_rows(&self) -> Vec<&DataTypeSyncInfo> {
        match self.layout {
            SyncDialogLayout::All => self.rows.iter().collect(),
            SyncDialogLayout::Changed => self
                .rows
                .iter()
                .filter(|r| r.has_change())
                .collect(),
            SyncDialogLayout::Conflicting => self
                .rows
                .iter()
                .filter(|r| r.sync_state() == DataTypeSyncState::Conflict)
                .collect(),
        }
    }

    /// Shows the dialog.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hides the dialog.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Returns whether the dialog is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Clears all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

/// The sync table model for the dialog.
#[derive(Debug, Clone)]
pub struct DataTypeSyncTableModel {
    /// The column names.
    columns: Vec<String>,
    /// The rows.
    rows: Vec<DataTypeSyncInfo>,
}

impl DataTypeSyncTableModel {
    /// Creates a new sync table model.
    pub fn new() -> Self {
        Self {
            columns: vec![
                "Data Type".to_string(),
                "Program".to_string(),
                "Source Archive".to_string(),
                "Status".to_string(),
            ],
            rows: Vec::new(),
        }
    }

    /// Returns the column names.
    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    /// Returns the number of columns.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Adds a row.
    pub fn add_row(&mut self, row: DataTypeSyncInfo) {
        self.rows.push(row);
    }

    /// Returns the rows.
    pub fn rows(&self) -> &[DataTypeSyncInfo] {
        &self.rows
    }

    /// Returns the row count.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Gets a cell value by row and column index.
    pub fn get_value_at(&self, row: usize, col: usize) -> Option<String> {
        let r = self.rows.get(row)?;
        match col {
            0 => Some(r.name().to_string()),
            1 => Some(r.ref_dt_path().category_path.display_name().to_string()),
            2 => Some(r.source_dt_path().category_path.display_name().to_string()),
            3 => Some(match r.sync_state() {
                DataTypeSyncState::Conflict => "Conflict".to_string(),
                DataTypeSyncState::Update | DataTypeSyncState::Commit => "Changed".to_string(),
                DataTypeSyncState::InSync => "Synced".to_string(),
                DataTypeSyncState::Orphan => "Orphan".to_string(),
                _ => "Unknown".to_string(),
            }),
            _ => None,
        }
    }

    /// Clears all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

impl Default for DataTypeSyncTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datamgr::sync::DataTypeSyncInfo;
    use ghidra_core::data::{CategoryPath, DataTypePath};

    fn make_sync_info(name: &str, in_sync: bool) -> DataTypeSyncInfo {
        let ref_path = DataTypePath::new(CategoryPath::ROOT, name);
        let source_path = DataTypePath::new(CategoryPath::ROOT, name);
        if in_sync {
            DataTypeSyncInfo::new(
                ref_path,
                name,
                100,
                100,
                "",
                source_path,
                100,
                "",
                true,
                false,
                false,
            )
        } else {
            DataTypeSyncInfo::new(
                ref_path,
                name,
                100,
                50,
                "changed",
                source_path,
                200,
                "source changed",
                true,
                false,
                true,
            )
        }
    }

    #[test]
    fn test_sync_dialog_creation() {
        let dialog = DataTypeSyncDialog::new("Test Sync");
        assert_eq!(dialog.title(), "Test Sync");
        assert_eq!(dialog.row_count(), 0);
        assert!(!dialog.is_visible());
    }

    #[test]
    fn test_sync_dialog_add_info() {
        let mut dialog = DataTypeSyncDialog::new("Test");
        dialog.add_sync_info(make_sync_info("int", true));
        dialog.add_sync_info(make_sync_info("char", true));
        assert_eq!(dialog.row_count(), 2);
    }

    #[test]
    fn test_sync_dialog_show_hide() {
        let mut dialog = DataTypeSyncDialog::new("Test");
        dialog.show();
        assert!(dialog.is_visible());
        dialog.hide();
        assert!(!dialog.is_visible());
    }

    #[test]
    fn test_sync_dialog_layout() {
        let mut dialog = DataTypeSyncDialog::new("Test");
        assert_eq!(dialog.layout(), SyncDialogLayout::All);
        dialog.set_layout(SyncDialogLayout::Changed);
        assert_eq!(dialog.layout(), SyncDialogLayout::Changed);
    }

    #[test]
    fn test_sync_dialog_filtered_rows() {
        let mut dialog = DataTypeSyncDialog::new("Test");
        dialog.add_sync_info(make_sync_info("int", true));
        dialog.add_sync_info(make_sync_info("char", false));

        dialog.set_layout(SyncDialogLayout::All);
        assert_eq!(dialog.filtered_rows().len(), 2);

        dialog.set_layout(SyncDialogLayout::Changed);
        assert_eq!(dialog.filtered_rows().len(), 1);
    }

    #[test]
    fn test_sync_table_model() {
        let mut model = DataTypeSyncTableModel::new();
        assert_eq!(model.column_count(), 4);
        assert_eq!(model.row_count(), 0);

        model.add_row(make_sync_info("int", true));
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn test_sync_table_model_get_value() {
        let mut model = DataTypeSyncTableModel::new();
        model.add_row(make_sync_info("int", true));

        assert_eq!(model.get_value_at(0, 0), Some("int".into()));
        assert!(model.get_value_at(0, 1).is_some());
        assert!(model.get_value_at(0, 2).is_some());
        assert!(model.get_value_at(0, 3).is_some());
        assert_eq!(model.get_value_at(1, 0), None);
    }
}
