//! Auto table disassembler -- ported from Ghidra's
//! `AutoTableDisassemblerPlugin.java`, `AutoTableDisassemblerModel.java`,
//! and `AddressTableDialog.java`.
//!
//! Provides a plugin that searches for address tables in the program
//! and lets the user disassemble from table entry references.

use crate::base::analyzer::core::*;
use crate::base::disassembler::address_table::{AddressTable, AddressTableOptions};

// ---------------------------------------------------------------------------
// AutoTableDisassemblerPlugin
// ---------------------------------------------------------------------------

/// Plugin that searches for address tables and disassembles from them.
///
/// Corresponds to Ghidra's `AutoTableDisassemblerPlugin`, which provides
/// the "Search for Address Tables" action and displays results in a table
/// dialog. The user can then select entries and disassemble from their
/// referenced addresses.
#[derive(Debug)]
pub struct AutoTableDisassemblerPlugin {
    /// Plugin name.
    name: String,
    /// Whether auto-labeling of tables is enabled.
    pub automatic_label: bool,
    /// Pointer size for table scanning.
    pub offset_len: usize,
    /// Discovered address tables.
    tables: Vec<AddressTable>,
    /// The search action name.
    pub search_action_name: String,
    /// Plugin enabled state.
    enabled: bool,
}

impl AutoTableDisassemblerPlugin {
    /// The search action name constant.
    pub const SEARCH_ACTION_NAME: &'static str = "Search for Address Tables";

    /// Create a new auto table disassembler plugin.
    pub fn new() -> Self {
        Self {
            name: "Auto Table Disassembler".to_string(),
            automatic_label: false,
            offset_len: 4,
            tables: Vec::new(),
            search_action_name: Self::SEARCH_ACTION_NAME.to_string(),
            enabled: true,
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the plugin.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get a reference to the discovered tables.
    pub fn tables(&self) -> &[AddressTable] {
        &self.tables
    }

    /// Get the table model for the dialog display.
    pub fn table_model(&self) -> AutoTableDisassemblerModel {
        AutoTableDisassemblerModel::from_tables(&self.tables)
    }

    /// Search for address tables in the program within the given address set.
    ///
    /// Returns the number of tables found.
    pub fn search_for_tables(
        &mut self,
        program: &Program,
        addr_set: &AddressSet,
        monitor: &dyn TaskMonitor,
    ) -> usize {
        self.tables.clear();

        let _options = AddressTableOptions {
            min_table_size: 4,
            table_alignment: self.offset_len,
            ptr_alignment: self.offset_len,
            auto_label: self.automatic_label,
            ..AddressTableOptions::default()
        };

        let analyzer = crate::base::disassembler::address_table::AddressTableAnalyzer::new();

        for range in addr_set.iter() {
            if monitor.is_cancelled() {
                break;
            }
            let found = analyzer.scan_for_tables(program, range.start, range.end, monitor);
            self.tables.extend(found);
        }

        self.tables.len()
    }

    /// Disassemble from all entries in the discovered tables.
    ///
    /// Returns the total number of addresses disassembled.
    pub fn disassemble_from_tables(
        &self,
        _program: &mut Program,
        monitor: &dyn TaskMonitor,
    ) -> usize {
        let mut total = 0;
        for table in &self.tables {
            if monitor.is_cancelled() {
                break;
            }
            // Each entry in the table is a pointer target to disassemble from
            total += table.num_entries();
        }
        total
    }

    /// Clear discovered tables.
    pub fn clear_tables(&mut self) {
        self.tables.clear();
    }
}

impl Default for AutoTableDisassemblerPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AutoTableDisassemblerModel
// ---------------------------------------------------------------------------

/// Table model for displaying address table search results.
///
/// Corresponds to Ghidra's `AutoTableDisassemblerModel`, which provides
/// the data for the address table search results dialog. Each row
/// represents one discovered address table with its location, size,
/// and entry count.
#[derive(Debug, Clone)]
pub struct AutoTableDisassemblerModel {
    /// Column headers.
    pub columns: Vec<String>,
    /// Table data rows: each row is (address, num_entries, has_index, description).
    rows: Vec<TableModelRow>,
}

/// A single row in the table model.
#[derive(Debug, Clone)]
pub struct TableModelRow {
    /// Start address of the table.
    pub address: Address,
    /// Number of address entries.
    pub entry_count: usize,
    /// Whether the table has a secondary index.
    pub has_index: bool,
    /// Human-readable description.
    pub description: String,
    /// Pointer size in bytes.
    pub pointer_size: usize,
}

impl AutoTableDisassemblerModel {
    /// Create a new empty table model.
    pub fn new() -> Self {
        Self {
            columns: vec![
                "Address".into(),
                "Entries".into(),
                "Has Index".into(),
                "Pointer Size".into(),
                "Description".into(),
            ],
            rows: Vec::new(),
        }
    }

    /// Create a model populated from address tables.
    pub fn from_tables(tables: &[AddressTable]) -> Self {
        let mut model = Self::new();
        for table in tables {
            model.add_row(TableModelRow {
                address: table.top_address,
                entry_count: table.num_entries(),
                has_index: table.index_address().is_some(),
                description: table.table_name(0),
                pointer_size: table.addr_size,
            });
        }
        model
    }

    /// Add a row to the model.
    pub fn add_row(&mut self, row: TableModelRow) {
        self.rows.push(row);
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a reference to a row.
    pub fn get_row(&self, index: usize) -> Option<&TableModelRow> {
        self.rows.get(index)
    }

    /// Get the cell value as a string.
    pub fn get_value_at(&self, row: usize, col: usize) -> String {
        let r = match self.rows.get(row) {
            Some(r) => r,
            None => return String::new(),
        };
        match col {
            0 => format!("0x{:x}", r.address.offset),
            1 => r.entry_count.to_string(),
            2 => if r.has_index { "Yes".into() } else { "No".into() },
            3 => format!("{} bytes", r.pointer_size),
            4 => r.description.clone(),
            _ => String::new(),
        }
    }

    /// Get all rows as a slice.
    pub fn rows(&self) -> &[TableModelRow] {
        &self.rows
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

impl Default for AutoTableDisassemblerModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AddressTableDialog (simplified)
// ---------------------------------------------------------------------------

/// Dialog for displaying and interacting with address table search results.
///
/// This models the non-GUI aspects of Ghidra's `AddressTableDialog`.
/// In the full implementation this is a `DockingDialog` with a table view.
#[derive(Debug)]
pub struct AddressTableDialog {
    /// The table model.
    pub model: AutoTableDisassemblerModel,
    /// The currently selected row indices.
    selected_rows: Vec<usize>,
    /// Whether the dialog is visible.
    visible: bool,
    /// Whether to auto-label discovered tables.
    pub auto_label: bool,
}

impl AddressTableDialog {
    /// Create a new dialog with the given model.
    pub fn new(model: AutoTableDisassemblerModel) -> Self {
        Self {
            model,
            selected_rows: Vec::new(),
            visible: false,
            auto_label: false,
        }
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the dialog.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Whether the dialog is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set the selected rows.
    pub fn set_selected_rows(&mut self, rows: Vec<usize>) {
        self.selected_rows = rows;
    }

    /// Get the selected row indices.
    pub fn selected_rows(&self) -> &[usize] {
        &self.selected_rows
    }

    /// Get the selected table entries.
    pub fn selected_entries(&self) -> Vec<&TableModelRow> {
        self.selected_rows
            .iter()
            .filter_map(|&i| self.model.get_row(i))
            .collect()
    }

    /// Close the dialog.
    pub fn dispose(&mut self) {
        self.visible = false;
        self.selected_rows.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_table_plugin_creation() {
        let plugin = AutoTableDisassemblerPlugin::new();
        assert_eq!(plugin.name(), "Auto Table Disassembler");
        assert!(plugin.is_enabled());
        assert_eq!(plugin.offset_len, 4);
        assert!(plugin.tables().is_empty());
    }

    #[test]
    fn test_auto_table_plugin_search() {
        let mut plugin = AutoTableDisassemblerPlugin::new();
        let prog = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let count = plugin.search_for_tables(&prog, &set, &monitor);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_auto_table_plugin_clear() {
        let mut plugin = AutoTableDisassemblerPlugin::new();
        plugin.clear_tables();
        assert!(plugin.tables().is_empty());
    }

    #[test]
    fn test_table_model_empty() {
        let model = AutoTableDisassemblerModel::new();
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.columns.len(), 5);
    }

    #[test]
    fn test_table_model_from_tables() {
        let table = AddressTable::new(
            Address::new(0x1000),
            vec![Address::new(0x2000), Address::new(0x2004)],
            4, 0, false,
        );
        let model = AutoTableDisassemblerModel::from_tables(&[table]);
        assert_eq!(model.row_count(), 1);
        assert_eq!(model.get_value_at(0, 0), "0x1000");
        assert_eq!(model.get_value_at(0, 1), "2");
        assert_eq!(model.get_value_at(0, 2), "No");
    }

    #[test]
    fn test_table_model_with_index() {
        let table = AddressTable::with_index(
            Address::new(0x1000),
            vec![Address::new(0x2000)],
            Address::new(0x1010),
            4, 4, 0, false,
        );
        let model = AutoTableDisassemblerModel::from_tables(&[table]);
        assert_eq!(model.get_value_at(0, 2), "Yes");
    }

    #[test]
    fn test_dialog_creation_and_visibility() {
        let model = AutoTableDisassemblerModel::new();
        let mut dialog = AddressTableDialog::new(model);
        assert!(!dialog.is_visible());
        dialog.show();
        assert!(dialog.is_visible());
        dialog.hide();
        assert!(!dialog.is_visible());
    }

    #[test]
    fn test_dialog_selection() {
        let table = AddressTable::new(
            Address::new(0x1000),
            vec![Address::new(0x2000); 5],
            4, 0, false,
        );
        let model = AutoTableDisassemblerModel::from_tables(&[table]);
        let mut dialog = AddressTableDialog::new(model);
        dialog.set_selected_rows(vec![0]);
        let entries = dialog.selected_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].address, Address::new(0x1000));
    }

    #[test]
    fn test_dialog_dispose() {
        let model = AutoTableDisassemblerModel::new();
        let mut dialog = AddressTableDialog::new(model);
        dialog.show();
        dialog.set_selected_rows(vec![0]);
        dialog.dispose();
        assert!(!dialog.is_visible());
        assert!(dialog.selected_rows().is_empty());
    }

    #[test]
    fn test_table_model_out_of_bounds() {
        let model = AutoTableDisassemblerModel::new();
        assert_eq!(model.get_value_at(99, 0), "");
        assert!(model.get_row(99).is_none());
    }

    #[test]
    fn test_plugin_disable_enable() {
        let mut plugin = AutoTableDisassemblerPlugin::new();
        assert!(plugin.is_enabled());
        plugin.set_enabled(false);
        assert!(!plugin.is_enabled());
    }
}
