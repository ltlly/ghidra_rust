//! Table Chooser framework -- plugin and dialog components.
//!
//! Ported from `ghidra.app.plugin.core.tablechooser` (Features/Base).
//!
//! This module provides the higher-level plugin and dialog components
//! that build on the base [`crate::base::tablechooser`] data model:
//!
//! - [`TableChooserPlugin`] -- Plugin lifecycle, options, and dialog
//!   management.
//! - [`TableChooserDialogState`] -- The dialog-level state with column
//!   configuration, filtering, executor binding, and status text.
//!
//! # Architecture
//!
//! The base module (`crate::base::tablechooser`) defines the core data
//! model traits and structures: `AddressableRowObject`, `ColumnDisplay`,
//! `TableChooserExecutor`, `TableChooserTableModel`, and a basic
//! `TableChooserDialog`.
//!
//! This module adds the Ghidra plugin integration layer on top:
//!
//! ```text
//! TableChooserPlugin
//!   |-- manages options, program lifecycle
//!   |-- owns Option<TableChooserDialogState>
//!
//! TableChooserDialogState
//!   |-- wraps base::TableChooserDialog
//!   |-- column visibility & sort configuration
//!   |-- filter text search
//!   |-- executor binding
//!   |-- status text
//! ```

pub mod table_chooser_dialog;
pub mod table_chooser_plugin;

pub use table_chooser_dialog::{ColumnConfig, TableChooserDialogState};
pub use table_chooser_plugin::{TableChooserDialogState as TableChooserPluginDialogState, TableChooserPlugin, TableChooserPluginOptions};

// Re-export the renamed plugin dialog state to avoid ambiguity with the dialog state.
// The plugin's TableChooserDialogState is a simple tracking struct;
// the dialog's TableChooserDialogState is the full generic dialog model.
// Users should prefer the dialog state for most use cases.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::tablechooser::{Address, AddressableRowObject};

    #[derive(Debug, Clone)]
    struct TestRow {
        addr: u64,
        name: String,
    }

    impl AddressableRowObject for TestRow {
        fn get_address(&self) -> Address {
            Address(self.addr)
        }
    }

    #[test]
    fn test_module_reexports_plugin() {
        let plugin = TableChooserPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
    }

    #[test]
    fn test_module_reexports_dialog_state() {
        let dialog = TableChooserDialogState::<TestRow>::new("TestDialog");
        assert_eq!(dialog.title(), "TestDialog");
    }

    #[test]
    fn test_module_reexports_column_config() {
        let cfg = ColumnConfig::new("TestColumn");
        assert_eq!(cfg.name, "TestColumn");
    }

    #[test]
    fn test_module_reexports_plugin_options() {
        let opts = TableChooserPluginOptions::new();
        assert!(opts.hex_display);
    }
}
