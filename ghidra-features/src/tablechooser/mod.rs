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

pub use table_chooser_dialog::{ColumnConfig, ExecutionResult, TableChooserDialogState};
pub use table_chooser_plugin::{
    TableChooserDialogStateWrapper, TableChooserPlugin, TableChooserPluginOptions,
};

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

    #[test]
    fn test_module_reexports_execution_result() {
        let result = ExecutionResult {
            processed: 5,
            removed: 3,
            cancelled: false,
        };
        assert_eq!(result.processed, 5);
        assert_eq!(result.removed, 3);
    }

    #[test]
    fn test_module_reexports_dialog_state_wrapper() {
        let wrapper = TableChooserDialogStateWrapper {
            title: "W".into(),
            row_count: 0,
            column_count: 0,
            visible: true,
            busy: false,
        };
        assert_eq!(wrapper.title, "W");
    }
}
