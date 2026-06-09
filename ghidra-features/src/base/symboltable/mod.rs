//! Symbol Table plugin for Features/Base.
//!
//! Ported from Ghidra's `Features/SymbolTable` (Java package
//! `ghidra.app.plugin.core.symtable`).  Provides a flat, sortable,
//! filterable table view of all symbols in a program, complementary
//! to the hierarchical symbol tree in [`super::symbol`].
//!
//! # Architecture
//!
//! The Ghidra Java implementation uses a Swing `GTable` backed by an
//! `AbstractSymbolTableModel`.  In Rust we keep the data model and
//! the plugin/provider logic; rendering is delegated to `ghidra-gui`.
//!
//! ```text
//! SymbolTablePlugin
//!   ├── SymbolTableProvider (panel / display configuration)
//!   ├── SymbolTableModel    (row data, sorting, filtering)
//!   └── SymbolFilter        (user filter criteria)
//! ```
//!
//! # Modules
//!
//! | Rust module              | Java class(es)                              |
//! |--------------------------|---------------------------------------------|
//! | `symbol_table_plugin`    | `SymbolTablePlugin`                         |
//! | `symbol_table_provider`  | `SymbolProvider`, `SymbolPanel`             |

pub mod symbol_table_plugin;
pub mod symbol_table_provider;

pub use symbol_table_plugin::*;
pub use symbol_table_provider::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_and_provider_creation() {
        let plugin = SymbolTablePlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_disposed());

        let provider = SymbolTableProvider::new("TestProvider");
        assert_eq!(provider.name(), "TestProvider");
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_plugin_add_symbols_and_query() {
        let mut plugin = SymbolTablePlugin::new("Test");
        plugin.add_symbol(SymbolTableEntry::new("main", 0x401000, EntryKind::Function, "Global"));
        plugin.add_symbol(SymbolTableEntry::new("init", 0x401100, EntryKind::Function, "Global"));
        plugin.add_symbol(SymbolTableEntry::new("data_seg", 0x402000, EntryKind::Label, "Global"));
        assert_eq!(plugin.row_count(), 3);

        let found = plugin.find_by_address(0x401100);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name(), "init");
    }

    #[test]
    fn test_provider_with_program() {
        let mut provider = SymbolTableProvider::new("Test");
        assert!(provider.program_name().is_none());
        provider.set_program_name(Some("test.bin".to_string()));
        assert_eq!(provider.program_name(), Some("test.bin"));
        provider.set_visible(true);
        assert!(provider.is_visible());
    }
}
