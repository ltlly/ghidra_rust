//! Symbol Tree Plugin -- displays program symbols in a tree hierarchy.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.symboltree` package.
//!
//! This module provides the symbol tree plugin that displays symbols from
//! the program in a tree organized by namespace.  Supports symbol operations
//! like rename, delete, move, create namespaces/classes, and external
//! library management.
//!
//! # Architecture
//!
//! ```text
//! SymbolTreePlugin
//!   ├── SymbolTreeProvider   (tree view component, event buffering)
//!   ├── TreeNode             (tree node model)
//!   ├── PendingTask          (buffered domain-object events)
//!   └── TreeState            (expanded/selected snapshot)
//! ```
//!
//! # Modules
//!
//! | Rust module              | Java class(es)                              |
//! |--------------------------|---------------------------------------------|
//! | `symbol_tree_plugin`     | `SymbolTreePlugin`, `SymbolTreeService`     |
//! | `symbol_tree_provider`   | `SymbolTreeProvider`, `DisconnectedSymbolTreeProvider` |

pub mod symbol_tree_plugin;
pub mod symbol_tree_provider;

pub use symbol_tree_plugin::{
    SymbolTreePlugin, OPTIONS_CATEGORY, OPTION_NAME_GROUP_THRESHOLD, DEFAULT_NODE_GROUP_THRESHOLD,
};
pub use symbol_tree_provider::{PendingTask, SymbolTreeProvider, TreeNode, TreeState};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_and_provider_creation() {
        let plugin = SymbolTreePlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_disposed());

        let provider = SymbolTreeProvider::new("TestProvider");
        assert_eq!(provider.name(), "TestProvider");
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        plugin.init();

        plugin.program_activated("test.bin");
        assert_eq!(plugin.program_name(), Some("test.bin"));

        // Provider should be bound to the program.
        assert_eq!(
            plugin.connected_provider().program_name(),
            Some("test.bin")
        );

        plugin.program_deactivated();
        assert!(plugin.program_name().is_none());
    }

    #[test]
    fn test_plugin_disconnected_provider_flow() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        plugin.init();
        plugin.program_activated("test.bin");

        plugin.create_disconnected_provider("test.bin");
        assert_eq!(plugin.disconnected_provider_count(), 1);

        let dp = plugin.disconnected_provider(0).unwrap();
        assert_eq!(dp.program_name(), Some("test.bin"));

        plugin.close_disconnected_provider(0);
        assert_eq!(plugin.disconnected_provider_count(), 0);
    }

    #[test]
    fn test_provider_event_buffering() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        provider.rebuild_tree();

        provider.symbol_added("main", "Global", "0x401000", "Function");
        provider.symbol_added("init", "Global", "0x401100", "Function");
        assert_eq!(provider.pending_task_count(), 2);

        provider.flush_tasks();
        assert_eq!(provider.pending_task_count(), 0);
    }

    #[test]
    fn test_provider_tree_state_persistence() {
        let mut provider = SymbolTreeProvider::new("TestProvider");
        provider.set_visible(true);
        provider.set_program(Some("test.bin".to_string()));

        // Expand Functions node.
        if let Some(funcs) = provider.root_mut().find_child_mut("Functions") {
            funcs.expanded = true;
        }

        // Save state and deactivate.
        provider.program_deactivated();
        assert!(provider.program_name().is_none());

        // Re-activate and rebuild -- state should be restored.
        provider.set_visible(true);
        provider.set_program(Some("test.bin".to_string()));
        let funcs = provider.root().find_child("Functions").unwrap();
        assert!(funcs.expanded);
    }

    #[test]
    fn test_constants() {
        assert_eq!(OPTIONS_CATEGORY, "Symbol Tree");
        assert_eq!(OPTION_NAME_GROUP_THRESHOLD, "Group Threshold");
        assert_eq!(DEFAULT_NODE_GROUP_THRESHOLD, 200);
    }

    #[test]
    fn test_reexports() {
        // Verify all re-exported types are accessible.
        let _plugin = SymbolTreePlugin::default();
        let _provider = SymbolTreeProvider::default();
        let _node = TreeNode::new("test");
        let _state = TreeState::default();
    }
}
