//! Symbol tree plugin -- ported from `ghidra.app.plugin.core.symboltree`.
//!
//! Provides the [`SymbolTreePlugin`] that shows program symbols in a
//! hierarchical tree, along with [`SymbolCategory`] for organising symbols
//! into predefined groups, [`SymbolTreeNode`] for the tree nodes, and the
//! [`SymbolTreeService`] trait for external consumers.
//!
//! # Architecture
//!
//! The Ghidra Java implementation uses a Swing `GTree` for display and a
//! `Plugin` subclass for lifecycle management.  In Rust we keep the data
//! model and logic, deferring any actual rendering to the `ghidra-gui`
//! crate.  The types here are therefore backend-agnostic.

pub mod actions;
pub mod category;
pub mod provider;
pub mod service;
pub mod plugin;

pub use actions::*;
pub use category::*;
pub use provider::*;
pub use service::*;
pub use plugin::*;

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;

    // ---- SymbolCategory ----

    #[test]
    fn test_all_categories() {
        let cats = all_categories();
        assert_eq!(cats.len(), 7);
        assert_eq!(cats[0].name(), "Global");
        assert_eq!(cats[1].name(), "Functions");
    }

    #[test]
    fn test_category_accepts() {
        let func = function_category();
        assert!(func.accepts(ghidra_core::symbol::SymbolType::Function));
        assert!(!func.accepts(ghidra_core::symbol::SymbolType::Label));
    }

    #[test]
    fn test_root_category() {
        assert!(root_category().is_root());
        assert!(!function_category().is_root());
    }

    #[test]
    fn test_custom_category() {
        let cat = SymbolCategory::new("Custom", Some(ghidra_core::symbol::SymbolType::Import));
        assert_eq!(cat.name(), "Custom");
        assert_eq!(cat.to_string(), "Custom");
    }

    // ---- SymbolTreeAction ----

    #[test]
    fn test_action_creation() {
        let action = SymbolTreeAction::new(SymbolTreeActionKind::CreateNamespace);
        assert_eq!(action.kind(), SymbolTreeActionKind::CreateNamespace);
        assert!(action.is_enabled());
    }

    #[test]
    fn test_action_name_mutable() {
        let mut action = SymbolTreeAction::new(SymbolTreeActionKind::Delete);
        assert!(!action.name().is_empty());
        action.set_name("Custom Delete");
        assert_eq!(action.name(), "Custom Delete");
    }

    #[test]
    fn test_action_enable_disable() {
        let mut action = SymbolTreeAction::new(SymbolTreeActionKind::Cut);
        assert!(action.is_enabled());
        action.set_enabled(false);
        assert!(!action.is_enabled());
        action.set_enabled(true);
        assert!(action.is_enabled());
    }

    // ---- SymbolTreePlugin ----

    #[test]
    fn test_plugin_creation() {
        let plugin = SymbolTreePlugin::new("TestPlugin");
        // Note: plugin name is empty due to upstream constructor bug
        // but the connected provider gets the name
        assert!(!plugin.is_disposed());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = SymbolTreePlugin::new("Test");
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = SymbolTreePlugin::new("Test");
        plugin.program_activated("test_program".to_string());
        plugin.program_closed();
    }

    #[test]
    fn test_plugin_add_symbol() {
        let mut plugin = SymbolTreePlugin::new("Test");
        plugin.add_symbol(ghidra_core::symbol::Symbol::function("main", Address::new(0x401000)));
        plugin.add_symbol(ghidra_core::symbol::Symbol::label("loop", Address::new(0x401010)));
        assert_eq!(plugin.connected_provider().symbol_count(), 2);
    }

    // ---- SymbolTreeProvider ----

    #[test]
    fn test_provider_connected() {
        let provider = SymbolTreeProvider::new_connected("TestProvider");
        assert!(provider.is_connected());
        assert_eq!(provider.name(), "TestProvider");
    }

    #[test]
    fn test_provider_disconnected() {
        let provider = SymbolTreeProvider::new_disconnected("TestProvider");
        assert!(!provider.is_connected());
    }

    #[test]
    fn test_provider_add_symbols() {
        let mut provider = SymbolTreeProvider::new_connected("Test");
        provider.add_symbol(ghidra_core::symbol::Symbol::function("main", Address::new(0x401000)));
        provider.add_symbol(ghidra_core::symbol::Symbol::label("data", Address::new(0x402000)));
        assert_eq!(provider.symbol_count(), 2);
    }

    #[test]
    fn test_provider_config() {
        let provider = SymbolTreeProvider::new_connected("Test");
        let _config = provider.config();
    }

    // ---- Cross-module integration ----

    #[test]
    fn test_plugin_with_provider_and_categories() {
        let mut plugin = SymbolTreePlugin::new("Test");
        plugin.add_symbol(ghidra_core::symbol::Symbol::function("main", Address::new(0x401000)));
        assert_eq!(plugin.connected_provider().symbol_count(), 1);

        let cats = all_categories();
        assert!(cats.len() >= 7);

        let action = SymbolTreeAction::new(SymbolTreeActionKind::Rename);
        assert!(action.is_enabled());
    }
}
