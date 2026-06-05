//! Code browser plugin -- the main program listing display window.
//!
//! This module is a port of Ghidra's `ghidra.app.plugin.core.codebrowser`
//! package, which provides the primary code listing view that users interact
//! with when analyzing a program.  The listing displays disassembly, data,
//! and other program information in a formatted, navigable view.
//!
//! # Module Structure
//!
//! - [`address_range_info`] -- Metadata about an address range for table display.
//! - [`action_context`] -- Action context types (`CodeViewerActionContext`,
//!   `OtherPanelContext`).
//! - [`actions`] -- Listing-specific actions (clone, expand/collapse, function
//!   navigation, mark & selection).
//! - [`color_model`] -- Background color models (`LayeredColorModel`,
//!   `MarkerServiceBackgroundColorModel`).
//! - [`hover`] -- Hover service interfaces for tooltip popups.
//! - [`location_memento`] -- Serializable position snapshot.
//! - [`plugin`] -- The abstract and concrete code browser plugin implementations.
//! - [`plugin_interface`] -- The `CodeBrowserPluginInterface` trait.
//! - [`provider`] -- The `CodeViewerProvider` component.
//! - [`selection_plugin`] -- Selection analysis plugin and
//!   `AddressRangeTableModel`.
//!
//! # Architecture
//!
//! The code browser follows Ghidra's plugin architecture:
//!
//! 1. [`CodeBrowserPlugin`] is the top-level plugin that owns a
//!    [`CodeViewerProvider`] (the connected/primary listing view).
//! 2. The provider manages navigation, selection, highlighting, and
//!    service registration (hover, margin, overview).
//! 3. Actions are dispatched to the provider for execution.
//! 4. The selection plugin provides analysis tables for address ranges.
//! 5. Hover services provide tooltips for various listing elements.
//!
//! # Example
//!
//! ```
//! use ghidra_features::codebrowser::plugin::CodeBrowserPlugin;
//! use ghidra_features::codebrowser::provider::CodeViewerProvider;
//! use ghidra_features::codebrowser::plugin_interface::CodeBrowserPluginInterface;
//!
//! let mut plugin = CodeBrowserPlugin::new();
//! assert_eq!(plugin.name(), "CodeBrowserPlugin");
//!
//! // Navigate to an address
//! plugin.connected_provider_mut().go_to("0x401000");
//! assert_eq!(plugin.connected_provider().current_address(), Some("0x401000"));
//! ```

pub mod action_context;
pub mod actions;
pub mod address_range_info;
pub mod color_model;
pub mod hover;
pub mod location_memento;
pub mod plugin;
pub mod plugin_interface;
pub mod provider;
pub mod selection_plugin;
pub mod listing_model;

/// Middle-mouse highlight provider for the code listing.
///
/// Ported from `ghidra.app.plugin.core.codebrowser.ListingMiddleMouseHighlightProvider`.
pub mod middle_mouse_highlight;

/// Code viewer actions and field edit types for the listing.
///
/// Ported from action classes and field-related classes in
/// `ghidra.app.plugin.core.codebrowser`.
pub mod code_viewer_actions;

// Re-export key types at the module root for convenience.
pub use action_context::{CodeViewerActionContext, OtherPanelContext};
pub use address_range_info::AddressRangeInfo;
pub use color_model::{
    LayeredColorModel, ListingBackgroundColorModel, MarkerServiceBackgroundColorModel,
    RgbaColor, SimpleBackgroundColorModel,
};
pub use hover::{HoverContext, HoverServiceRegistry, ListingHoverService};
pub use location_memento::CodeViewerLocationMemento;
pub use plugin::{AbstractCodeBrowserPlugin, CodeBrowserPlugin};
pub use plugin_interface::CodeBrowserPluginInterface;
pub use provider::CodeViewerProvider;
pub use selection_plugin::{AddressRangeTableModel, CodeBrowserSelectionPlugin};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, RwLock};

    /// Integration test: create a plugin, navigate, select, and snapshot.
    #[test]
    fn test_full_workflow() {
        // 1. Create the code browser plugin.
        let mut plugin = CodeBrowserPlugin::new();
        assert_eq!(plugin.name(), "CodeBrowserPlugin");

        // 2. Set the program.
        plugin.inner_mut().set_current_program(Some("test.exe".into()));

        // 3. Navigate to an address.
        plugin.connected_provider_mut().go_to("0x401000");
        assert_eq!(
            plugin.connected_provider().current_address(),
            Some("0x401000")
        );

        // 4. Create a memento.
        let memento = plugin.connected_provider().get_memento();
        assert_eq!(memento.address.as_deref(), Some("0x401000"));

        // 5. Set a selection.
        plugin
            .connected_provider_mut()
            .set_selection(Some("0x401000".into()), Some("0x4010FF".into()));
        assert!(plugin.connected_provider().has_selection());

        // 6. Set a highlight.
        plugin
            .connected_provider_mut()
            .set_highlight(Some("0x401020".into()), Some("0x401030".into()));
        assert!(plugin.connected_provider().current_highlight().is_some());

        // 7. Toggle header and hover.
        plugin.connected_provider_mut().show_header(false);
        assert!(!plugin.connected_provider().is_header_showing());
        plugin.connected_provider_mut().set_hover_enabled(false);
        assert!(!plugin.connected_provider().is_hover_enabled());
    }

    /// Integration test: selection plugin + table model.
    #[test]
    fn test_selection_table_workflow() {
        let mut sel_plugin = CodeBrowserSelectionPlugin::new();
        sel_plugin.set_min_range_size(10);

        let ranges = vec![
            AddressRangeInfo::new(0x1000, 0x10FF, 256, true, 10, 5),
            AddressRangeInfo::new(0x2000, 0x2005, 6, false, 1, 0), // < 10, filtered
            AddressRangeInfo::new(0x3000, 0x3FFF, 4096, true, 20, 10),
        ];

        let model = sel_plugin.create_table_model("test.exe", &ranges);
        assert_eq!(model.row_count(), 2); // Only 2 ranges pass the filter

        // Verify cell values.
        assert_eq!(model.get_cell_value(0, 0), Some("0x1000".to_string()));
        assert_eq!(model.get_cell_value(0, 3), Some("Yes".to_string()));
        assert_eq!(model.get_cell_value(1, 3), Some("Yes".to_string()));

        // Get selection.
        let sel = model.get_program_selection(&[0, 1]);
        assert_eq!(sel.len(), 2);
    }

    /// Integration test: color model composition.
    #[test]
    fn test_color_model_composition() {
        use color_model::RgbaColor;

        let white = RgbaColor::new(255, 255, 255);
        let red = RgbaColor::new(255, 0, 0);

        let primary = SimpleBackgroundColorModel::new(white);
        let colors = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let secondary = MarkerServiceBackgroundColorModel::new(Arc::clone(&colors));
        secondary.set_marker_color(0x1000, red);

        let layered = LayeredColorModel::new(Box::new(primary), Box::new(secondary));

        // At 0x1000, secondary has a marker color -> should be used.
        assert_eq!(layered.get_background_color(0x1000), red);
        // At 0x2000, no marker -> primary default.
        assert_eq!(layered.get_background_color(0x2000), white);
    }

    /// Integration test: hover service registry.
    #[test]
    fn test_hover_service_integration() {
        let mut registry = HoverServiceRegistry::new();
        registry.register(Box::new(hover::DataTypeListingHover));
        registry.register(Box::new(hover::TruncatedTextListingHover));

        let ctx = HoverContext {
            text: Some("int x = 42;".into()),
            ..Default::default()
        };

        // TruncatedTextListingHover returns the text.
        let text = registry.get_hover_text(&ctx);
        assert_eq!(text, Some("int x = 42;".into()));
    }

    /// Integration test: memento save/restore roundtrip.
    #[test]
    fn test_memento_roundtrip() {
        let mut state = std::collections::HashMap::new();
        state.insert("ADDRESS".to_string(), "0x401000".to_string());
        state.insert("CURSOR_OFFSET".to_string(), "15".to_string());

        let memento = CodeViewerLocationMemento::from_state(&state);
        assert_eq!(memento.address.as_deref(), Some("0x401000"));
        assert_eq!(memento.cursor_offset(), 15);

        // Save and restore.
        let saved = memento.save_state();
        let restored = CodeViewerLocationMemento::from_state(&saved);
        assert_eq!(restored, memento);
    }

    /// Integration test: actions enumeration.
    #[test]
    fn test_actions_integration() {
        let actions = actions::all_actions();
        assert_eq!(actions.len(), 8);

        // Verify all actions have names.
        for action in &actions {
            assert!(!action.name().is_empty());
            assert!(!action.display_name().is_empty());
            assert!(action.is_enabled());
        }
    }

    /// Integration test: disconnected provider lifecycle.
    #[test]
    fn test_disconnected_provider_lifecycle() {
        let mut plugin = AbstractCodeBrowserPlugin::new("TestPlugin");

        // Create a disconnected provider.
        let _ = plugin.create_disconnected_provider();
        assert_eq!(plugin.disconnected_providers().len(), 1);
        let id = plugin.disconnected_providers()[0].id();

        // Remove it.
        let removed = plugin.remove_disconnected_provider(id);
        assert!(removed.is_some());
        assert_eq!(plugin.disconnected_providers().len(), 0);
    }

    /// Integration test: plugin options system.
    #[test]
    fn test_plugin_options_system() {
        let mut plugin = AbstractCodeBrowserPlugin::new("TestPlugin");

        // Set display options.
        plugin.set_bool_option("highlight_cursor_line", true);
        plugin.set_int_option("font_size", 14);
        plugin.set_string_option("theme", "dark");

        assert!(plugin.get_bool_option("highlight_cursor_line", false));
        assert_eq!(plugin.get_int_option("font_size", 12), 14);
        assert_eq!(plugin.get_string_option("theme", "light"), "dark");

        // Default fallback.
        assert!(!plugin.get_bool_option("nonexistent", false));
    }
}
