//! DWARFExternalDebugFilesPlugin -- configuration entry point.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.DWARFExternalDebugFilesPlugin`.
//!
//! In the Java version this is a Ghidra [`Plugin`] that registers a menu
//! action to open the DWARF external debug files configuration dialog.
//! In the Rust port we provide the equivalent configuration logic without
//! the Swing GUI, exposing the same entry-point via a simple function.

use super::debug_info_provider_registry::{DebugInfoProviderCreatorContext, DebugInfoProviderRegistry};
use super::external_debug_files_service::ExternalDebugFilesService;

/// Help topic identifier used by the Ghidra help system.
pub const HELP_TOPIC: &str = "DWARFExternalDebugFilesPlugin";

/// Menu path for the configuration action (matches the Java constant).
pub const MENU_EDIT: &str = "Edit";

/// Menu group for the configuration action.
pub const TOOL_OPTIONS_MENU_GROUP: &str = "zzz_Tool_Options";

/// Plugin status constant.
pub const PLUGIN_STATUS: &str = "RELEASED";

/// Plugin package name.
pub const PLUGIN_PACKAGE: &str = "CorePluginPackage";

/// Plugin category.
pub const PLUGIN_CATEGORY: &str = "Common";

/// Short description of the plugin.
pub const SHORT_DESCRIPTION: &str = "DWARF External Debug Files";

/// Full description of the plugin.
pub const DESCRIPTION: &str = "Configure how the DWARF analyzer finds external debug files.";

/// Action name for the configuration menu item.
pub const ACTION_NAME: &str = "DWARF External Debug Config";

/// Plugin information structure.
///
/// In the Java version this is annotated via `@PluginInfo`. Here we
/// store the same metadata as a plain struct.
#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub status: &'static str,
    pub package_name: &'static str,
    pub category: &'static str,
    pub short_description: &'static str,
    pub description: &'static str,
}

impl PluginInfo {
    /// Returns the default plugin info for this plugin.
    pub fn default_info() -> Self {
        Self {
            status: PLUGIN_STATUS,
            package_name: PLUGIN_PACKAGE,
            category: PLUGIN_CATEGORY,
            short_description: SHORT_DESCRIPTION,
            description: DESCRIPTION,
        }
    }
}

/// The DWARF External Debug Files plugin.
///
/// In the Java version this extends `Plugin` and registers a menu action
/// via `ActionBuilder`.  In the Rust port we expose the configuration
/// functionality directly.
#[derive(Debug)]
pub struct DWARFExternalDebugFilesPlugin {
    info: PluginInfo,
}

impl DWARFExternalDebugFilesPlugin {
    /// Creates a new plugin instance.
    pub fn new() -> Self {
        Self {
            info: PluginInfo::default_info(),
        }
    }

    /// Returns the plugin info.
    pub fn info(&self) -> &PluginInfo {
        &self.info
    }

    /// Returns the help topic for this plugin.
    pub fn help_topic(&self) -> &str {
        HELP_TOPIC
    }

    /// Opens the configuration dialog (or in the Rust port, returns the
    /// current configuration as an [`ExternalDebugFilesService`]).
    ///
    /// In the Java version this is triggered by the menu action. Here we
    /// provide the equivalent by loading the saved configuration.
    pub fn open_configuration() -> ExternalDebugFilesService {
        let context = DebugInfoProviderCreatorContext::new();
        ExternalDebugFilesService::from_config_with_context("", &context)
            .unwrap_or_else(ExternalDebugFilesService::default_service)
    }

    /// Creates the configuration action descriptor.
    ///
    /// In the Java version this is done via `ActionBuilder`. Here we
    /// return the action metadata as a struct.
    pub fn create_action(&self) -> ActionDescriptor {
        ActionDescriptor {
            name: ACTION_NAME.to_string(),
            owner: self.info.short_description.to_string(),
            menu_path: vec![MENU_EDIT.to_string(), ACTION_NAME.to_string()],
            menu_group: TOOL_OPTIONS_MENU_GROUP.to_string(),
            help_topic: HELP_TOPIC.to_string(),
            help_anchor: "Configuration".to_string(),
        }
    }
}

impl Default for DWARFExternalDebugFilesPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Describes a menu action that would be registered with the Ghidra tool.
///
/// This is a Rust-only abstraction since we don't have the full Swing
/// docking framework.
#[derive(Debug, Clone)]
pub struct ActionDescriptor {
    /// The action name.
    pub name: String,
    /// The owner plugin name.
    pub owner: String,
    /// The menu path (list of menu items from root to leaf).
    pub menu_path: Vec<String>,
    /// The menu group for ordering.
    pub menu_group: String,
    /// The help topic.
    pub help_topic: String,
    /// The help anchor within the topic.
    pub help_anchor: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = DWARFExternalDebugFilesPlugin::new();
        assert_eq!(plugin.help_topic(), "DWARFExternalDebugFilesPlugin");
    }

    #[test]
    fn test_plugin_info() {
        let plugin = DWARFExternalDebugFilesPlugin::new();
        let info = plugin.info();
        assert_eq!(info.status, "RELEASED");
        assert_eq!(info.category, "Common");
        assert_eq!(info.short_description, "DWARF External Debug Files");
    }

    #[test]
    fn test_plugin_default() {
        let plugin = DWARFExternalDebugFilesPlugin::default();
        assert_eq!(plugin.help_topic(), HELP_TOPIC);
    }

    #[test]
    fn test_create_action() {
        let plugin = DWARFExternalDebugFilesPlugin::new();
        let action = plugin.create_action();
        assert_eq!(action.name, "DWARF External Debug Config");
        assert_eq!(action.menu_path.len(), 2);
        assert_eq!(action.menu_path[0], "Edit");
        assert_eq!(action.menu_path[1], "DWARF External Debug Config");
        assert_eq!(action.help_topic, "DWARFExternalDebugFilesPlugin");
        assert_eq!(action.help_anchor, "Configuration");
    }

    #[test]
    fn test_open_configuration() {
        let service = DWARFExternalDebugFilesPlugin::open_configuration();
        // Should return a valid service (either from config or default)
        assert!(!service.providers().is_empty() || service.storage().name().len() > 0);
    }

    #[test]
    fn test_plugin_info_default() {
        let info = PluginInfo::default_info();
        assert_eq!(info.status, PLUGIN_STATUS);
        assert_eq!(info.package_name, PLUGIN_PACKAGE);
        assert_eq!(info.category, PLUGIN_CATEGORY);
        assert_eq!(info.short_description, SHORT_DESCRIPTION);
        assert_eq!(info.description, DESCRIPTION);
    }

    #[test]
    fn test_action_descriptor_clone() {
        let plugin = DWARFExternalDebugFilesPlugin::new();
        let action = plugin.create_action();
        let cloned = action.clone();
        assert_eq!(action.name, cloned.name);
        assert_eq!(action.menu_path, cloned.menu_path);
    }
}
