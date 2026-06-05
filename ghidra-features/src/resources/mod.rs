//! Resource actions plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.resources` package.
//!
//! Provides actions for managing Ghidra resources such as icons,
//! images, and other UI assets.
//!
//! # Key Types
//!
//! - [`ResourceActionsPlugin`] -- Plugin providing resource-related actions
//! - [`ResourceType`] -- Types of resources managed by the plugin
//! - [`ResourceInfo`] -- Metadata about a resource

/// Icon definitions for the Ghidra UI.
///
/// Ported from `ghidra.app.plugin.core.resources` icon classes.
pub mod icons;

use std::collections::HashMap;
use std::path::PathBuf;

/// Default resource directory name.
pub const RESOURCE_DIR: &str = "resources";

/// Supported graphic format extensions.
pub const GRAPHIC_FORMATS: &[&str] = &["png", "gif", "jpg", "jpeg", "svg", "ico"];

// ---------------------------------------------------------------------------
// Resource type
// ---------------------------------------------------------------------------

/// Types of resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceType {
    /// Icon image.
    Icon,
    /// General image.
    Image,
    /// Help documentation.
    Help,
    /// Localization/translation file.
    Localization,
    /// Theme definition.
    Theme,
    /// Other resource type.
    Other,
}

impl ResourceType {
    /// Display name for this resource type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Icon => "Icon",
            Self::Image => "Image",
            Self::Help => "Help",
            Self::Localization => "Localization",
            Self::Theme => "Theme",
            Self::Other => "Other",
        }
    }
}

// ---------------------------------------------------------------------------
// Resource info
// ---------------------------------------------------------------------------

/// Metadata about a resource.
#[derive(Debug, Clone)]
pub struct ResourceInfo {
    /// The resource key/path.
    pub key: String,
    /// The resource type.
    pub resource_type: ResourceType,
    /// File system path, if applicable.
    pub path: Option<PathBuf>,
    /// Description of the resource.
    pub description: String,
}

impl ResourceInfo {
    /// Create a new resource info.
    pub fn new(
        key: impl Into<String>,
        resource_type: ResourceType,
    ) -> Self {
        Self {
            key: key.into(),
            resource_type,
            path: None,
            description: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Resource actions plugin
// ---------------------------------------------------------------------------

/// Plugin providing resource-related actions.
///
/// Ported from `ghidra.app.plugin.core.resources.ResourceActionsPlugin`.
#[derive(Debug)]
pub struct ResourceActionsPlugin {
    /// Registered resources.
    resources: HashMap<String, ResourceInfo>,
}

impl ResourceActionsPlugin {
    /// Create a new resource actions plugin.
    pub fn new() -> Self {
        Self {
            resources: HashMap::new(),
        }
    }

    /// Register a resource.
    pub fn register_resource(&mut self, info: ResourceInfo) {
        self.resources.insert(info.key.clone(), info);
    }

    /// Get a resource by key.
    pub fn get_resource(&self, key: &str) -> Option<&ResourceInfo> {
        self.resources.get(key)
    }

    /// Number of registered resources.
    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    /// Get all resource keys.
    pub fn resource_keys(&self) -> Vec<&str> {
        self.resources.keys().map(|s| s.as_str()).collect()
    }

    /// Get resources of a specific type.
    pub fn resources_of_type(&self, rt: ResourceType) -> Vec<&ResourceInfo> {
        self.resources
            .values()
            .filter(|r| r.resource_type == rt)
            .collect()
    }
}

impl Default for ResourceActionsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_type_display() {
        assert_eq!(ResourceType::Icon.display_name(), "Icon");
        assert_eq!(ResourceType::Image.display_name(), "Image");
        assert_eq!(ResourceType::Help.display_name(), "Help");
    }

    #[test]
    fn test_resource_info() {
        let info = ResourceInfo::new("icons/test.png", ResourceType::Icon);
        assert_eq!(info.key, "icons/test.png");
        assert_eq!(info.resource_type, ResourceType::Icon);
        assert!(info.path.is_none());
    }

    #[test]
    fn test_resource_actions_plugin() {
        let mut plugin = ResourceActionsPlugin::new();
        assert_eq!(plugin.resource_count(), 0);

        plugin.register_resource(ResourceInfo::new("icon1", ResourceType::Icon));
        plugin.register_resource(ResourceInfo::new("image1", ResourceType::Image));
        assert_eq!(plugin.resource_count(), 2);

        assert!(plugin.get_resource("icon1").is_some());
        assert!(plugin.get_resource("missing").is_none());

        let icons = plugin.resources_of_type(ResourceType::Icon);
        assert_eq!(icons.len(), 1);

        let keys = plugin.resource_keys();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_graphic_formats() {
        assert!(GRAPHIC_FORMATS.contains(&"png"));
        assert!(GRAPHIC_FORMATS.contains(&"svg"));
    }
}
