//! SaveService -- service interface and tool-config save dialog.
//!
//! Ported from `ghidra.framework.plugintool.dialog.SaveToolConfigDialog`
//! and the save-related service traits from `ghidra.framework.main`.
//!
//! Provides:
//! - [`SaveService`] -- trait for save operations on domain files
//! - [`ToolConfigSaveDialog`] -- dialog for saving a tool configuration
//!   to the tool chest with a name and icon

use std::fmt;

// ---------------------------------------------------------------------------
// ToolIconURL
// ---------------------------------------------------------------------------

/// Represents a tool icon URL.
///
/// Ported from `docking.util.image.ToolIconURL`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ToolIconUrl {
    /// The icon name or identifier.
    pub name: String,
    /// The icon URL path.
    pub url: String,
}

impl ToolIconUrl {
    /// Create a new tool icon URL.
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
        }
    }
}

impl fmt::Display for ToolIconUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ---------------------------------------------------------------------------
// ToolChest / ToolTemplate (placeholders)
// ---------------------------------------------------------------------------

/// A template describing a Ghidra tool configuration.
///
/// Ported from `ghidra.framework.project.tool.GhidraToolTemplate`.
#[derive(Debug, Clone)]
pub struct ToolTemplate {
    /// The tool name.
    pub name: String,
    /// The tool description.
    pub description: String,
    /// The tool icon URL.
    pub icon_url: Option<ToolIconUrl>,
    /// The tool configuration file path.
    pub config_path: Option<String>,
}

impl ToolTemplate {
    /// Create a new tool template.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            icon_url: None,
            config_path: None,
        }
    }

    /// Set the tool description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the tool icon URL.
    pub fn with_icon(mut self, icon: ToolIconUrl) -> Self {
        self.icon_url = Some(icon);
        self
    }
}

/// A collection of saved tool configurations.
///
/// Ported from `ghidra.framework.model.ToolChest`.
#[derive(Debug, Default)]
pub struct ToolChest {
    /// The saved tool templates.
    tools: Vec<ToolTemplate>,
}

impl ToolChest {
    /// Create a new empty tool chest.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a tool template to the chest.
    pub fn add_tool(&mut self, tool: ToolTemplate) {
        // Replace if a tool with the same name exists
        if let Some(existing) = self.tools.iter_mut().find(|t| t.name == tool.name) {
            *existing = tool;
        } else {
            self.tools.push(tool);
        }
    }

    /// Get a tool template by name.
    pub fn get_tool(&self, name: &str) -> Option<&ToolTemplate> {
        self.tools.iter().find(|t| t.name == name)
    }

    /// Check if a tool with the given name exists.
    pub fn has_tool(&self, name: &str) -> bool {
        self.tools.iter().any(|t| t.name == name)
    }

    /// Get the number of tools in the chest.
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Get all tool names.
    pub fn tool_names(&self) -> Vec<&str> {
        self.tools.iter().map(|t| t.name.as_str()).collect()
    }

    /// Get all tool templates.
    pub fn tools(&self) -> &[ToolTemplate] {
        &self.tools
    }

    /// Remove a tool by name.
    pub fn remove_tool(&mut self, name: &str) -> Option<ToolTemplate> {
        if let Some(pos) = self.tools.iter().position(|t| t.name == name) {
            Some(self.tools.remove(pos))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// ToolServices (placeholder)
// ---------------------------------------------------------------------------

/// Service for managing tool configurations.
///
/// Ported from `ghidra.framework.plugintool.ToolServices`.
#[derive(Debug, Default)]
pub struct ToolServices {
    /// The tool chest containing saved tools.
    tool_chest: ToolChest,
    /// Available icons for tools.
    available_icons: Vec<ToolIconUrl>,
}

impl ToolServices {
    /// Create a new tool services instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the tool chest.
    pub fn get_tool_chest(&self) -> &ToolChest {
        &self.tool_chest
    }

    /// Get a mutable reference to the tool chest.
    pub fn get_tool_chest_mut(&mut self) -> &mut ToolChest {
        &mut self.tool_chest
    }

    /// Get the list of available tool icons.
    pub fn get_available_icons(&self) -> &[ToolIconUrl] {
        &self.available_icons
    }

    /// Add an available icon.
    pub fn add_icon(&mut self, icon: ToolIconUrl) {
        self.available_icons.push(icon);
    }

    /// Save a tool configuration to the tool chest.
    pub fn save_tool(&mut self, template: ToolTemplate) {
        self.tool_chest.add_tool(template);
    }
}

// ---------------------------------------------------------------------------
// NamingUtilities (simplified)
// ---------------------------------------------------------------------------

/// Utilities for naming Ghidra objects.
///
/// Ported from `ghidra.util.NamingUtilities`.
pub struct NamingUtilities;

impl NamingUtilities {
    /// Maximum length for a tool name.
    pub const MAX_NAME_LENGTH: usize = 200;

    /// Check if a name is valid (non-empty, not too long, no invalid chars).
    pub fn is_valid_name(name: &str) -> bool {
        if name.is_empty() || name.len() > Self::MAX_NAME_LENGTH {
            return false;
        }
        // Disallow characters that are problematic in file systems
        !name.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|'])
    }

    /// Suggest a unique name by appending a suffix if needed.
    pub fn make_unique_name(base: &str, existing: &[&str]) -> String {
        if !existing.contains(&base) {
            return base.to_string();
        }
        for i in 2.. {
            let candidate = format!("{} ({})", base, i);
            if !existing.contains(&candidate.as_str()) {
                return candidate;
            }
        }
        base.to_string() // Unreachable in practice
    }
}

// ---------------------------------------------------------------------------
// SaveToolConfigResult
// ---------------------------------------------------------------------------

/// Result of saving a tool configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveToolConfigResult {
    /// The tool was saved successfully.
    Success,
    /// The user cancelled the save.
    Cancelled,
    /// The provided name was invalid.
    InvalidName(String),
    /// An error occurred.
    Error(String),
}

impl fmt::Display for SaveToolConfigResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "Tool saved successfully"),
            Self::Cancelled => write!(f, "Save cancelled"),
            Self::InvalidName(name) => write!(f, "Invalid tool name: {}", name),
            Self::Error(msg) => write!(f, "Error saving tool: {}", msg),
        }
    }
}

// ---------------------------------------------------------------------------
// ToolConfigSaveDialog
// ---------------------------------------------------------------------------

/// Modal dialog for saving a tool configuration to the tool chest.
///
/// Ported from `ghidra.framework.plugintool.dialog.SaveToolConfigDialog`.
///
/// Allows the user to:
/// - Enter a name for the tool configuration
/// - Select an icon from the available icons
/// - Browse for a custom icon file
/// - Save or cancel
///
/// # Example
///
/// ```
/// use ghidra_features::save::save_service::*;
///
/// let mut services = ToolServices::new();
/// services.add_icon(ToolIconUrl::new("default", "/icons/default.png"));
///
/// let mut dialog = ToolConfigSaveDialog::new("MyTool", &services);
/// dialog.set_name("My Custom Tool");
///
/// assert_eq!(dialog.name(), "My Custom Tool");
/// assert!(dialog.validate_name().is_ok());
/// ```
#[derive(Debug)]
pub struct ToolConfigSaveDialog {
    /// The tool name entered by the user.
    name: String,
    /// The default name.
    default_name: String,
    /// The selected icon.
    selected_icon: Option<ToolIconUrl>,
    /// The available icons.
    available_icons: Vec<ToolIconUrl>,
    /// Whether the user cancelled.
    did_cancel: bool,
    /// Custom icon path (from browse).
    custom_icon_path: Option<String>,
}

impl ToolConfigSaveDialog {
    /// Create a new tool config save dialog.
    ///
    /// Pre-populates the name field with the current tool name and
    /// the icon list with the available icons from tool services.
    pub fn new(tool_name: impl Into<String>, services: &ToolServices) -> Self {
        let name = tool_name.into();
        let icons = services.get_available_icons().to_vec();
        Self {
            default_name: name.clone(),
            name,
            selected_icon: icons.first().cloned(),
            available_icons: icons,
            did_cancel: false,
            custom_icon_path: None,
        }
    }

    /// Get the current tool name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the tool name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// Get the default name.
    pub fn default_name(&self) -> &str {
        &self.default_name
    }

    /// Get the selected icon.
    pub fn selected_icon(&self) -> Option<&ToolIconUrl> {
        self.selected_icon.as_ref()
    }

    /// Set the selected icon.
    pub fn set_selected_icon(&mut self, icon: Option<ToolIconUrl>) {
        self.selected_icon = icon;
    }

    /// Get the available icons.
    pub fn available_icons(&self) -> &[ToolIconUrl] {
        &self.available_icons
    }

    /// Set a custom icon path (from browse dialog).
    pub fn set_custom_icon_path(&mut self, path: impl Into<String>) {
        self.custom_icon_path = Some(path.into());
    }

    /// Get the custom icon path.
    pub fn custom_icon_path(&self) -> Option<&str> {
        self.custom_icon_path.as_deref()
    }

    /// Whether the user cancelled.
    pub fn did_cancel(&self) -> bool {
        self.did_cancel
    }

    /// Validate the tool name.
    ///
    /// Returns `Ok(())` if valid, or `Err(message)` if invalid.
    pub fn validate_name(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Tool name cannot be empty".into());
        }
        if !NamingUtilities::is_valid_name(&self.name) {
            return Err(format!(
                "Tool name contains invalid characters: {}",
                self.name
            ));
        }
        if self.name.len() > NamingUtilities::MAX_NAME_LENGTH {
            return Err(format!(
                "Tool name is too long (max {} characters)",
                NamingUtilities::MAX_NAME_LENGTH
            ));
        }
        Ok(())
    }

    /// Execute the "Save" action.
    ///
    /// Validates the name and saves the tool configuration to the tool chest.
    pub fn save(&self, tool_services: &mut ToolServices) -> SaveToolConfigResult {
        if let Err(msg) = self.validate_name() {
            return SaveToolConfigResult::InvalidName(msg);
        }

        let icon = self
            .selected_icon
            .clone()
            .or_else(|| {
                self.custom_icon_path
                    .as_ref()
                    .map(|p| ToolIconUrl::new("custom", p))
            });

        let mut template = ToolTemplate::new(&self.name);
        if let Some(icon) = icon {
            template = template.with_icon(icon);
        }

        tool_services.save_tool(template);
        SaveToolConfigResult::Success
    }

    /// Execute the "Cancel" action.
    pub fn cancel(&mut self) {
        self.did_cancel = true;
    }
}

// ---------------------------------------------------------------------------
// SaveService trait
// ---------------------------------------------------------------------------

/// Service interface for save operations.
///
/// Ported from the save-related methods in `ghidra.framework.main.FrontEndService`
/// and `ghidra.framework.model.DomainFile`.
///
/// This trait defines the contract for saving domain files and tool
/// configurations.  Implementations coordinate with the project
/// manager, tool services, and UI to perform the actual save.
pub trait SaveService: fmt::Debug + Send + Sync {
    /// Save the given domain file.
    ///
    /// Returns `true` if the save succeeded.
    fn save_domain_file(&self, pathname: &str) -> bool;

    /// Save the given domain file to a new location (Save As).
    ///
    /// Returns `true` if the save succeeded.
    fn save_domain_file_as(&self, pathname: &str, new_pathname: &str) -> bool;

    /// Save all modified domain files.
    ///
    /// Returns the number of files saved.
    fn save_all(&self) -> usize;

    /// Check if there are unsaved changes.
    fn has_unsaved_changes(&self) -> bool;

    /// Get the names of all files with unsaved changes.
    fn unsaved_file_names(&self) -> Vec<String>;

    /// Save the current tool configuration.
    ///
    /// Returns `true` if the save succeeded.
    fn save_tool_config(&self, tool_name: &str) -> bool;
}

/// A simple in-memory implementation of [`SaveService`] for testing.
#[derive(Debug, Default)]
pub struct SimpleSaveService {
    /// Map of pathname to saved state.
    files: std::sync::Mutex<std::collections::HashMap<String, bool>>,
    /// Tool names that have been saved.
    saved_tools: std::sync::Mutex<Vec<String>>,
}

impl SimpleSaveService {
    /// Create a new simple save service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a file with the service.
    pub fn register_file(&self, pathname: &str) {
        if let Ok(mut files) = self.files.lock() {
            files.insert(pathname.to_string(), true);
        }
    }

    /// Mark a file as dirty.
    pub fn mark_dirty(&self, pathname: &str) {
        if let Ok(mut files) = self.files.lock() {
            files.insert(pathname.to_string(), false);
        }
    }

    /// Check if a file is clean.
    pub fn is_clean(&self, pathname: &str) -> bool {
        if let Ok(files) = self.files.lock() {
            files.get(pathname).copied().unwrap_or(false)
        } else {
            false
        }
    }
}

impl SaveService for SimpleSaveService {
    fn save_domain_file(&self, pathname: &str) -> bool {
        if let Ok(mut files) = self.files.lock() {
            if files.contains_key(pathname) {
                files.insert(pathname.to_string(), true);
                return true;
            }
        }
        false
    }

    fn save_domain_file_as(&self, _pathname: &str, new_pathname: &str) -> bool {
        if let Ok(mut files) = self.files.lock() {
            files.insert(new_pathname.to_string(), true);
            return true;
        }
        false
    }

    fn save_all(&self) -> usize {
        if let Ok(mut files) = self.files.lock() {
            let mut count = 0;
            for saved in files.values_mut() {
                if !*saved {
                    *saved = true;
                    count += 1;
                }
            }
            count
        } else {
            0
        }
    }

    fn has_unsaved_changes(&self) -> bool {
        if let Ok(files) = self.files.lock() {
            files.values().any(|saved| !saved)
        } else {
            false
        }
    }

    fn unsaved_file_names(&self) -> Vec<String> {
        if let Ok(files) = self.files.lock() {
            files
                .iter()
                .filter(|(_, saved)| !**saved)
                .map(|(name, _)| name.clone())
                .collect()
        } else {
            Vec::new()
        }
    }

    fn save_tool_config(&self, tool_name: &str) -> bool {
        if let Ok(mut tools) = self.saved_tools.lock() {
            if !tools.contains(&tool_name.to_string()) {
                tools.push(tool_name.to_string());
            }
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ToolIconUrl tests --

    #[test]
    fn test_tool_icon_url() {
        let icon = ToolIconUrl::new("default", "/icons/default.png");
        assert_eq!(icon.name, "default");
        assert_eq!(icon.url, "/icons/default.png");
        assert_eq!(icon.to_string(), "default");
    }

    #[test]
    fn test_tool_icon_url_equality() {
        let a = ToolIconUrl::new("icon", "/path");
        let b = ToolIconUrl::new("icon", "/path");
        assert_eq!(a, b);
    }

    // -- ToolTemplate tests --

    #[test]
    fn test_tool_template_new() {
        let t = ToolTemplate::new("MyTool");
        assert_eq!(t.name, "MyTool");
        assert!(t.description.is_empty());
        assert!(t.icon_url.is_none());
    }

    #[test]
    fn test_tool_template_builder() {
        let icon = ToolIconUrl::new("icon", "/path");
        let t = ToolTemplate::new("MyTool")
            .with_description("A test tool")
            .with_icon(icon);
        assert_eq!(t.description, "A test tool");
        assert!(t.icon_url.is_some());
    }

    // -- ToolChest tests --

    #[test]
    fn test_tool_chest_new() {
        let chest = ToolChest::new();
        assert_eq!(chest.tool_count(), 0);
        assert!(chest.tools().is_empty());
    }

    #[test]
    fn test_tool_chest_add() {
        let mut chest = ToolChest::new();
        chest.add_tool(ToolTemplate::new("Tool1"));
        chest.add_tool(ToolTemplate::new("Tool2"));
        assert_eq!(chest.tool_count(), 2);
        assert!(chest.has_tool("Tool1"));
        assert!(chest.has_tool("Tool2"));
    }

    #[test]
    fn test_tool_chest_replace() {
        let mut chest = ToolChest::new();
        chest.add_tool(ToolTemplate::new("Tool1"));
        chest.add_tool(ToolTemplate::new("Tool1").with_description("Updated"));
        assert_eq!(chest.tool_count(), 1);
        assert_eq!(
            chest.get_tool("Tool1").unwrap().description,
            "Updated"
        );
    }

    #[test]
    fn test_tool_chest_remove() {
        let mut chest = ToolChest::new();
        chest.add_tool(ToolTemplate::new("Tool1"));
        let removed = chest.remove_tool("Tool1");
        assert!(removed.is_some());
        assert_eq!(chest.tool_count(), 0);
    }

    #[test]
    fn test_tool_chest_tool_names() {
        let mut chest = ToolChest::new();
        chest.add_tool(ToolTemplate::new("A"));
        chest.add_tool(ToolTemplate::new("B"));
        let names = chest.tool_names();
        assert_eq!(names, vec!["A", "B"]);
    }

    // -- ToolServices tests --

    #[test]
    fn test_tool_services() {
        let mut services = ToolServices::new();
        services.add_icon(ToolIconUrl::new("icon1", "/1"));
        services.add_icon(ToolIconUrl::new("icon2", "/2"));
        assert_eq!(services.get_available_icons().len(), 2);

        services.save_tool(ToolTemplate::new("MyTool"));
        assert!(services.get_tool_chest().has_tool("MyTool"));
    }

    // -- NamingUtilities tests --

    #[test]
    fn test_naming_valid() {
        assert!(NamingUtilities::is_valid_name("MyTool"));
        assert!(NamingUtilities::is_valid_name("tool-1"));
        assert!(NamingUtilities::is_valid_name("tool_1"));
    }

    #[test]
    fn test_naming_invalid() {
        assert!(!NamingUtilities::is_valid_name(""));
        assert!(!NamingUtilities::is_valid_name("tool/name"));
        assert!(!NamingUtilities::is_valid_name("tool\\name"));
        assert!(!NamingUtilities::is_valid_name("tool:name"));
        assert!(!NamingUtilities::is_valid_name("tool*name"));
        assert!(!NamingUtilities::is_valid_name("tool?name"));
        assert!(!NamingUtilities::is_valid_name("tool\"name"));
        assert!(!NamingUtilities::is_valid_name("tool<name"));
        assert!(!NamingUtilities::is_valid_name("tool>name"));
        assert!(!NamingUtilities::is_valid_name("tool|name"));
    }

    #[test]
    fn test_naming_unique() {
        let existing = vec!["MyTool", "MyTool (2)"];
        assert_eq!(
            NamingUtilities::make_unique_name("MyTool", &existing),
            "MyTool (3)"
        );
        assert_eq!(
            NamingUtilities::make_unique_name("NewTool", &existing),
            "NewTool"
        );
    }

    // -- SaveToolConfigResult tests --

    #[test]
    fn test_save_tool_config_result_display() {
        assert_eq!(
            SaveToolConfigResult::Success.to_string(),
            "Tool saved successfully"
        );
        assert_eq!(
            SaveToolConfigResult::Cancelled.to_string(),
            "Save cancelled"
        );
        assert_eq!(
            SaveToolConfigResult::InvalidName("bad".into()).to_string(),
            "Invalid tool name: bad"
        );
    }

    // -- ToolConfigSaveDialog tests --

    #[test]
    fn test_tool_config_dialog_new() {
        let services = ToolServices::new();
        let dialog = ToolConfigSaveDialog::new("MyTool", &services);
        assert_eq!(dialog.name(), "MyTool");
        assert_eq!(dialog.default_name(), "MyTool");
        assert!(dialog.selected_icon().is_none());
        assert!(!dialog.did_cancel());
    }

    #[test]
    fn test_tool_config_dialog_with_icons() {
        let mut services = ToolServices::new();
        services.add_icon(ToolIconUrl::new("icon1", "/1"));
        services.add_icon(ToolIconUrl::new("icon2", "/2"));

        let dialog = ToolConfigSaveDialog::new("MyTool", &services);
        assert_eq!(dialog.available_icons().len(), 2);
        assert!(dialog.selected_icon().is_some());
        assert_eq!(dialog.selected_icon().unwrap().name, "icon1");
    }

    #[test]
    fn test_tool_config_dialog_set_name() {
        let services = ToolServices::new();
        let mut dialog = ToolConfigSaveDialog::new("MyTool", &services);
        dialog.set_name("NewName");
        assert_eq!(dialog.name(), "NewName");
    }

    #[test]
    fn test_tool_config_dialog_validate_empty() {
        let services = ToolServices::new();
        let mut dialog = ToolConfigSaveDialog::new("MyTool", &services);
        dialog.set_name("");
        assert!(dialog.validate_name().is_err());
    }

    #[test]
    fn test_tool_config_dialog_validate_invalid() {
        let services = ToolServices::new();
        let mut dialog = ToolConfigSaveDialog::new("MyTool", &services);
        dialog.set_name("bad/name");
        assert!(dialog.validate_name().is_err());
    }

    #[test]
    fn test_tool_config_dialog_validate_ok() {
        let services = ToolServices::new();
        let dialog = ToolConfigSaveDialog::new("MyTool", &services);
        assert!(dialog.validate_name().is_ok());
    }

    #[test]
    fn test_tool_config_dialog_save() {
        let mut services = ToolServices::new();
        let dialog = ToolConfigSaveDialog::new("MyTool", &services);
        let result = dialog.save(&mut services);
        assert_eq!(result, SaveToolConfigResult::Success);
        assert!(services.get_tool_chest().has_tool("MyTool"));
    }

    #[test]
    fn test_tool_config_dialog_save_invalid_name() {
        let mut services = ToolServices::new();
        let mut dialog = ToolConfigSaveDialog::new("MyTool", &services);
        dialog.set_name("");
        let result = dialog.save(&mut services);
        assert!(matches!(result, SaveToolConfigResult::InvalidName(_)));
    }

    #[test]
    fn test_tool_config_dialog_save_with_icon() {
        let mut services = ToolServices::new();
        services.add_icon(ToolIconUrl::new("icon1", "/1"));

        let dialog = ToolConfigSaveDialog::new("MyTool", &services);
        let result = dialog.save(&mut services);
        assert_eq!(result, SaveToolConfigResult::Success);

        let tool = services.get_tool_chest().get_tool("MyTool").unwrap();
        assert!(tool.icon_url.is_some());
    }

    #[test]
    fn test_tool_config_dialog_save_with_custom_icon() {
        let services = ToolServices::new();
        let mut dialog = ToolConfigSaveDialog::new("MyTool", &services);
        dialog.set_custom_icon_path("/custom/icon.png");

        let mut services = ToolServices::new();
        let result = dialog.save(&mut services);
        assert_eq!(result, SaveToolConfigResult::Success);

        let tool = services.get_tool_chest().get_tool("MyTool").unwrap();
        assert!(tool.icon_url.is_some());
        assert_eq!(tool.icon_url.as_ref().unwrap().url, "/custom/icon.png");
    }

    #[test]
    fn test_tool_config_dialog_cancel() {
        let services = ToolServices::new();
        let mut dialog = ToolConfigSaveDialog::new("MyTool", &services);
        assert!(!dialog.did_cancel());
        dialog.cancel();
        assert!(dialog.did_cancel());
    }

    // -- SimpleSaveService tests --

    #[test]
    fn test_simple_save_service_new() {
        let service = SimpleSaveService::new();
        assert!(!service.has_unsaved_changes());
        assert!(service.unsaved_file_names().is_empty());
    }

    #[test]
    fn test_simple_save_service_register_and_dirty() {
        let service = SimpleSaveService::new();
        service.register_file("/dir/test.exe");
        assert!(service.is_clean("/dir/test.exe"));

        service.mark_dirty("/dir/test.exe");
        assert!(!service.is_clean("/dir/test.exe"));
        assert!(service.has_unsaved_changes());
    }

    #[test]
    fn test_simple_save_service_save() {
        let service = SimpleSaveService::new();
        service.register_file("/dir/test.exe");
        service.mark_dirty("/dir/test.exe");

        assert!(service.save_domain_file("/dir/test.exe"));
        assert!(service.is_clean("/dir/test.exe"));
        assert!(!service.has_unsaved_changes());
    }

    #[test]
    fn test_simple_save_service_save_unknown() {
        let service = SimpleSaveService::new();
        assert!(!service.save_domain_file("/unknown"));
    }

    #[test]
    fn test_simple_save_service_save_as() {
        let service = SimpleSaveService::new();
        assert!(service.save_domain_file_as("/old", "/new"));
        assert!(service.is_clean("/new"));
    }

    #[test]
    fn test_simple_save_service_save_all() {
        let service = SimpleSaveService::new();
        service.register_file("/a");
        service.register_file("/b");
        service.register_file("/c");
        service.mark_dirty("/a");
        service.mark_dirty("/b");

        let count = service.save_all();
        assert_eq!(count, 2);
        assert!(!service.has_unsaved_changes());
    }

    #[test]
    fn test_simple_save_service_unsaved_names() {
        let service = SimpleSaveService::new();
        service.register_file("/a");
        service.register_file("/b");
        service.mark_dirty("/a");

        let names = service.unsaved_file_names();
        assert_eq!(names.len(), 1);
        assert!(names.contains(&"/a".to_string()));
    }

    #[test]
    fn test_simple_save_service_tool_config() {
        let service = SimpleSaveService::new();
        assert!(service.save_tool_config("MyTool"));
    }
}
