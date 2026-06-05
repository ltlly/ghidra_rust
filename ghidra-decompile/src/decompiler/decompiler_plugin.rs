//! Decompiler plugin.
//!
//! Ports `ghidra.app.plugin.core.decompile.DecompilePlugin`.
//!
//! The DecompilePlugin is the main Ghidra plugin that provides the
//! decompiler view. It manages the decompiler provider, handles tool
//! integration, and registers all decompiler-specific actions.

use std::collections::HashMap;

/// The decompiler plugin that integrates the decompiler with the Ghidra tool.
///
/// Ports `ghidra.app.plugin.core.decompile.DecompilePlugin`.
#[derive(Debug)]
pub struct DecompilePlugin {
    /// Plugin name.
    name: String,
    /// Whether the plugin is enabled.
    enabled: bool,
    /// Registered action contexts.
    actions: HashMap<String, DecompilerActionDef>,
    /// Current program address being decompiled.
    current_address: Option<u64>,
    /// Plugin configuration.
    config: DecompilePluginConfig,
}

/// A decompiler action definition.
#[derive(Debug, Clone)]
pub struct DecompilerActionDef {
    /// Action name.
    pub name: String,
    /// Action description.
    pub description: String,
    /// Menu path.
    pub menu_path: String,
    /// Key binding (if any).
    pub key_binding: Option<String>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

/// Configuration for the decompiler plugin.
#[derive(Debug, Clone)]
pub struct DecompilePluginConfig {
    /// Whether to auto-decompile on location change.
    pub auto_decompile: bool,
    /// Maximum decompile timeout in milliseconds.
    pub timeout_ms: u64,
    /// Whether to show line numbers.
    pub show_line_numbers: bool,
    /// Whether to show address comments.
    pub show_addresses: bool,
    /// Whether to enable hover popups.
    pub enable_hover: bool,
}

impl Default for DecompilePluginConfig {
    fn default() -> Self {
        Self {
            auto_decompile: true,
            timeout_ms: 30000,
            show_line_numbers: true,
            show_addresses: false,
            enable_hover: true,
        }
    }
}

impl DecompilePlugin {
    /// Create a new decompiler plugin.
    pub fn new() -> Self {
        let mut plugin = Self {
            name: "DecompilePlugin".to_string(),
            enabled: true,
            actions: HashMap::new(),
            current_address: None,
            config: DecompilePluginConfig::default(),
        };
        plugin.register_default_actions();
        plugin
    }

    /// Register the default decompiler actions.
    fn register_default_actions(&mut self) {
        let actions = vec![
            DecompilerActionDef {
                name: "Decompile".into(),
                description: "Decompile the current function".into(),
                menu_path: "Decompiler>Decompile".into(),
                key_binding: Some("Ctrl+Shift+E".into()),
                enabled: true,
            },
            DecompilerActionDef {
                name: "Export to C".into(),
                description: "Export decompiled function as C source".into(),
                menu_path: "Decompiler>Export to C".into(),
                key_binding: None,
                enabled: true,
            },
            DecompilerActionDef {
                name: "Find Action".into(),
                description: "Search for text in decompiler output".into(),
                menu_path: "Decompiler>Find".into(),
                key_binding: Some("Ctrl+F".into()),
                enabled: true,
            },
            DecompilerActionDef {
                name: "Rename".into(),
                description: "Rename the symbol at the current cursor position".into(),
                menu_path: "Decompiler>Rename".into(),
                key_binding: Some("L".into()),
                enabled: true,
            },
            DecompilerActionDef {
                name: "Retype Variable".into(),
                description: "Change the data type of a variable".into(),
                menu_path: "Decompiler>Retype".into(),
                key_binding: Some("Ctrl+L".into()),
                enabled: true,
            },
            DecompilerActionDef {
                name: "Edit Function Signature".into(),
                description: "Edit the signature of the current function".into(),
                menu_path: "Decompiler>Edit Signature".into(),
                key_binding: None,
                enabled: true,
            },
            DecompilerActionDef {
                name: "Backward Slice".into(),
                description: "Highlight backward slice from cursor".into(),
                menu_path: "Decompiler>Backward Slice".into(),
                key_binding: None,
                enabled: true,
            },
            DecompilerActionDef {
                name: "Forward Slice".into(),
                description: "Highlight forward slice from cursor".into(),
                menu_path: "Decompiler>Forward Slice".into(),
                key_binding: None,
                enabled: true,
            },
            DecompilerActionDef {
                name: "Select All".into(),
                description: "Select all decompiler text".into(),
                menu_path: "Decompiler>Select All".into(),
                key_binding: Some("Ctrl+A".into()),
                enabled: true,
            },
            DecompilerActionDef {
                name: "Clone Decompiler".into(),
                description: "Open a new decompiler view".into(),
                menu_path: "Decompiler>Clone".into(),
                key_binding: None,
                enabled: true,
            },
        ];
        for action in actions {
            self.actions.insert(action.name.clone(), action);
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Enable or disable the plugin.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the current decompile address.
    pub fn set_current_address(&mut self, address: Option<u64>) {
        self.current_address = address;
    }

    /// Get the current address.
    pub fn current_address(&self) -> Option<u64> {
        self.current_address
    }

    /// Get the plugin configuration.
    pub fn config(&self) -> &DecompilePluginConfig {
        &self.config
    }

    /// Get mutable plugin configuration.
    pub fn config_mut(&mut self) -> &mut DecompilePluginConfig {
        &mut self.config
    }

    /// Get a registered action by name.
    pub fn get_action(&self, name: &str) -> Option<&DecompilerActionDef> {
        self.actions.get(name)
    }

    /// Get all registered action names.
    pub fn action_names(&self) -> Vec<&str> {
        self.actions.keys().map(|s| s.as_str()).collect()
    }

    /// Enable or disable a specific action.
    pub fn set_action_enabled(&mut self, name: &str, enabled: bool) {
        if let Some(action) = self.actions.get_mut(name) {
            action.enabled = enabled;
        }
    }
}

impl Default for DecompilePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Decompiler action context for action dispatch.
///
/// Ports `ghidra.app.plugin.core.decompile.DecompilerActionContext`.
#[derive(Debug, Clone)]
pub struct DecompilerActionContext {
    /// The address at the cursor.
    pub address: u64,
    /// The token text at the cursor.
    pub token_text: String,
    /// The token type (if known).
    pub token_type: Option<String>,
    /// Whether there is an active selection.
    pub has_selection: bool,
    /// Selected text (if any).
    pub selected_text: Option<String>,
}

impl DecompilerActionContext {
    /// Create a new action context.
    pub fn new(address: u64, token_text: impl Into<String>) -> Self {
        Self {
            address,
            token_text: token_text.into(),
            token_type: None,
            has_selection: false,
            selected_text: None,
        }
    }

    /// Set the token type.
    pub fn with_token_type(mut self, token_type: impl Into<String>) -> Self {
        self.token_type = Some(token_type.into());
        self
    }

    /// Mark as having a selection.
    pub fn with_selection(mut self, selected: impl Into<String>) -> Self {
        self.has_selection = true;
        self.selected_text = Some(selected.into());
        self
    }
}

/// Decompiler clipboard provider.
///
/// Ports `ghidra.app.plugin.core.decompile.DecompilerClipboardProvider`.
/// Handles copy/paste operations for the decompiler view.
#[derive(Debug, Clone, Default)]
pub struct DecompilerClipboardProvider {
    /// Clipboard contents.
    clipboard: Option<String>,
}

impl DecompilerClipboardProvider {
    /// Create a new clipboard provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Copy text to the clipboard.
    pub fn copy(&mut self, text: impl Into<String>) {
        self.clipboard = Some(text.into());
    }

    /// Paste from the clipboard.
    pub fn paste(&self) -> Option<&str> {
        self.clipboard.as_deref()
    }

    /// Whether the clipboard has contents.
    pub fn has_contents(&self) -> bool {
        self.clipboard.is_some()
    }

    /// Clear the clipboard.
    pub fn clear(&mut self) {
        self.clipboard = None;
    }
}

/// Decompiler location memento for saving/restoring state.
///
/// Ports `ghidra.app.plugin.core.decompile.DecompilerLocationMemento`.
#[derive(Debug, Clone)]
pub struct DecompilerLocationMemento {
    /// The address.
    pub address: u64,
    /// The cursor row.
    pub row: usize,
    /// The cursor column.
    pub col: usize,
    /// The function name (if any).
    pub function_name: Option<String>,
}

impl DecompilerLocationMemento {
    /// Create a new memento.
    pub fn new(address: u64, row: usize, col: usize) -> Self {
        Self {
            address,
            row,
            col,
            function_name: None,
        }
    }

    /// Set the function name.
    pub fn with_function(mut self, name: impl Into<String>) -> Self {
        self.function_name = Some(name.into());
        self
    }
}

/// Decompiler validator for parameter identification.
///
/// Ports `ghidra.app.plugin.core.decompiler.validator.DecompilerValidator`.
#[derive(Debug, Clone, Default)]
pub struct DecompilerValidator {
    /// Whether the validation passed.
    valid: bool,
    /// Validation messages.
    messages: Vec<String>,
}

impl DecompilerValidator {
    /// Create a new validator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a validation message.
    pub fn add_message(&mut self, msg: impl Into<String>) {
        self.messages.push(msg.into());
    }

    /// Mark validation as failed.
    pub fn invalidate(&mut self, msg: impl Into<String>) {
        self.valid = false;
        self.messages.push(msg.into());
    }

    /// Whether validation passed.
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Get validation messages.
    pub fn messages(&self) -> &[String] {
        &self.messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompile_plugin_new() {
        let plugin = DecompilePlugin::new();
        assert!(plugin.is_enabled());
        assert!(!plugin.action_names().is_empty());
    }

    #[test]
    fn decompile_plugin_actions() {
        let plugin = DecompilePlugin::new();
        assert!(plugin.get_action("Decompile").is_some());
        assert!(plugin.get_action("Rename").is_some());
        assert!(plugin.get_action("Export to C").is_some());
        assert!(plugin.get_action("NonExistent").is_none());
    }

    #[test]
    fn decompile_plugin_config() {
        let mut plugin = DecompilePlugin::new();
        assert!(plugin.config().auto_decompile);
        plugin.config_mut().auto_decompile = false;
        assert!(!plugin.config().auto_decompile);
    }

    #[test]
    fn decompile_plugin_disable_action() {
        let mut plugin = DecompilePlugin::new();
        plugin.set_action_enabled("Rename", false);
        assert!(!plugin.get_action("Rename").unwrap().enabled);
    }

    #[test]
    fn action_context_new() {
        let ctx = DecompilerActionContext::new(0x1000, "myFunc")
            .with_token_type("function_name")
            .with_selection("selected text");
        assert_eq!(ctx.address, 0x1000);
        assert_eq!(ctx.token_text, "myFunc");
        assert!(ctx.has_selection);
    }

    #[test]
    fn clipboard_provider() {
        let mut cp = DecompilerClipboardProvider::new();
        assert!(!cp.has_contents());
        cp.copy("hello");
        assert!(cp.has_contents());
        assert_eq!(cp.paste(), Some("hello"));
        cp.clear();
        assert!(!cp.has_contents());
    }

    #[test]
    fn location_memento() {
        let m = DecompilerLocationMemento::new(0x1000, 5, 10)
            .with_function("main");
        assert_eq!(m.address, 0x1000);
        assert_eq!(m.row, 5);
        assert_eq!(m.col, 10);
        assert_eq!(m.function_name.as_deref(), Some("main"));
    }

    #[test]
    fn decompiler_validator() {
        let mut v = DecompilerValidator::new();
        v.invalidate("bad parameter");
        assert!(!v.is_valid());
        assert_eq!(v.messages().len(), 1);
    }
}
