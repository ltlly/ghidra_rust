//! Code Browser Plugin -- the main program listing display window.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin`.
//!
//! This is the primary plugin that provides the code listing view where users
//! interact with disassembly, data, and other program information. It manages
//! the connected (primary) and disconnected (cloned) providers, handles
//! navigation, selection, highlighting, and service registration.
//!
//! # Architecture
//!
//! ```text
//! CodeBrowserPlugin
//!   ├── PrimaryCodeBrowserProvider (connected)
//!   ├── Vec<CodeBrowserProvider> (disconnected / clones)
//!   ├── NavigationManager
//!   ├── SelectionManager
//!   └── HighlightManager
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::plugin::codebrowser::code_browser_plugin::CodeBrowserPlugin;
//!
//! let mut plugin = CodeBrowserPlugin::new("CodeBrowser");
//! plugin.init();
//! assert_eq!(plugin.name(), "CodeBrowser");
//! ```

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Plugin status and metadata
// ---------------------------------------------------------------------------

/// Plugin lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStatus {
    /// Plugin is released and stable.
    Released,
    /// Plugin is in beta.
    Beta,
    /// Plugin is unstable/experimental.
    Unstable,
}

/// Metadata about a plugin.
#[derive(Debug, Clone)]
pub struct PluginInfo {
    /// Plugin status.
    pub status: PluginStatus,
    /// Package name.
    pub package_name: String,
    /// Category.
    pub category: String,
    /// Short description.
    pub short_description: String,
    /// Full description.
    pub description: String,
}

impl Default for PluginInfo {
    fn default() -> Self {
        Self {
            status: PluginStatus::Released,
            package_name: "Core".to_string(),
            category: "Common".to_string(),
            short_description: "Code Browser Plugin".to_string(),
            description: "Provides the main code listing display window.".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// CodeBrowserProvider -- a single listing view
// ---------------------------------------------------------------------------

/// A provider for the code browser listing view.
///
/// Each provider represents a single listing window (either connected/primary
/// or disconnected/clone).
#[derive(Debug)]
pub struct CodeBrowserProvider {
    /// Provider name.
    name: String,
    /// Current address as a hex string.
    current_address: Option<String>,
    /// Whether this is the connected (primary) provider.
    connected: bool,
    /// Current program name.
    program: Option<String>,
    /// Address history for back/forward navigation.
    history: Vec<String>,
    /// Current position in history.
    history_index: usize,
}

impl CodeBrowserProvider {
    /// Creates a new provider.
    pub fn new(name: impl Into<String>, connected: bool) -> Self {
        Self {
            name: name.into(),
            current_address: None,
            connected,
            program: None,
            history: Vec::new(),
            history_index: 0,
        }
    }

    /// Returns the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the current address.
    pub fn current_address(&self) -> Option<&str> {
        self.current_address.as_deref()
    }

    /// Navigates to the given address.
    pub fn go_to(&mut self, address: impl Into<String>) {
        let addr = address.into();
        // Truncate forward history
        self.history.truncate(self.history_index);
        self.history.push(addr.clone());
        self.history_index = self.history.len();
        self.current_address = Some(addr);
    }

    /// Navigates back in history.
    pub fn go_back(&mut self) -> bool {
        if self.history_index > 1 {
            self.history_index -= 1;
            self.current_address = self.history.get(self.history_index - 1).cloned();
            true
        } else {
            false
        }
    }

    /// Navigates forward in history.
    pub fn go_forward(&mut self) -> bool {
        if self.history_index < self.history.len() {
            self.current_address = self.history.get(self.history_index).cloned();
            self.history_index += 1;
            true
        } else {
            false
        }
    }

    /// Returns whether this is the connected (primary) provider.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Sets the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.program = program;
    }

    /// Returns the current program name.
    pub fn program(&self) -> Option<&str> {
        self.program.as_deref()
    }

    /// Clears the provider state.
    pub fn clear(&mut self) {
        self.current_address = None;
        self.history.clear();
        self.history_index = 0;
    }
}

// ---------------------------------------------------------------------------
// CodeBrowserPlugin -- the main plugin
// ---------------------------------------------------------------------------

/// The code browser plugin.
///
/// Manages the connected (primary) and disconnected (cloned) providers,
/// navigation, selection, and highlighting.
///
/// Ported from Ghidra's `CodeBrowserPlugin` Java class.
#[derive(Debug)]
pub struct CodeBrowserPlugin {
    /// The plugin name.
    name: String,
    /// The primary (connected) provider.
    connected_provider: CodeBrowserProvider,
    /// Disconnected (cloned) providers.
    disconnected_providers: Vec<CodeBrowserProvider>,
    /// The current program name.
    current_program: Option<String>,
    /// Whether the plugin is initialized.
    initialized: bool,
    /// Whether the plugin is disposed.
    disposed: bool,
    /// Plugin options.
    options: HashMap<String, PluginOptionValue>,
    /// Plugin info.
    info: PluginInfo,
}

/// A plugin option value.
#[derive(Debug, Clone)]
pub enum PluginOptionValue {
    /// Boolean option.
    Bool(bool),
    /// Integer option.
    Int(i32),
    /// String option.
    String(String),
}

impl fmt::Display for PluginOptionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{}", v),
            Self::Int(v) => write!(f, "{}", v),
            Self::String(v) => write!(f, "{}", v),
        }
    }
}

impl CodeBrowserPlugin {
    /// Creates a new code browser plugin.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            connected_provider: CodeBrowserProvider::new(
                format!("{}_Primary", name),
                true,
            ),
            name,
            disconnected_providers: Vec::new(),
            current_program: None,
            initialized: false,
            disposed: false,
            options: HashMap::new(),
            info: PluginInfo::default(),
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Initializes the plugin.
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
    }

    /// Disposes the plugin and releases resources.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.connected_provider.clear();
        self.disconnected_providers.clear();
    }

    /// Returns whether the plugin is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Returns a reference to the connected (primary) provider.
    pub fn connected_provider(&self) -> &CodeBrowserProvider {
        &self.connected_provider
    }

    /// Returns a mutable reference to the connected (primary) provider.
    pub fn connected_provider_mut(&mut self) -> &mut CodeBrowserProvider {
        &mut self.connected_provider
    }

    /// Returns the number of disconnected providers.
    pub fn disconnected_provider_count(&self) -> usize {
        self.disconnected_providers.len()
    }

    /// Returns a reference to a disconnected provider by index.
    pub fn disconnected_provider(&self, index: usize) -> Option<&CodeBrowserProvider> {
        self.disconnected_providers.get(index)
    }

    /// Creates a new disconnected (cloned) provider.
    pub fn clone_provider(&mut self) -> usize {
        let index = self.disconnected_providers.len();
        let name = format!("{}_Clone_{}", self.name, index);
        let mut provider = CodeBrowserProvider::new(name, false);
        provider.set_program(self.current_program.clone());
        self.disconnected_providers.push(provider);
        index
    }

    /// Removes a disconnected provider by index.
    pub fn remove_disconnected_provider(&mut self, index: usize) -> Option<CodeBrowserProvider> {
        if index < self.disconnected_providers.len() {
            Some(self.disconnected_providers.remove(index))
        } else {
            None
        }
    }

    /// Sets the current program for all providers.
    pub fn set_program(&mut self, program: Option<String>) {
        self.current_program = program.clone();
        self.connected_provider.set_program(program.clone());
        for provider in &mut self.disconnected_providers {
            provider.set_program(program.clone());
        }
    }

    /// Returns the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Navigates the connected provider to the given address.
    pub fn go_to(&mut self, address: impl Into<String>) {
        self.connected_provider.go_to(address);
    }

    /// Navigates the connected provider back.
    pub fn go_back(&mut self) -> bool {
        self.connected_provider.go_back()
    }

    /// Navigates the connected provider forward.
    pub fn go_forward(&mut self) -> bool {
        self.connected_provider.go_forward()
    }

    /// Returns a reference to the plugin info.
    pub fn info(&self) -> &PluginInfo {
        &self.info
    }

    /// Sets a plugin option.
    pub fn set_option(&mut self, key: impl Into<String>, value: PluginOptionValue) {
        self.options.insert(key.into(), value);
    }

    /// Gets a plugin option.
    pub fn get_option(&self, key: &str) -> Option<&PluginOptionValue> {
        self.options.get(key)
    }

    /// Returns the number of plugin options.
    pub fn option_count(&self) -> usize {
        self.options.len()
    }
}

impl Default for CodeBrowserPlugin {
    fn default() -> Self {
        Self::new("CodeBrowserPlugin")
    }
}

impl fmt::Display for CodeBrowserPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CodeBrowserPlugin({}, program={:?})",
            self.name, self.current_program
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = CodeBrowserPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_initialized());
        assert!(!plugin.is_disposed());
    }

    #[test]
    fn test_plugin_init_dispose() {
        let mut plugin = CodeBrowserPlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_navigation() {
        let mut plugin = CodeBrowserPlugin::new("TestPlugin");
        plugin.init();
        plugin.go_to("0x401000");
        assert_eq!(plugin.connected_provider().current_address(), Some("0x401000"));
        plugin.go_to("0x402000");
        assert_eq!(plugin.connected_provider().current_address(), Some("0x402000"));
        plugin.go_back();
        assert_eq!(plugin.connected_provider().current_address(), Some("0x401000"));
    }

    #[test]
    fn test_clone_provider() {
        let mut plugin = CodeBrowserPlugin::new("TestPlugin");
        let idx = plugin.clone_provider();
        assert_eq!(plugin.disconnected_provider_count(), 1);
        assert!(plugin.disconnected_provider(idx).is_some());
    }

    #[test]
    fn test_program_management() {
        let mut plugin = CodeBrowserPlugin::new("TestPlugin");
        plugin.set_program(Some("test.exe".to_string()));
        assert_eq!(plugin.current_program(), Some("test.exe"));
    }
}
