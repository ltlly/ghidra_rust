//! Console plugin integration.
//!
//! Port of Ghidra's `ghidra.app.plugin.core.console.ConsolePlugin`.
//!
//! This module provides the plugin wrapper that connects the console
//! component provider to the Ghidra tool framework.

use super::console_component_provider::ConsoleComponentProvider;
use super::console_service::ConsoleService;

/// Plugin metadata status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStatus {
    /// Plugin is released and stable.
    Released,
    /// Plugin is in beta.
    Beta,
    /// Plugin is unstable/experimental.
    Unstable,
}

/// Console plugin configuration.
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
            short_description: "I/O Console".to_string(),
            description: "Displays an I/O console.".to_string(),
        }
    }
}

/// Console plugin.
///
/// Wraps the [`ConsoleComponentProvider`] and provides plugin lifecycle
/// methods (`init`, `dispose`) and program activation/deactivation hooks.
///
/// # Example
///
/// ```
/// use ghidra_features::base::console::{ConsolePlugin, ConsoleService};
///
/// let mut plugin = ConsolePlugin::new("Console");
/// plugin.init();
/// plugin.program_activated("my_program");
/// plugin.add_message("script", "Analysis complete");
/// plugin.dispose();
/// ```
pub struct ConsolePlugin {
    provider: ConsoleComponentProvider,
    name: String,
    current_program: Option<String>,
    info: PluginInfo,
    initialized: bool,
}

impl ConsolePlugin {
    /// Create a new console plugin.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            provider: ConsoleComponentProvider::new(&name),
            name,
            current_program: None,
            info: PluginInfo::default(),
            initialized: false,
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get plugin info.
    pub fn info(&self) -> &PluginInfo {
        &self.info
    }

    /// Initialize the plugin.
    pub fn init(&mut self) {
        self.provider.set_visible(true);
        self.initialized = true;
    }

    /// Dispose of the plugin.
    pub fn dispose(&mut self) {
        self.provider.clear_messages();
        self.initialized = false;
    }

    /// Called when a program is activated.
    pub fn program_activated(&mut self, program: &str) {
        self.current_program = Some(program.to_string());
    }

    /// Called when a program is deactivated.
    pub fn program_deactivated(&mut self, _program: &str) {
        self.current_program = None;
    }

    /// Get the currently active program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Check if the plugin has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get a reference to the underlying console provider.
    pub fn provider(&self) -> &ConsoleComponentProvider {
        &self.provider
    }

    /// Get a mutable reference to the underlying console provider.
    pub fn provider_mut(&mut self) -> &mut ConsoleComponentProvider {
        &mut self.provider
    }
}

// Delegate ConsoleService methods to the provider
impl ConsoleService for ConsolePlugin {
    fn add_message(&mut self, originator: &str, message: &str) {
        self.provider.add_message(originator, message);
    }

    fn add_error_message(&mut self, originator: &str, message: &str) {
        self.provider.add_error_message(originator, message);
    }

    fn add_exception(&mut self, originator: &str, message: &str) {
        self.provider.add_exception(originator, message);
    }

    fn clear_messages(&mut self) {
        self.provider.clear_messages();
    }

    fn print(&mut self, msg: &str) {
        self.provider.print(msg);
    }

    fn print_error(&mut self, errmsg: &str) {
        self.provider.print_error(errmsg);
    }

    fn println(&mut self, msg: &str) {
        self.provider.println(msg);
    }

    fn println_error(&mut self, errmsg: &str) {
        self.provider.println_error(errmsg);
    }

    fn get_stdout(&self) -> Box<dyn std::io::Write> {
        self.provider.get_stdout()
    }

    fn get_stderr(&self) -> Box<dyn std::io::Write> {
        self.provider.get_stderr()
    }

    fn get_text(&self, offset: usize, length: usize) -> Option<String> {
        self.provider.get_text(offset, length)
    }

    fn get_text_length(&self) -> usize {
        self.provider.get_text_length()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = ConsolePlugin::new("TestConsole");
        assert_eq!(plugin.name(), "TestConsole");
        assert!(!plugin.is_initialized());
        assert!(plugin.current_program().is_none());
    }

    #[test]
    fn test_plugin_init() {
        let mut plugin = ConsolePlugin::new("Test");
        plugin.init();
        assert!(plugin.is_initialized());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = ConsolePlugin::new("Test");
        plugin.init();
        plugin.add_message("s", "hello");
        plugin.dispose();
        assert!(!plugin.is_initialized());
        assert_eq!(plugin.get_text_length(), 0);
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = ConsolePlugin::new("Test");
        assert!(plugin.current_program().is_none());

        plugin.program_activated("program1");
        assert_eq!(plugin.current_program(), Some("program1"));

        plugin.program_deactivated("program1");
        assert!(plugin.current_program().is_none());
    }

    #[test]
    fn test_plugin_info() {
        let plugin = ConsolePlugin::new("Test");
        let info = plugin.info();
        assert_eq!(info.status, PluginStatus::Released);
        assert_eq!(info.category, "Common");
        assert_eq!(info.short_description, "I/O Console");
    }

    #[test]
    fn test_plugin_console_service_delegation() {
        let mut plugin = ConsolePlugin::new("Test");
        plugin.add_message("s", "hello");
        plugin.add_error_message("s", "error");
        plugin.println("line");

        assert!(plugin.get_text_length() > 0);
    }

    #[test]
    fn test_plugin_provider_access() {
        let mut plugin = ConsolePlugin::new("Test");
        plugin.provider_mut().set_scroll_lock(true);
        assert!(plugin.provider().is_scroll_locked());
    }
}
