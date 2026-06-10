//! Terminal plugin -- integrates the terminal provider into the Ghidra tool
//! framework.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.terminal.TerminalPlugin`.
//!
//! This module provides [`TerminalPlugin`], which owns a [`TerminalProvider`]
//! and manages the plugin lifecycle (init, dispose, program activation).
//! It delegates I/O calls to the provider so that the display layer can be
//! tested independently.
//!
//! [`TerminalProvider`]: super::terminal_provider::TerminalProvider

use super::terminal_provider::TerminalProvider;

/// Plugin metadata status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStatus {
    /// Plugin is released and stable.
    Released,
    /// Plugin is in beta.
    Beta,
    /// Plugin is unstable / experimental.
    Unstable,
}

/// Terminal plugin configuration metadata.
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
            short_description: "VT100 Terminal Emulator".to_string(),
            description: "Provides an embedded VT100 terminal emulator.".to_string(),
        }
    }
}

/// Terminal plugin.
///
/// Wraps a [`TerminalProvider`] and provides Ghidra plugin lifecycle methods
/// (`init`, `dispose`) as well as program activation / deactivation hooks.
///
/// # Example
///
/// ```
/// use ghidra_features::base::terminal::{TerminalPlugin, TerminalService};
///
/// let mut plugin = TerminalPlugin::new("Terminal");
/// plugin.init();
/// plugin.program_activated("my_program");
/// plugin.write("Hello, terminal!\n");
/// assert!(plugin.get_screen_text().contains("Hello"));
/// plugin.dispose();
/// ```
pub struct TerminalPlugin {
    provider: TerminalProvider,
    name: String,
    current_program: Option<String>,
    info: PluginInfo,
    initialized: bool,
}

impl TerminalPlugin {
    /// Create a new terminal plugin.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            provider: TerminalProvider::new(&name),
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
        self.provider.clear();
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

    /// Get a reference to the underlying terminal provider.
    pub fn provider(&self) -> &TerminalProvider {
        &self.provider
    }

    /// Get a mutable reference to the underlying terminal provider.
    pub fn provider_mut(&mut self) -> &mut TerminalProvider {
        &mut self.provider
    }
}

// -- TerminalService delegation --------------------------------------------------

/// Trait for interacting with the terminal from the plugin level.
///
/// This is a convenience re-export so callers can use `TerminalPlugin`
/// directly as a `TerminalService`.
pub trait TerminalService {
    /// Write text to the terminal.
    fn write(&mut self, text: &str);

    /// Write text followed by a newline.
    fn writeln(&mut self, text: &str);

    /// Clear the terminal display.
    fn clear(&mut self);

    /// Get the full screen contents as a string.
    fn get_screen_text(&self) -> String;

    /// Get a specific row of the terminal as a string.
    fn get_row_text(&self, row: usize) -> Option<String>;

    /// Get the current cursor row.
    fn cursor_row(&self) -> usize;

    /// Get the current cursor column.
    fn cursor_col(&self) -> usize;
}

impl TerminalService for TerminalPlugin {
    fn write(&mut self, text: &str) {
        self.provider.write(text);
    }

    fn writeln(&mut self, text: &str) {
        self.provider.writeln(text);
    }

    fn clear(&mut self) {
        self.provider.clear();
    }

    fn get_screen_text(&self) -> String {
        self.provider.get_screen_text()
    }

    fn get_row_text(&self, row: usize) -> Option<String> {
        self.provider.get_row_text(row)
    }

    fn cursor_row(&self) -> usize {
        self.provider.cursor_row()
    }

    fn cursor_col(&self) -> usize {
        self.provider.cursor_col()
    }
}

// -- Display / Default -----------------------------------------------------------

impl std::fmt::Debug for TerminalPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalPlugin")
            .field("name", &self.name)
            .field("initialized", &self.initialized)
            .field("current_program", &self.current_program)
            .finish()
    }
}

impl Default for TerminalPlugin {
    fn default() -> Self {
        Self::new("TerminalPlugin")
    }
}

impl std::fmt::Display for TerminalPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TerminalPlugin({})", self.name)
    }
}

// -- Tests -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = TerminalPlugin::new("TestTerminal");
        assert_eq!(plugin.name(), "TestTerminal");
        assert!(!plugin.is_initialized());
        assert!(plugin.current_program().is_none());
    }

    #[test]
    fn test_plugin_init() {
        let mut plugin = TerminalPlugin::new("Test");
        plugin.init();
        assert!(plugin.is_initialized());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = TerminalPlugin::new("Test");
        plugin.init();
        plugin.write("hello");
        plugin.dispose();
        assert!(!plugin.is_initialized());
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = TerminalPlugin::new("Test");
        assert!(plugin.current_program().is_none());

        plugin.program_activated("prog1");
        assert_eq!(plugin.current_program(), Some("prog1"));

        plugin.program_deactivated("prog1");
        assert!(plugin.current_program().is_none());
    }

    #[test]
    fn test_plugin_info() {
        let plugin = TerminalPlugin::new("Test");
        let info = plugin.info();
        assert_eq!(info.status, PluginStatus::Released);
        assert_eq!(info.category, "Common");
        assert_eq!(info.short_description, "VT100 Terminal Emulator");
    }

    #[test]
    fn test_plugin_terminal_service_delegation() {
        let mut plugin = TerminalPlugin::new("Test");
        plugin.write("Hello");
        plugin.writeln(" World");
        let text = plugin.get_screen_text();
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
    }

    #[test]
    fn test_plugin_clear() {
        let mut plugin = TerminalPlugin::new("Test");
        plugin.write("data");
        plugin.clear();
        assert_eq!(plugin.cursor_row(), 0);
        assert_eq!(plugin.cursor_col(), 0);
    }

    #[test]
    fn test_plugin_provider_access() {
        let mut plugin = TerminalPlugin::new("Test");
        plugin.provider_mut().set_visible(false);
        assert!(!plugin.provider().is_visible());
    }

    #[test]
    fn test_plugin_display() {
        let plugin = TerminalPlugin::new("MyTerm");
        assert_eq!(format!("{}", plugin), "TerminalPlugin(MyTerm)");
    }

    #[test]
    fn test_plugin_default() {
        let plugin = TerminalPlugin::default();
        assert_eq!(plugin.name(), "TerminalPlugin");
    }
}
