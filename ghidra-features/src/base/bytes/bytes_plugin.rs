//! BytesView Plugin -- top-level plugin for the Byte Viewer feature.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.byteviewer.ByteViewerPlugin`
//! and `ghidra.app.plugin.core.byteviewer.AbstractByteViewerPlugin`.
//!
//! This module provides [`BytesViewPlugin`], which manages the lifecycle of
//! one connected [`BytesViewProvider`] (tied to the active program) and zero
//! or more disconnected providers (snapshot views).  It forwards navigation
//! events (location, selection, highlight) between providers and the tool,
//! handles program open/close/activate events, and persists configuration.
//!
//! # Architecture
//!
//! ```text
//! BytesViewPlugin
//!   ├── connected_provider: BytesViewProvider  (always present, linked to active program)
//!   ├── disconnected_providers: Vec<BytesViewProvider>  (detached snapshots)
//!   └── state tracking (current_program, current_location, events_disabled)
//! ```

use std::fmt;

use super::bytes_provider::BytesViewProvider;

// ---------------------------------------------------------------------------
// BytesViewPlugin
// ---------------------------------------------------------------------------

/// The BytesView plugin.
///
/// Manages a connected provider that follows the active program and
/// a list of disconnected providers that hold independent snapshots.
///
/// Ported from `AbstractByteViewerPlugin` and `ByteViewerPlugin`.
#[derive(Debug)]
pub struct BytesViewPlugin {
    /// Plugin name.
    name: String,
    /// The connected (primary) provider tied to the active program.
    connected_provider: BytesViewProvider,
    /// Disconnected (snapshot) providers.
    disconnected_providers: Vec<BytesViewProvider>,
    /// Name of the currently active program (if any).
    current_program: Option<String>,
    /// Current program location (opaque address string).
    current_location: Option<String>,
    /// Whether plugin events are temporarily suppressed.
    events_disabled: bool,
    /// Whether the plugin has been initialized.
    initialized: bool,
    /// Whether the plugin has been disposed.
    disposed: bool,
    /// Stored configuration (key-value pairs).
    config: std::collections::HashMap<String, ConfigValue>,
}

/// A configuration value stored by the plugin.
#[derive(Debug, Clone)]
pub enum ConfigValue {
    /// Boolean value.
    Bool(bool),
    /// Integer value.
    Int(i32),
    /// String value.
    String(String),
}

impl fmt::Display for ConfigValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{}", v),
            Self::Int(v) => write!(f, "{}", v),
            Self::String(v) => write!(f, "{}", v),
        }
    }
}

impl BytesViewPlugin {
    /// Creates a new BytesView plugin.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            connected_provider: BytesViewProvider::new("Bytes", true),
            name,
            disconnected_providers: Vec::new(),
            current_program: None,
            current_location: None,
            events_disabled: false,
            initialized: false,
            disposed: false,
            config: std::collections::HashMap::new(),
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
        self.connected_provider.set_visible(true);
    }

    /// Disposes the plugin and all providers.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.connected_provider.dispose();
        for provider in &mut self.disconnected_providers {
            provider.dispose();
        }
        self.disconnected_providers.clear();
    }

    /// Whether the plugin is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // ---- Provider access ----

    /// Returns a reference to the connected provider.
    pub fn connected_provider(&self) -> &BytesViewProvider {
        &self.connected_provider
    }

    /// Returns a mutable reference to the connected provider.
    pub fn connected_provider_mut(&mut self) -> &mut BytesViewProvider {
        &mut self.connected_provider
    }

    /// Returns a reference to the disconnected providers.
    pub fn disconnected_providers(&self) -> &[BytesViewProvider] {
        &self.disconnected_providers
    }

    /// Creates a new disconnected (snapshot) provider and returns its index.
    pub fn create_disconnected_provider(&mut self) -> usize {
        let idx = self.disconnected_providers.len();
        let mut provider = BytesViewProvider::new(
            format!("Bytes ({})", idx + 1),
            false,
        );
        provider.set_visible(true);
        if let Some(ref prog) = self.current_program {
            provider.program_opened(prog.clone());
        }
        self.disconnected_providers.push(provider);
        idx
    }

    /// Removes a disconnected provider by index.
    pub fn remove_disconnected_provider(&mut self, index: usize) -> Option<BytesViewProvider> {
        if index < self.disconnected_providers.len() {
            Some(self.disconnected_providers.remove(index))
        } else {
            None
        }
    }

    /// Number of disconnected providers.
    pub fn disconnected_count(&self) -> usize {
        self.disconnected_providers.len()
    }

    // ---- Program lifecycle ----

    /// Called when a program is opened.
    pub fn program_opened(&mut self, program_name: impl Into<String>) {
        let name = program_name.into();
        self.current_program = Some(name.clone());
        self.current_location = None;
        self.connected_provider.program_opened(name);
    }

    /// Called when the active program changes.
    pub fn program_activated(&mut self, program_name: impl Into<String>) {
        let name = program_name.into();
        self.current_program = Some(name.clone());
        self.current_location = None;
        self.connected_provider.program_opened(name);
    }

    /// Called when a program is closed.
    pub fn program_closed(&mut self, program_name: &str) {
        if self.current_program.as_deref() == Some(program_name) {
            self.current_program = None;
            self.current_location = None;
            self.connected_provider.program_closed();
        }
        // Remove any disconnected providers for this program.
        self.disconnected_providers
            .retain(|p| p.program_name() != Some(program_name));
    }

    /// The name of the currently active program, if any.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    // ---- Navigation events ----

    /// Called when the program location changes.
    pub fn location_changed(&mut self, location: impl Into<String>) {
        if self.events_disabled {
            return;
        }
        self.current_location = Some(location.into());
    }

    /// Called when the program selection changes.
    pub fn selection_changed(&mut self, _selection: &str) {
        if self.events_disabled {
            return;
        }
        // Forward to connected provider as needed.
    }

    /// Called when the program highlight changes.
    pub fn highlight_changed(&mut self, _highlight: &str) {
        if self.events_disabled {
            return;
        }
        // Forward to connected provider as needed.
    }

    /// The current program location, if any.
    pub fn current_location(&self) -> Option<&str> {
        self.current_location.as_deref()
    }

    // ---- Event suppression ----

    /// Runs a closure with plugin events disabled.
    pub fn with_events_disabled<F: FnOnce(&mut Self)>(&mut self, f: F) {
        let prev = self.events_disabled;
        self.events_disabled = true;
        f(self);
        self.events_disabled = prev;
    }

    /// Whether events are currently disabled.
    pub fn are_events_disabled(&self) -> bool {
        self.events_disabled
    }

    // ---- Configuration persistence ----

    /// Writes configuration state to the given key-value store.
    pub fn write_config_state(&self, store: &mut std::collections::HashMap<String, ConfigValue>) {
        self.connected_provider.write_config_state(store);
    }

    /// Reads configuration state from the given key-value store.
    pub fn read_config_state(&mut self, store: &std::collections::HashMap<String, ConfigValue>) {
        self.connected_provider.read_config_state(store);
    }

    /// Sets a config value.
    pub fn set_config(&mut self, key: impl Into<String>, value: ConfigValue) {
        self.config.insert(key.into(), value);
    }

    /// Gets a config value.
    pub fn get_config(&self, key: &str) -> Option<&ConfigValue> {
        self.config.get(key)
    }
}

impl Default for BytesViewPlugin {
    fn default() -> Self {
        Self::new("BytesViewPlugin")
    }
}

impl fmt::Display for BytesViewPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BytesViewPlugin({}, connected={}, disconnected={})",
            self.name,
            self.connected_provider.name(),
            self.disconnected_providers.len()
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = BytesViewPlugin::new("TestBytes");
        assert_eq!(plugin.name(), "TestBytes");
        assert!(!plugin.is_initialized());
        assert!(!plugin.is_disposed());
        assert!(plugin.current_program().is_none());
        assert_eq!(plugin.disconnected_count(), 0);
    }

    #[test]
    fn test_plugin_init_dispose() {
        let mut plugin = BytesViewPlugin::new("TestBytes");
        plugin.init();
        assert!(plugin.is_initialized());
        assert!(plugin.connected_provider().is_visible());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_program_lifecycle() {
        let mut plugin = BytesViewPlugin::new("TestBytes");
        plugin.init();
        plugin.program_opened("test.exe");
        assert_eq!(plugin.current_program(), Some("test.exe"));
        assert_eq!(
            plugin.connected_provider().program_name(),
            Some("test.exe")
        );

        plugin.program_closed("test.exe");
        assert!(plugin.current_program().is_none());
    }

    #[test]
    fn test_disconnected_provider() {
        let mut plugin = BytesViewPlugin::new("TestBytes");
        plugin.init();
        plugin.program_opened("test.exe");

        let idx = plugin.create_disconnected_provider();
        assert_eq!(idx, 0);
        assert_eq!(plugin.disconnected_count(), 1);
        assert_eq!(
            plugin.disconnected_providers()[0].program_name(),
            Some("test.exe")
        );

        plugin.remove_disconnected_provider(0);
        assert_eq!(plugin.disconnected_count(), 0);
    }

    #[test]
    fn test_event_suppression() {
        let mut plugin = BytesViewPlugin::new("TestBytes");
        assert!(!plugin.are_events_disabled());
        plugin.with_events_disabled(|p| {
            assert!(p.are_events_disabled());
        });
        assert!(!plugin.are_events_disabled());
    }

    #[test]
    fn test_location_changed() {
        let mut plugin = BytesViewPlugin::new("TestBytes");
        plugin.init();
        plugin.program_opened("test.exe");
        plugin.location_changed("0x401000");
        assert_eq!(plugin.current_location(), Some("0x401000"));
    }

    #[test]
    fn test_config() {
        let mut plugin = BytesViewPlugin::new("TestBytes");
        plugin.set_config("bytes_per_line", ConfigValue::Int(16));
        assert!(matches!(
            plugin.get_config("bytes_per_line"),
            Some(ConfigValue::Int(16))
        ));
    }

    #[test]
    fn test_default() {
        let plugin = BytesViewPlugin::default();
        assert_eq!(plugin.name(), "BytesViewPlugin");
    }

    #[test]
    fn test_display() {
        let plugin = BytesViewPlugin::new("Test");
        let s = format!("{}", plugin);
        assert!(s.contains("Test"));
        assert!(s.contains("connected="));
    }
}
