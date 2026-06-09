//! Byte Viewer Plugin implementation.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.byteviewer.ByteViewerPlugin`.
//!
//! This is the top-level plugin that integrates the byte viewer into the
//! Ghidra framework. It manages provider lifecycle, coordinates navigation
//! events, and wires the byte viewer component to the current program and
//! address set.
//!
//! # Key types
//!
//! - [`ByteViewerPlugin`] -- the main plugin struct
//! - [`ByteViewerProvider`] -- the provider that owns the component and
//!   manages its visibility within the tool

use num_bigint::BigInt;
use std::collections::BTreeMap;

use super::{
    ByteBlockInfo, ByteBlockSet, ByteBlockSelection, ByteViewerConfigOptions,
};
use super::byte_viewer_component::ByteViewerComponent;

// ---------------------------------------------------------------------------
// ByteViewerProvider
// ---------------------------------------------------------------------------

/// Provider that hosts the [`ByteViewerComponent`] within the tool.
///
/// Ported from Ghidra's `ByteViewerPlugin$ByteViewerProvider` inner class.
///
/// The provider is responsible for creating the component, managing its
/// connection to the active program, and forwarding navigation/address
/// change events.
#[derive(Debug)]
pub struct ByteViewerProvider {
    /// Display name for this provider.
    name: String,
    /// The owned byte viewer component.
    component: ByteViewerComponent,
    /// Whether this provider is currently visible.
    visible: bool,
    /// The currently connected program (opaque name reference).
    program_name: Option<String>,
    /// Whether the provider has been disposed.
    disposed: bool,
}

impl ByteViewerProvider {
    /// Create a new provider with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            component: ByteViewerComponent::new(),
            visible: false,
            program_name: None,
            disposed: false,
        }
    }

    /// The provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether the provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Connect this provider to a program.
    pub fn program_opened(&mut self, program_name: impl Into<String>) {
        self.program_name = Some(program_name.into());
        self.component.clear();
    }

    /// Disconnect from the current program.
    pub fn program_closed(&mut self) {
        self.program_name = None;
        self.component.clear();
    }

    /// Get a reference to the component.
    pub fn component(&self) -> &ByteViewerComponent {
        &self.component
    }

    /// Get a mutable reference to the component.
    pub fn component_mut(&mut self) -> &mut ByteViewerComponent {
        &mut self.component
    }

    /// Dispose of this provider, releasing resources.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.visible = false;
        self.program_name = None;
        self.component.clear();
    }
}

// ---------------------------------------------------------------------------
// ByteViewerPlugin
// ---------------------------------------------------------------------------

/// The main plugin that manages byte viewer instances.
///
/// Ported from Ghidra's `ByteViewerPlugin`.
///
/// This plugin:
/// - Creates and manages a [`ByteViewerProvider`] for each open program
/// - Listens for program open/close events and navigates the viewer
/// - Provides programmatic access to the byte viewer component
/// - Manages configuration options that are shared across providers
#[derive(Debug)]
pub struct ByteViewerPlugin {
    /// Providers keyed by program name.
    providers: BTreeMap<String, ByteViewerProvider>,
    /// Global configuration options.
    config: ByteViewerConfigOptions,
    /// Whether the plugin has been disposed.
    disposed: bool,
    /// The name of the currently active program.
    active_program: Option<String>,
}

impl ByteViewerPlugin {
    /// Create a new byte viewer plugin.
    pub fn new() -> Self {
        Self {
            providers: BTreeMap::new(),
            config: ByteViewerConfigOptions::new(),
            disposed: false,
            active_program: None,
        }
    }

    /// Create with custom configuration options.
    pub fn with_config(config: ByteViewerConfigOptions) -> Self {
        Self {
            providers: BTreeMap::new(),
            config,
            disposed: false,
            active_program: None,
        }
    }

    /// Handle a program being opened.
    ///
    /// Creates a new provider for the program and makes it the active viewer.
    pub fn program_opened(&mut self, program_name: impl Into<String>) {
        let name = program_name.into();
        let mut provider = ByteViewerProvider::new(&name);
        provider.program_opened(&name);
        provider.component_mut().set_config(self.config.clone());
        self.providers.insert(name.clone(), provider);
        self.active_program = Some(name);
    }

    /// Handle a program being closed.
    ///
    /// Disposes the provider associated with the program.
    pub fn program_closed(&mut self, program_name: &str) {
        if let Some(mut provider) = self.providers.remove(program_name) {
            provider.dispose();
        }
        if self.active_program.as_deref() == Some(program_name) {
            self.active_program = self.providers.keys().next().cloned();
        }
    }

    /// Set the active program.
    pub fn set_active_program(&mut self, program_name: Option<String>) {
        self.active_program = program_name;
    }

    /// Get the active program name.
    pub fn active_program(&self) -> Option<&str> {
        self.active_program.as_deref()
    }

    /// Get the provider for the given program.
    pub fn provider(&self, program_name: &str) -> Option<&ByteViewerProvider> {
        self.providers.get(program_name)
    }

    /// Get the mutable provider for the given program.
    pub fn provider_mut(&mut self, program_name: &str) -> Option<&mut ByteViewerProvider> {
        self.providers.get_mut(program_name)
    }

    /// Get the active provider.
    pub fn active_provider(&self) -> Option<&ByteViewerProvider> {
        self.active_program
            .as_ref()
            .and_then(|name| self.providers.get(name))
    }

    /// Get the active provider (mutable).
    pub fn active_provider_mut(&mut self) -> Option<&mut ByteViewerProvider> {
        self.active_program
            .clone()
            .and_then(move |name| self.providers.get_mut(&name))
    }

    /// Get the configuration options.
    pub fn config(&self) -> &ByteViewerConfigOptions {
        &self.config
    }

    /// Get mutable configuration options.
    pub fn config_mut(&mut self) -> &mut ByteViewerConfigOptions {
        &mut self.config
    }

    /// Set configuration options and propagate to all providers.
    pub fn set_config(&mut self, config: ByteViewerConfigOptions) {
        self.config = config.clone();
        for provider in self.providers.values_mut() {
            provider.component_mut().set_config(config.clone());
        }
    }

    /// Navigate the active viewer to the given address.
    pub fn go_to(&mut self, address: u64) {
        if let Some(provider) = self.active_provider_mut() {
            provider.component_mut().go_to_address(address);
        }
    }

    /// Set the byte block set for the active viewer.
    pub fn set_byte_block_set(&mut self, block_set: ByteBlockSet) {
        if let Some(provider) = self.active_provider_mut() {
            provider.component_mut().set_block_set(block_set);
        }
    }

    /// Get all open program names.
    pub fn open_programs(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }

    /// Number of active providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose of the plugin and all providers.
    pub fn dispose(&mut self) {
        let providers = std::mem::take(&mut self.providers);
        for (_, mut provider) in providers.into_iter() {
            provider.dispose();
        }
        self.disposed = true;
        self.active_program = None;
    }
}

impl Default for ByteViewerPlugin {
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
    fn test_plugin_create() {
        let plugin = ByteViewerPlugin::new();
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.provider_count(), 0);
        assert!(plugin.active_program().is_none());
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = ByteViewerPlugin::new();
        plugin.program_opened("test.exe");
        assert_eq!(plugin.provider_count(), 1);
        assert_eq!(plugin.active_program(), Some("test.exe"));

        let provider = plugin.provider("test.exe").unwrap();
        assert_eq!(provider.name(), "test.exe");
        assert!(provider.is_disposed() == false);

        plugin.program_closed("test.exe");
        assert_eq!(plugin.provider_count(), 0);
        assert!(plugin.active_program().is_none());
    }

    #[test]
    fn test_plugin_multiple_programs() {
        let mut plugin = ByteViewerPlugin::new();
        plugin.program_opened("prog1.exe");
        plugin.program_opened("prog2.exe");
        assert_eq!(plugin.provider_count(), 2);
        assert_eq!(plugin.active_program(), Some("prog2.exe"));

        plugin.program_closed("prog2.exe");
        assert_eq!(plugin.active_program(), Some("prog1.exe"));
    }

    #[test]
    fn test_plugin_config_propagation() {
        let mut plugin = ByteViewerPlugin::new();
        plugin.program_opened("test.exe");

        let mut config = ByteViewerConfigOptions::new();
        config.set_bytes_per_line(32);
        plugin.set_config(config);

        let provider = plugin.provider("test.exe").unwrap();
        assert_eq!(
            provider.component().config().bytes_per_line(),
            32
        );
    }

    #[test]
    fn test_plugin_go_to() {
        let mut plugin = ByteViewerPlugin::new();
        plugin.program_opened("test.exe");

        let mut block_set = ByteBlockSet::new("test.exe");
        block_set.add_block(super::super::ByteBlock::new(".text", 0x1000, vec![0; 256]));
        plugin.set_byte_block_set(block_set);

        plugin.go_to(0x1000);
        let provider = plugin.provider("test.exe").unwrap();
        assert!(provider.component().current_address().is_some());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = ByteViewerPlugin::new();
        plugin.program_opened("test.exe");
        plugin.dispose();

        assert!(plugin.is_disposed());
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = ByteViewerProvider::new("test");
        assert!(!provider.is_visible());
        provider.set_visible(true);
        assert!(provider.is_visible());
    }

    #[test]
    fn test_provider_program_connection() {
        let mut provider = ByteViewerProvider::new("test");
        provider.program_opened("prog.exe");
        assert!(!provider.is_disposed());

        provider.program_closed();
        provider.dispose();
        assert!(provider.is_disposed());
    }

    #[test]
    fn test_plugin_open_programs() {
        let mut plugin = ByteViewerPlugin::new();
        plugin.program_opened("a.exe");
        plugin.program_opened("b.exe");
        let names = plugin.open_programs();
        assert_eq!(names, vec!["a.exe", "b.exe"]);
    }

    #[test]
    fn test_plugin_with_config() {
        let mut config = ByteViewerConfigOptions::new();
        config.set_bytes_per_line(32);
        let plugin = ByteViewerPlugin::with_config(config);
        assert_eq!(plugin.config().bytes_per_line(), 32);
    }
}
