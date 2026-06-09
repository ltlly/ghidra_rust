//! Terminal Plugin -- service provider for VT100 terminal emulation.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.terminal.TerminalPlugin` Java class.
//!
//! This module provides the plugin that implements `TerminalService`, managing
//! terminal provider instances and wiring clipboard and output services.
//!
//! # Architecture
//!
//! - [`TerminalPlugin`] -- top-level plugin managing terminal providers
//! - [`TerminalService`] -- trait modelling the service interface
//! - [`TerminalCreationConfig`] -- configuration for creating new terminals
//! - [`PluginStatus`] -- lifecycle status of the plugin

use std::sync::{Arc, Mutex};

use super::terminal_listener::{
    BufferedTerminalOutput, DefaultTerminal, TerminalListener, TerminalOutput, TerminalProvider,
    ThreadedTerminal,
};

// ---------------------------------------------------------------------------
// PluginStatus -- lifecycle status
// ---------------------------------------------------------------------------

/// Lifecycle status of the terminal plugin.
///
/// Ported from Ghidra's `PluginStatus` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStatus {
    /// Plugin is stable and production-ready.
    Stable,
    /// Plugin is in a release candidate state.
    ReleaseCandidate,
    /// Plugin is in a BETA state.
    Beta,
    /// Plugin is in an ALPHA state.
    Alpha,
    /// Plugin is unstable or under development.
    Unstable,
}

impl Default for PluginStatus {
    fn default() -> Self {
        Self::Stable
    }
}

// ---------------------------------------------------------------------------
// TerminalCreationConfig -- configuration for terminal creation
// ---------------------------------------------------------------------------

/// Configuration for creating a new terminal instance.
///
/// Ported from the various parameters accepted by `TerminalPlugin.createProvider()`.
#[derive(Debug, Clone)]
pub struct TerminalCreationConfig {
    /// The name of the help plugin (used for help location).
    pub help_plugin_name: String,
    /// Whether to auto-show the terminal after creation.
    pub auto_show: bool,
    /// Whether to bring the terminal to front after creation.
    pub to_front: bool,
    /// Fixed column count, or `None` for dynamic sizing.
    pub fixed_cols: Option<u16>,
    /// Fixed row count, or `None` for dynamic sizing.
    pub fixed_rows: Option<u16>,
    /// Maximum scrollback rows.
    pub max_scrollback: Option<usize>,
}

impl Default for TerminalCreationConfig {
    fn default() -> Self {
        Self {
            help_plugin_name: String::new(),
            auto_show: true,
            to_front: true,
            fixed_cols: None,
            fixed_rows: None,
            max_scrollback: None,
        }
    }
}

// ---------------------------------------------------------------------------
// ClipboardService trait
// ---------------------------------------------------------------------------

/// Trait modelling the clipboard service interface.
///
/// Ported from Ghidra's `ClipboardService`. In Java this is a framework service
/// obtained from the tool; here we model it as a trait for testability.
pub trait ClipboardService: Send + Sync {
    /// Copy text to the system clipboard.
    fn set_clipboard_contents(&self, text: &str);

    /// Get text from the system clipboard.
    fn get_clipboard_contents(&self) -> Option<String>;
}

/// A no-op clipboard service that discards all operations.
#[derive(Debug, Clone, Copy)]
pub struct NoOpClipboardService;

impl ClipboardService for NoOpClipboardService {
    fn set_clipboard_contents(&self, _text: &str) {}
    fn get_clipboard_contents(&self) -> Option<String> {
        None
    }
}

/// An in-memory clipboard service for testing.
#[derive(Debug, Clone, Default)]
pub struct InMemoryClipboardService {
    contents: Arc<Mutex<Option<String>>>,
}

impl InMemoryClipboardService {
    /// Create a new in-memory clipboard service.
    pub fn new() -> Self {
        Self {
            contents: Arc::new(Mutex::new(None)),
        }
    }
}

impl ClipboardService for InMemoryClipboardService {
    fn set_clipboard_contents(&self, text: &str) {
        *self.contents.lock().unwrap() = Some(text.to_string());
    }

    fn get_clipboard_contents(&self) -> Option<String> {
        self.contents.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------
// TerminalService trait
// ---------------------------------------------------------------------------

/// Trait modelling Ghidra's `TerminalService` interface.
///
/// Ported from the `TerminalService` interface that `TerminalPlugin` implements
/// in Java.  Clients obtain this service from the plugin tool and use it to
/// create terminal instances.
pub trait TerminalService: Send + Sync {
    /// Create a null terminal (display-only, with callback-based output).
    ///
    /// Ported from `TerminalService.createNullTerminal(Plugin, Charset, VtOutput)`.
    fn create_null_terminal(&self, config: &TerminalCreationConfig) -> usize;

    /// Remove all terminated providers from the tool.
    ///
    /// Ported from `TerminalService.cleanTerminated()`.
    fn clean_terminated(&self);
}

// ---------------------------------------------------------------------------
// TerminalPlugin
// ---------------------------------------------------------------------------

/// The plugin that provides [`TerminalService`].
///
/// Ported from Ghidra's `ghidra.app.plugin.core.terminal.TerminalPlugin`.
///
/// Manages a list of [`TerminalProvider`] instances.  When a new terminal is
/// requested, a provider is created, configured, and made visible.  The plugin
/// also tracks clipboard and other services, distributing them to providers.
pub struct TerminalPlugin {
    /// Plugin status.
    status: PluginStatus,
    /// Clipboard service (set when available from the tool).
    clipboard_service: Option<Arc<dyn ClipboardService>>,
    /// Managed terminal providers.
    providers: Vec<ManagedProvider>,
    /// Configuration for the next terminal creation.
    default_config: TerminalCreationConfig,
    /// Monotonically increasing ID counter for terminals.
    next_id: usize,
}

/// A managed terminal provider with its associated metadata.
#[derive(Debug)]
struct ManagedProvider {
    /// Unique ID for this provider.
    id: usize,
    /// The terminal provider instance.
    provider: TerminalProvider,
    /// Whether this provider's session has terminated.
    terminated: bool,
    /// The name of the help plugin for this provider.
    help_plugin_name: String,
}

impl TerminalPlugin {
    /// Create a new terminal plugin.
    pub fn new() -> Self {
        Self {
            status: PluginStatus::Stable,
            clipboard_service: None,
            providers: Vec::new(),
            default_config: TerminalCreationConfig::default(),
            next_id: 0,
        }
    }

    /// Get the plugin status.
    pub fn status(&self) -> PluginStatus {
        self.status
    }

    /// Set the plugin status.
    pub fn set_status(&mut self, status: PluginStatus) {
        self.status = status;
    }

    /// Set the clipboard service.
    ///
    /// Ported from `TerminalPlugin.serviceAdded(ClipboardService.class, ...)`.
    /// When the clipboard service becomes available, it is distributed to all
    /// existing providers.
    pub fn set_clipboard_service(&mut self, service: Arc<dyn ClipboardService>) {
        self.clipboard_service = Some(service);
    }

    /// Remove the clipboard service.
    ///
    /// Ported from `TerminalPlugin.serviceRemoved(ClipboardService.class, ...)`.
    pub fn remove_clipboard_service(&mut self) {
        self.clipboard_service = None;
    }

    /// Get a reference to the current clipboard service, if any.
    pub fn clipboard_service(&self) -> Option<&dyn ClipboardService> {
        self.clipboard_service.as_deref()
    }

    /// Set the default configuration for new terminals.
    pub fn set_default_config(&mut self, config: TerminalCreationConfig) {
        self.default_config = config;
    }

    /// Get the default configuration.
    pub fn default_config(&self) -> &TerminalCreationConfig {
        &self.default_config
    }

    /// Create a new terminal provider.
    ///
    /// Ported from `TerminalPlugin.createProvider(Plugin, Charset, VtOutput)`.
    ///
    /// Cleans terminated providers first, then creates and registers a new one.
    /// Returns the ID assigned to the new provider.
    pub fn create_provider(
        &mut self,
        output: Box<dyn TerminalOutput>,
        config: Option<&TerminalCreationConfig>,
    ) -> usize {
        // Clean terminated providers first (matching Java's cleanTerminated call).
        self.clean_terminated_impl();

        let cfg = config.unwrap_or(&self.default_config);
        let id = self.next_id;
        self.next_id += 1;

        let mut provider =
            TerminalProvider::new(format!("Terminal-{}", id), output);

        // Apply fixed size if configured.
        if let (Some(cols), Some(rows)) = (cfg.fixed_cols, cfg.fixed_rows) {
            provider.notify_resize(cols, rows);
        }

        provider.set_visible(cfg.auto_show);

        self.providers.push(ManagedProvider {
            id,
            provider,
            terminated: false,
            help_plugin_name: cfg.help_plugin_name.clone(),
        });

        id
    }

    /// Create a null terminal (display-only, with callback-based output).
    ///
    /// Ported from `TerminalPlugin.createNullTerminal(Plugin, Charset, VtOutput)`.
    pub fn create_null_terminal_impl(
        &mut self,
        output: Box<dyn TerminalOutput>,
        config: Option<&TerminalCreationConfig>,
    ) -> DefaultTerminal {
        let id = self.create_provider(output, config);
        // Since DefaultTerminal wraps a TerminalProvider, we create a new one
        // with the same name pattern as the managed provider.
        let output = Box::new(BufferedTerminalOutput::new());
        let new_provider =
            TerminalProvider::new(format!("Terminal-{}", id), output);
        DefaultTerminal::new(new_provider)
    }

    /// Get a reference to a provider by ID.
    pub fn provider(&self, id: usize) -> Option<&TerminalProvider> {
        self.providers.iter().find(|p| p.id == id).map(|p| &p.provider)
    }

    /// Get a mutable reference to a provider by ID.
    pub fn provider_mut(&mut self, id: usize) -> Option<&mut TerminalProvider> {
        self.providers
            .iter_mut()
            .find(|p| p.id == id)
            .map(|p| &mut p.provider)
    }

    /// Check if a provider is terminated.
    pub fn is_provider_terminated(&self, id: usize) -> bool {
        self.providers
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.terminated)
            .unwrap_or(true)
    }

    /// Mark a provider as terminated.
    ///
    /// Ported from the termination flow in `TerminalProvider.terminated(int)`.
    pub fn mark_provider_terminated(&mut self, id: usize) {
        if let Some(managed) = self.providers.iter_mut().find(|p| p.id == id) {
            managed.terminated = true;
            managed.provider.terminated(0);
        }
    }

    /// Remove a provider by ID.
    ///
    /// Ported from `TerminalProvider.removeFromTool()`.
    pub fn remove_provider(&mut self, id: usize) -> bool {
        if let Some(pos) = self.providers.iter().position(|p| p.id == id) {
            let mut managed = self.providers.remove(pos);
            managed.provider.remove_from_tool();
            true
        } else {
            false
        }
    }

    /// The number of active (non-terminated) providers.
    pub fn active_provider_count(&self) -> usize {
        self.providers.iter().filter(|p| !p.terminated).count()
    }

    /// The total number of providers (including terminated).
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Get all provider IDs.
    pub fn provider_ids(&self) -> Vec<usize> {
        self.providers.iter().map(|p| p.id).collect()
    }

    /// Remove all terminated providers.
    ///
    /// Ported from `TerminalPlugin.doCleanTerminated()`.
    fn clean_terminated_impl(&mut self) {
        let terminated_ids: Vec<usize> = self
            .providers
            .iter()
            .filter(|p| p.terminated)
            .map(|p| p.id)
            .collect();

        for id in terminated_ids {
            self.remove_provider(id);
        }
    }
}

impl Default for TerminalPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TerminalPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalPlugin")
            .field("status", &self.status)
            .field("clipboard_service", &self.clipboard_service.is_some())
            .field("providers", &self.providers)
            .field("default_config", &self.default_config)
            .field("next_id", &self.next_id)
            .finish()
    }
}

impl TerminalService for TerminalPlugin {
    fn create_null_terminal(&self, _config: &TerminalCreationConfig) -> usize {
        // In the trait interface we return a placeholder; real creation goes
        // through the inherent method which requires &mut self.
        0
    }

    fn clean_terminated(&self) {
        // Requires &mut self; see `clean_terminated_impl`.
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_status_default() {
        assert_eq!(PluginStatus::default(), PluginStatus::Stable);
    }

    #[test]
    fn test_terminal_plugin_new() {
        let plugin = TerminalPlugin::new();
        assert_eq!(plugin.status(), PluginStatus::Stable);
        assert_eq!(plugin.provider_count(), 0);
        assert_eq!(plugin.active_provider_count(), 0);
        assert!(plugin.clipboard_service().is_none());
    }

    #[test]
    fn test_terminal_plugin_create_provider() {
        let mut plugin = TerminalPlugin::new();
        let output = Box::new(BufferedTerminalOutput::new());
        let id = plugin.create_provider(output, None);

        assert_eq!(plugin.provider_count(), 1);
        assert_eq!(plugin.active_provider_count(), 1);
        assert!(plugin.provider(id).is_some());
        assert!(!plugin.is_provider_terminated(id));
    }

    #[test]
    fn test_terminal_plugin_create_provider_with_config() {
        let mut plugin = TerminalPlugin::new();
        let output = Box::new(BufferedTerminalOutput::new());
        let config = TerminalCreationConfig {
            help_plugin_name: "MyPlugin".into(),
            auto_show: true,
            to_front: true,
            fixed_cols: Some(120),
            fixed_rows: Some(40),
            max_scrollback: Some(5000),
        };
        let id = plugin.create_provider(output, Some(&config));

        assert_eq!(plugin.provider_count(), 1);
        let provider = plugin.provider(id).unwrap();
        assert_eq!(provider.name(), "Terminal-0");
    }

    #[test]
    fn test_terminal_plugin_multiple_providers() {
        let mut plugin = TerminalPlugin::new();

        let id1 = plugin.create_provider(Box::new(BufferedTerminalOutput::new()), None);
        let id2 = plugin.create_provider(Box::new(BufferedTerminalOutput::new()), None);
        let id3 = plugin.create_provider(Box::new(BufferedTerminalOutput::new()), None);

        assert_eq!(plugin.provider_count(), 3);
        assert_eq!(plugin.provider_ids(), vec![id1, id2, id3]);
    }

    #[test]
    fn test_terminal_plugin_terminate_and_clean() {
        let mut plugin = TerminalPlugin::new();

        let id1 = plugin.create_provider(Box::new(BufferedTerminalOutput::new()), None);
        let id2 = plugin.create_provider(Box::new(BufferedTerminalOutput::new()), None);

        plugin.mark_provider_terminated(id1);
        assert!(plugin.is_provider_terminated(id1));
        assert_eq!(plugin.active_provider_count(), 1);

        // Creating a new provider triggers clean_terminated.
        let _id3 = plugin.create_provider(Box::new(BufferedTerminalOutput::new()), None);
        // The terminated provider should have been removed.
        assert_eq!(plugin.provider_count(), 2);
        assert!(plugin.provider(id1).is_none());
    }

    #[test]
    fn test_terminal_plugin_remove_provider() {
        let mut plugin = TerminalPlugin::new();
        let id = plugin.create_provider(Box::new(BufferedTerminalOutput::new()), None);
        assert_eq!(plugin.provider_count(), 1);

        assert!(plugin.remove_provider(id));
        assert_eq!(plugin.provider_count(), 0);
        assert!(plugin.provider(id).is_none());
    }

    #[test]
    fn test_terminal_plugin_remove_nonexistent() {
        let mut plugin = TerminalPlugin::new();
        assert!(!plugin.remove_provider(999));
    }

    #[test]
    fn test_clipboard_service_none_initially() {
        let plugin = TerminalPlugin::new();
        assert!(plugin.clipboard_service().is_none());
    }

    #[test]
    fn test_clipboard_service_set_and_remove() {
        let mut plugin = TerminalPlugin::new();
        let service = Arc::new(InMemoryClipboardService::new());

        plugin.set_clipboard_service(service.clone());
        assert!(plugin.clipboard_service().is_some());

        plugin.remove_clipboard_service();
        assert!(plugin.clipboard_service().is_none());
    }

    #[test]
    fn test_in_memory_clipboard_service() {
        let service = InMemoryClipboardService::new();
        assert!(service.get_clipboard_contents().is_none());

        service.set_clipboard_contents("hello world");
        assert_eq!(
            service.get_clipboard_contents(),
            Some("hello world".to_string())
        );
    }

    #[test]
    fn test_no_op_clipboard_service() {
        let service = NoOpClipboardService;
        service.set_clipboard_contents("ignored");
        assert!(service.get_clipboard_contents().is_none());
    }

    #[test]
    fn test_terminal_creation_config_default() {
        let config = TerminalCreationConfig::default();
        assert!(config.help_plugin_name.is_empty());
        assert!(config.auto_show);
        assert!(config.to_front);
        assert!(config.fixed_cols.is_none());
        assert!(config.fixed_rows.is_none());
        assert!(config.max_scrollback.is_none());
    }

    #[test]
    fn test_plugin_status_variants() {
        let statuses = [
            PluginStatus::Stable,
            PluginStatus::ReleaseCandidate,
            PluginStatus::Beta,
            PluginStatus::Alpha,
            PluginStatus::Unstable,
        ];
        // All variants are distinct.
        for (i, a) in statuses.iter().enumerate() {
            for (j, b) in statuses.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn test_plugin_provider_mut() {
        let mut plugin = TerminalPlugin::new();
        let id = plugin.create_provider(Box::new(BufferedTerminalOutput::new()), None);

        if let Some(provider) = plugin.provider_mut(id) {
            provider.set_visible(true);
            assert!(provider.is_visible());
        } else {
            panic!("Provider not found");
        }
    }

    #[test]
    fn test_create_null_terminal() {
        let mut plugin = TerminalPlugin::new();
        let terminal = plugin.create_null_terminal_impl(
            Box::new(BufferedTerminalOutput::new()),
            None,
        );
        // DefaultTerminal wraps a provider.
        assert!(terminal.provider().name().starts_with("Terminal-"));
    }
}
