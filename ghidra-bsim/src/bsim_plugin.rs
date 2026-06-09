//! BSim Plugin -- top-level plugin entry point.
//!
//! Ports Ghidra's `ghidra.features.bsim.gui.BSimPlugin`. In the Java version
//! this is a `Plugin` subclass that the Ghidra tool framework discovers via
//! `@ToolServiceProvider` annotations and wires into the application lifecycle.
//! In Rust we provide the same metadata and lifecycle hooks so a host
//! environment (e.g. an embedded Ghidra or a standalone CLI) can initialise
//! and shut down the BSim feature cleanly.

use std::sync::{Arc, RwLock};

use crate::query::bsim_plugin_package::BSimPluginPackage;
use crate::query::server_config::ServerConfig;
use crate::query::bsim_initializer::BSimInitializer;

/// Top-level BSim plugin.
///
/// Owns the module initializer and a set of registered server configurations.
/// A host calls [`BSimPlugin::init`] once at start-up and
/// [`BSimPlugin::dispose`] when the tool shuts down.
pub struct BSimPlugin {
    /// Plugin package metadata.
    package: BSimPluginPackage,
    /// Module-level initializer (registers protocols, etc.).
    initializer: BSimInitializer,
    /// Server configurations known to this plugin instance.
    server_configs: Vec<ServerConfig>,
    /// Help topic identifier shown in the Ghidra help browser.
    help_topic: String,
    /// Whether the plugin has been initialised.
    initialised: bool,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl BSimPlugin {
    /// Create a new BSim plugin with default settings.
    pub fn new() -> Self {
        Self {
            package: BSimPluginPackage::ghidra_bsim(),
            initializer: BSimInitializer::new(),
            server_configs: Vec::new(),
            help_topic: "BSimPlugin".to_string(),
            initialised: false,
            disposed: false,
        }
    }

    /// Create a BSim plugin with a custom help topic.
    pub fn with_help_topic(mut self, topic: impl Into<String>) -> Self {
        self.help_topic = topic.into();
        self
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /// Initialise the plugin.
    ///
    /// Runs the module initializer (protocol registration, etc.) and marks
    /// the plugin as ready.  Calling `init` more than once is a no-op.
    pub fn init(&mut self) {
        if self.initialised {
            return;
        }
        self.initializer.run();
        self.initialised = true;
    }

    /// Dispose of the plugin, releasing resources.
    ///
    /// After disposal the plugin should not be used.  Calling `dispose`
    /// more than once is a no-op.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.server_configs.clear();
        self.disposed = true;
    }

    /// Whether the plugin has been initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Get the plugin package metadata.
    pub fn package(&self) -> &BSimPluginPackage {
        &self.package
    }

    /// Get the help topic identifier.
    pub fn help_topic(&self) -> &str {
        &self.help_topic
    }

    /// Get the module initializer.
    pub fn initializer(&self) -> &BSimInitializer {
        &self.initializer
    }

    /// Get a reference to the registered server configurations.
    pub fn server_configs(&self) -> &[ServerConfig] {
        &self.server_configs
    }

    /// Register a server configuration with this plugin.
    pub fn add_server_config(&mut self, config: ServerConfig) {
        self.server_configs.push(config);
    }

    /// Remove a server configuration by backend type and database name.
    pub fn remove_server_config(&mut self, backend_type: &str, database: &str) {
        self.server_configs
            .retain(|c| !(c.backend_type == backend_type && c.database == database));
    }

    /// Get a mutable reference to the module initializer.
    pub fn initializer_mut(&mut self) -> &mut BSimInitializer {
        &mut self.initializer
    }
}

impl std::fmt::Debug for BSimPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BSimPlugin")
            .field("package", &self.package)
            .field("help_topic", &self.help_topic)
            .field("initialised", &self.initialised)
            .field("disposed", &self.disposed)
            .field("server_configs_count", &self.server_configs.len())
            .finish()
    }
}

impl Default for BSimPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe shared handle to a [`BSimPlugin`].
///
/// Equivalent to the Java pattern where the tool framework holds a reference
/// to the plugin and multiple services share it through the tool.
pub type SharedBSimPlugin = Arc<RwLock<BSimPlugin>>;

/// Create a new shared plugin handle.
pub fn new_shared_plugin() -> SharedBSimPlugin {
    Arc::new(RwLock::new(BSimPlugin::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_new() {
        let plugin = BSimPlugin::new();
        assert!(!plugin.is_initialised());
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.help_topic(), "BSimPlugin");
    }

    #[test]
    fn test_plugin_with_help_topic() {
        let plugin = BSimPlugin::new().with_help_topic("CustomTopic");
        assert_eq!(plugin.help_topic(), "CustomTopic");
    }

    #[test]
    fn test_plugin_init() {
        let mut plugin = BSimPlugin::new();
        plugin.init();
        assert!(plugin.is_initialised());
        assert!(plugin.initializer().is_initialized());
    }

    #[test]
    fn test_plugin_init_idempotent() {
        let mut plugin = BSimPlugin::new();
        plugin.init();
        plugin.init();
        assert!(plugin.is_initialised());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = BSimPlugin::new();
        plugin.init();
        plugin.add_server_config(ServerConfig::postgresql("host", "db"));
        assert_eq!(plugin.server_configs().len(), 1);

        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(plugin.server_configs().is_empty());
    }

    #[test]
    fn test_plugin_dispose_idempotent() {
        let mut plugin = BSimPlugin::new();
        plugin.dispose();
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_plugin_add_remove_server_config() {
        let mut plugin = BSimPlugin::new();
        plugin.add_server_config(ServerConfig::postgresql("h1", "db1"));
        plugin.add_server_config(ServerConfig::elasticsearch("h2", 9200));
        assert_eq!(plugin.server_configs().len(), 2);

        plugin.remove_server_config("postgresql", "db1");
        assert_eq!(plugin.server_configs().len(), 1);
        assert_eq!(plugin.server_configs()[0].backend_type, "elastic");
    }

    #[test]
    fn test_plugin_package() {
        let plugin = BSimPlugin::new();
        assert_eq!(plugin.package().name(), "GhidraBSim");
    }

    #[test]
    fn test_shared_plugin() {
        let shared = new_shared_plugin();
        {
            let mut p = shared.write().unwrap();
            p.init();
        }
        let p = shared.read().unwrap();
        assert!(p.is_initialised());
    }

    #[test]
    fn test_default_trait() {
        let plugin = BSimPlugin::default();
        assert!(!plugin.is_initialised());
    }
}
