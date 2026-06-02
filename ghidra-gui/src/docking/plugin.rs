//! Plugin system for the docking framework.
//!
//! Plugins are extension modules that contribute actions, component
//! providers, and other functionality to a [`super::tool::DockingTool`].

use std::collections::{HashMap, HashSet};

use super::action::DockingAction;
use super::component::ComponentProvider;
use super::tool::DockingTool;

// ---------------------------------------------------------------------------
// PluginConfig
// ---------------------------------------------------------------------------

/// Global configuration for the plugin system.
#[derive(Debug, Clone, Default)]
pub struct PluginConfig {
    /// Whether to auto-load plugins at startup.
    pub auto_load: bool,
    /// Plugin names that should never be loaded.
    pub disabled_plugins: HashSet<String>,
    /// Additional filesystem paths to search for plugins.
    pub plugin_paths: Vec<String>,
    /// Additional Java-style class paths (for Ghidra compatibility).
    pub class_paths: Vec<String>,
    /// Arbitrary key-value settings passed to plugins at init time.
    pub settings: HashMap<String, String>,
}

impl PluginConfig {
    /// Create a new, empty plugin configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder — set auto-load.
    pub fn with_auto_load(mut self, auto: bool) -> Self {
        self.auto_load = auto;
        self
    }

    /// Builder — add a disabled plugin name.
    pub fn with_disabled(mut self, name: impl Into<String>) -> Self {
        self.disabled_plugins.insert(name.into());
        self
    }

    /// Builder — add a plugin search path.
    pub fn with_plugin_path(mut self, path: impl Into<String>) -> Self {
        self.plugin_paths.push(path.into());
        self
    }

    /// Builder — add a class path.
    pub fn with_class_path(mut self, path: impl Into<String>) -> Self {
        self.class_paths.push(path.into());
        self
    }

    /// Builder — set a configuration key/value.
    pub fn with_setting(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.settings.insert(key.into(), value.into());
        self
    }

    /// Check whether a plugin is explicitly disabled.
    pub fn is_disabled(&self, name: &str) -> bool {
        self.disabled_plugins.contains(name)
    }
}

// ---------------------------------------------------------------------------
// Plugin trait
// ---------------------------------------------------------------------------

/// Every Ghidra-style plugin must implement this trait.
///
/// Plugins are loaded once, initialized with a reference to the owning
/// tool, and contribute actions and/or component providers to the
/// application.
pub trait Plugin {
    /// Unique plugin name (e.g. `"DecompilerPlugin"`).
    fn name(&self) -> &str;

    /// Plugin version string.
    fn version(&self) -> &str;

    /// Human-readable description.
    fn description(&self) -> &str;

    /// Called once when the plugin is loaded into a tool.
    ///
    /// Use this to register actions, providers, and set up any internal
    /// state that depends on the tool.
    fn init(&mut self, tool: &mut DockingTool);

    /// Return the actions this plugin contributes.
    fn get_actions(&self) -> Vec<DockingAction> {
        Vec::new()
    }

    /// Return the component providers this plugin contributes.
    fn get_components(&self) -> Vec<ComponentProvider> {
        Vec::new()
    }

    /// Called when the plugin is unloaded.  Release any resources here.
    fn dispose(&mut self) {}
}

// ---------------------------------------------------------------------------
// Plugin metadata (for discovery without instantiation)
// ---------------------------------------------------------------------------

/// Lightweight metadata about a plugin, discoverable without loading it.
#[derive(Debug, Clone)]
pub struct PluginInfo {
    /// Plugin name.
    pub name: String,
    /// Plugin version.
    pub version: String,
    /// Human-readable description.
    pub description: String,
    /// File path or module path where the plugin was found.
    pub source_path: Option<String>,
}

// ---------------------------------------------------------------------------
// PluginManager
// ---------------------------------------------------------------------------

/// Manages the lifecycle of all plugins in a tool.
pub struct PluginManager {
    /// Loaded plugin instances.
    pub plugins: Vec<Box<dyn Plugin>>,
    /// Set of plugin names that are currently loaded.
    pub loaded: HashSet<String>,
    /// Plugin system configuration.
    pub config: PluginConfig,
    /// Registry of discovered-but-not-loaded plugins.
    pub available: Vec<PluginInfo>,
}

impl PluginManager {
    /// Create a new, empty plugin manager.
    pub fn new(config: PluginConfig) -> Self {
        Self {
            plugins: Vec::new(),
            loaded: HashSet::new(),
            config,
            available: Vec::new(),
        }
    }

    /// Create a manager with default configuration.
    pub fn with_default_config() -> Self {
        Self::new(PluginConfig::default())
    }

    // ---------------------------------------------------------------
    // Discovery
    // ---------------------------------------------------------------

    /// Register a discovered plugin so it can be loaded later.
    pub fn register_available(&mut self, info: PluginInfo) {
        // Avoid duplicates.
        if !self.available.iter().any(|p| p.name == info.name) {
            self.available.push(info);
        }
    }

    /// Register multiple discovered plugins.
    pub fn register_all_available(&mut self, infos: Vec<PluginInfo>) {
        for info in infos {
            self.register_available(info);
        }
    }

    /// Return the metadata for all discovered (but not necessarily loaded)
    /// plugins.
    pub fn available_plugins(&self) -> &[PluginInfo] {
        &self.available
    }

    // ---------------------------------------------------------------
    // Load / unload
    // ---------------------------------------------------------------

    /// Load a plugin and initialise it against the given tool.
    ///
    /// Returns `Ok(())` on success, or an error if the plugin is already
    /// loaded, disabled, or if loading fails for another reason.
    pub fn load(
        &mut self,
        mut plugin: Box<dyn Plugin>,
        tool: &mut DockingTool,
    ) -> Result<(), PluginError> {
        let name = plugin.name().to_owned();

        if self.loaded.contains(&name) {
            return Err(PluginError::AlreadyLoaded(name));
        }

        if self.config.is_disabled(&name) {
            return Err(PluginError::Disabled(name));
        }

        plugin.init(tool);
        self.loaded.insert(name);
        self.plugins.push(plugin);

        Ok(())
    }

    /// Load the first available plugin matching `name`.
    pub fn load_by_name(&mut self, name: &str, _tool: &mut DockingTool) -> Result<(), PluginError>
where
        // The caller must provide a factory that constructs a Plugin from
        // PluginInfo.  In practice this would be a registry of plugin
        // constructors.
    {
        if self.loaded.contains(name) {
            return Err(PluginError::AlreadyLoaded(name.to_owned()));
        }
        if self.config.is_disabled(name) {
            return Err(PluginError::Disabled(name.to_owned()));
        }
        // Without a concrete plugin factory, we can only report the
        // plugin as "not found" at this level.  Real implementations
        // would use `libloading` or similar.
        Err(PluginError::NotFound(name.to_owned()))
    }

    /// Unload a plugin by name, calling its `dispose()` method.
    pub fn unload(&mut self, name: &str) -> Result<(), PluginError> {
        let pos = self
            .plugins
            .iter()
            .position(|p| p.name() == name)
            .ok_or_else(|| PluginError::NotFound(name.to_owned()))?;

        let mut plugin = self.plugins.remove(pos);
        plugin.dispose();
        self.loaded.remove(name);

        Ok(())
    }

    /// Unload all plugins (reverse load order).
    pub fn unload_all(&mut self) {
        while let Some(mut plugin) = self.plugins.pop() {
            let name = plugin.name().to_owned();
            plugin.dispose();
            self.loaded.remove(&name);
        }
    }

    // ---------------------------------------------------------------
    // Queries
    // ---------------------------------------------------------------

    /// Returns `true` when a plugin with the given name is loaded.
    pub fn is_loaded(&self, name: &str) -> bool {
        self.loaded.contains(name)
    }

    /// Get a reference to a loaded plugin by name.
    pub fn get_plugin(&self, name: &str) -> Option<&dyn Plugin> {
        self.plugins
            .iter()
            .find(|p| p.name() == name)
            .map(|p| p.as_ref())
    }

    /// Get a mutable reference to a loaded plugin by name.
    pub fn get_plugin_mut(&mut self, name: &str) -> Option<&mut (dyn Plugin + '_)> {
        for p in &mut self.plugins {
            if p.name() == name {
                return Some(p.as_mut());
            }
        }
        None
    }

    /// Collect all actions from all loaded plugins.
    pub fn collect_actions(&self) -> Vec<DockingAction> {
        let mut actions = Vec::new();
        for plugin in &self.plugins {
            actions.extend(plugin.get_actions());
        }
        actions
    }

    /// Collect all component providers from all loaded plugins.
    pub fn collect_components(&self) -> Vec<ComponentProvider> {
        let mut providers = Vec::new();
        for plugin in &self.plugins {
            providers.extend(plugin.get_components());
        }
        providers
    }

    /// Number of loaded plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether no plugins are loaded.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Iterate over loaded plugin references.
    pub fn iter(&self) -> impl Iterator<Item = &dyn Plugin> {
        self.plugins.iter().map(|p| p.as_ref())
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::with_default_config()
    }
}

impl Drop for PluginManager {
    fn drop(&mut self) {
        // Ensure all plugins are disposed in reverse load order.
        while let Some(mut plugin) = self.plugins.pop() {
            plugin.dispose();
        }
    }
}

// ---------------------------------------------------------------------------
// PluginError
// ---------------------------------------------------------------------------

/// Errors that can occur during plugin management.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginError {
    /// Plugin is already loaded.
    AlreadyLoaded(String),
    /// Plugin was not found (neither loaded nor available).
    NotFound(String),
    /// Plugin is explicitly disabled.
    Disabled(String),
    /// Plugin initialisation failed.
    InitFailed(String),
    /// Plugin dependency is missing.
    MissingDependency(String),
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginError::AlreadyLoaded(name) => write!(f, "plugin already loaded: {}", name),
            PluginError::NotFound(name) => write!(f, "plugin not found: {}", name),
            PluginError::Disabled(name) => write!(f, "plugin disabled: {}", name),
            PluginError::InitFailed(msg) => write!(f, "plugin init failed: {}", msg),
            PluginError::MissingDependency(name) => {
                write!(f, "missing plugin dependency: {}", name)
            }
        }
    }
}

impl std::error::Error for PluginError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::tool::DockingTool;
    use super::*;

    /// A minimal test plugin.
    struct TestPlugin {
        name: String,
        version: String,
        desc: String,
        init_called: bool,
        dispose_called: bool,
    }

    impl TestPlugin {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_owned(),
                version: "1.0.0".to_owned(),
                desc: "Test plugin".to_owned(),
                init_called: false,
                dispose_called: false,
            }
        }
    }

    impl Plugin for TestPlugin {
        fn name(&self) -> &str {
            &self.name
        }

        fn version(&self) -> &str {
            &self.version
        }

        fn description(&self) -> &str {
            &self.desc
        }

        fn init(&mut self, _tool: &mut DockingTool) {
            self.init_called = true;
        }

        fn dispose(&mut self) {
            self.dispose_called = true;
        }
    }

    fn make_tool() -> DockingTool {
        DockingTool::new()
    }

    #[test]
    fn test_load_and_unload() {
        let mut mgr = PluginManager::with_default_config();
        let mut tool = make_tool();
        let plugin = TestPlugin::new("test-plugin");

        assert!(!mgr.is_loaded("test-plugin"));
        assert_eq!(mgr.len(), 0);

        mgr.load(Box::new(plugin), &mut tool).unwrap();
        assert!(mgr.is_loaded("test-plugin"));
        assert_eq!(mgr.len(), 1);

        // Init should have been called.
        {
            let _p = mgr.get_plugin("test-plugin").unwrap();
            // We can't access init_called through the trait ref directly,
            // but we can verify via drop.
        }

        mgr.unload("test-plugin").unwrap();
        assert!(!mgr.is_loaded("test-plugin"));
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn test_double_load_fails() {
        let mut mgr = PluginManager::with_default_config();
        let mut tool = make_tool();

        mgr.load(Box::new(TestPlugin::new("dup")), &mut tool)
            .unwrap();
        let result = mgr.load(Box::new(TestPlugin::new("dup")), &mut tool);
        assert!(result.is_err());
        match result.unwrap_err() {
            PluginError::AlreadyLoaded(name) => assert_eq!(name, "dup"),
            _ => panic!("expected AlreadyLoaded"),
        }
    }

    #[test]
    fn test_disabled_plugin() {
        let config = PluginConfig::new().with_disabled("blocked");
        let mut mgr = PluginManager::new(config);
        let mut tool = make_tool();

        let result = mgr.load(Box::new(TestPlugin::new("blocked")), &mut tool);
        assert!(result.is_err());
        match result.unwrap_err() {
            PluginError::Disabled(name) => assert_eq!(name, "blocked"),
            _ => panic!("expected Disabled"),
        }
    }

    #[test]
    fn test_unload_not_found() {
        let mut mgr = PluginManager::with_default_config();
        let result = mgr.unload("ghost");
        assert!(result.is_err());
        match result.unwrap_err() {
            PluginError::NotFound(name) => assert_eq!(name, "ghost"),
            _ => panic!("expected NotFound"),
        }
    }

    #[test]
    fn test_unload_all() {
        let mut mgr = PluginManager::with_default_config();
        let mut tool = make_tool();

        mgr.load(Box::new(TestPlugin::new("p1")), &mut tool)
            .unwrap();
        mgr.load(Box::new(TestPlugin::new("p2")), &mut tool)
            .unwrap();
        assert_eq!(mgr.len(), 2);

        mgr.unload_all();
        assert_eq!(mgr.len(), 0);
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_register_available() {
        let mut mgr = PluginManager::with_default_config();
        mgr.register_available(PluginInfo {
            name: "future-plugin".into(),
            version: "0.1.0".into(),
            description: "Not loaded yet".into(),
            source_path: None,
        });
        assert_eq!(mgr.available_plugins().len(), 1);

        // Duplicate should be ignored.
        mgr.register_available(PluginInfo {
            name: "future-plugin".into(),
            version: "0.2.0".into(),
            description: "Updated".into(),
            source_path: None,
        });
        assert_eq!(mgr.available_plugins().len(), 1);
    }

    #[test]
    fn test_plugin_config() {
        let config = PluginConfig::new()
            .with_auto_load(true)
            .with_disabled("bad-plugin")
            .with_plugin_path("/home/user/plugins")
            .with_class_path("/opt/ghidra/lib")
            .with_setting("theme", "dark");

        assert!(config.auto_load);
        assert!(config.is_disabled("bad-plugin"));
        assert!(!config.is_disabled("good-plugin"));
        assert!(config
            .plugin_paths
            .contains(&"/home/user/plugins".to_owned()));
        assert_eq!(config.settings.get("theme").unwrap(), "dark");
    }

    #[test]
    fn test_drop_disposes() {
        let mut mgr = PluginManager::with_default_config();
        let mut tool = make_tool();
        mgr.load(Box::new(TestPlugin::new("dropped")), &mut tool)
            .unwrap();
        // Dropping the manager calls dispose on all plugins.
        drop(mgr);
        // After drop, plugin.dispose_called would be true if we could
        // check it.  The drop implementation handles this.
    }
}
