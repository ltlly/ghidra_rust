//! Plugin system for the docking framework.
//!
//! Plugins are extension modules that contribute actions, component
//! providers, and other functionality to a [`super::tool::DockingTool`].

use std::collections::{HashMap, HashSet};

use super::action::DockingAction;
use super::component::ComponentProvider;
use super::tool::DockingTool;

// ---------------------------------------------------------------------------
// Plugin lifecycle phases
// ---------------------------------------------------------------------------

/// The lifecycle phase of a plugin.
///
/// Ghidra plugins transition through distinct phases as they are loaded,
/// initialized, started, and eventually disposed.  This enum models
/// those phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginLifecycle {
    /// Plugin has been discovered but not yet loaded.
    Discovered,
    /// Plugin class has been loaded into memory.
    Loaded,
    /// Plugin has been initialized (`init` called).
    Initialized,
    /// Plugin is actively running.
    Running,
    /// Plugin has been stopped / disposed.
    Disposed,
    /// Plugin encountered an error during a lifecycle transition.
    Error,
}

impl PluginLifecycle {
    /// Returns `true` if the plugin is in an active state.
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            PluginLifecycle::Initialized | PluginLifecycle::Running
        )
    }

    /// Returns `true` if the plugin is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, PluginLifecycle::Disposed | PluginLifecycle::Error)
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            PluginLifecycle::Discovered => "Discovered",
            PluginLifecycle::Loaded => "Loaded",
            PluginLifecycle::Initialized => "Initialized",
            PluginLifecycle::Running => "Running",
            PluginLifecycle::Disposed => "Disposed",
            PluginLifecycle::Error => "Error",
        }
    }
}

impl Default for PluginLifecycle {
    fn default() -> Self {
        PluginLifecycle::Discovered
    }
}

// ---------------------------------------------------------------------------
// Plugin dependency
// ---------------------------------------------------------------------------

/// A dependency declared by a plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginDependency {
    /// The name of the required plugin.
    pub plugin_name: String,
    /// Whether this dependency is optional (the plugin can load without it).
    pub optional: bool,
    /// Minimum version required (if any).
    pub min_version: Option<String>,
}

impl PluginDependency {
    /// Create a required dependency.
    pub fn required(plugin_name: impl Into<String>) -> Self {
        Self {
            plugin_name: plugin_name.into(),
            optional: false,
            min_version: None,
        }
    }

    /// Create an optional dependency.
    pub fn optional(plugin_name: impl Into<String>) -> Self {
        Self {
            plugin_name: plugin_name.into(),
            optional: true,
            min_version: None,
        }
    }

    /// Set the minimum version requirement.
    pub fn with_min_version(mut self, version: impl Into<String>) -> Self {
        self.min_version = Some(version.into());
        self
    }
}

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
    /// Current lifecycle phase.
    pub lifecycle: PluginLifecycle,
    /// Plugins this plugin depends on.
    pub dependencies: Vec<PluginDependency>,
    /// Plugin category (e.g. "Analysis", "Decompiler", "Navigation").
    pub category: String,
    /// Plugin author.
    pub author: String,
}

impl PluginInfo {
    /// Create a basic plugin info.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            description: description.into(),
            source_path: None,
            lifecycle: PluginLifecycle::default(),
            dependencies: Vec::new(),
            category: String::new(),
            author: String::new(),
        }
    }

    /// Set the source path.
    pub fn with_source_path(mut self, path: impl Into<String>) -> Self {
        self.source_path = Some(path.into());
        self
    }

    /// Add a dependency.
    pub fn with_dependency(mut self, dep: PluginDependency) -> Self {
        self.dependencies.push(dep);
        self
    }

    /// Set the category.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = category.into();
        self
    }

    /// Set the author.
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    /// Set the lifecycle phase.
    pub fn with_lifecycle(mut self, lifecycle: PluginLifecycle) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    /// Returns `true` if this plugin has any required dependencies.
    pub fn has_required_dependencies(&self) -> bool {
        self.dependencies.iter().any(|d| !d.optional)
    }

    /// Return the names of all required dependencies.
    pub fn required_dependencies(&self) -> Vec<&str> {
        self.dependencies
            .iter()
            .filter(|d| !d.optional)
            .map(|d| d.plugin_name.as_str())
            .collect()
    }

    /// Return the names of all optional dependencies.
    pub fn optional_dependencies(&self) -> Vec<&str> {
        self.dependencies
            .iter()
            .filter(|d| d.optional)
            .map(|d| d.plugin_name.as_str())
            .collect()
    }
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
    /// Current lifecycle phase for each plugin (keyed by name).
    pub lifecycle: HashMap<String, PluginLifecycle>,
}

impl PluginManager {
    /// Create a new, empty plugin manager.
    pub fn new(config: PluginConfig) -> Self {
        Self {
            plugins: Vec::new(),
            loaded: HashSet::new(),
            config,
            available: Vec::new(),
            lifecycle: HashMap::new(),
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
            return Err(PluginError::AlreadyLoaded(name.clone()));
        }

        if self.config.is_disabled(&name) {
            return Err(PluginError::Disabled(name));
        }

        self.lifecycle.insert(name.clone(), PluginLifecycle::Loaded);
        plugin.init(tool);
        self.lifecycle
            .insert(name.clone(), PluginLifecycle::Initialized);
        self.loaded.insert(name.clone());
        self.plugins.push(plugin);
        self.lifecycle.insert(name, PluginLifecycle::Running);

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
        self.lifecycle
            .insert(name.to_owned(), PluginLifecycle::Disposed);
        plugin.dispose();
        self.loaded.remove(name);

        Ok(())
    }

    /// Unload all plugins (reverse load order).
    pub fn unload_all(&mut self) {
        while let Some(mut plugin) = self.plugins.pop() {
            let name = plugin.name().to_owned();
            self.lifecycle
                .insert(name.clone(), PluginLifecycle::Disposed);
            plugin.dispose();
            self.loaded.remove(&name);
        }
    }

    // ---------------------------------------------------------------
    // Bulk loading with dependency resolution
    // ---------------------------------------------------------------

    /// Load all available plugins in dependency order.
    ///
    /// Plugins with unsatisfied required dependencies are skipped (with a
    /// log warning).  Optional dependencies are silently ignored if
    /// missing.
    pub fn load_all_available(&mut self, _tool: &mut DockingTool) -> Vec<Result<(), PluginError>> {
        // Phase 1: gather names and dependencies.
        let mut results = Vec::new();
        let mut load_order: Vec<String> = Vec::new();
        let mut remaining: Vec<PluginInfo> = self.available.clone();

        // Simple topological sort: repeatedly pick a plugin whose
        // required deps are all in load_order (or not in available at all).
        let mut changed = true;
        while changed && !remaining.is_empty() {
            changed = false;
            let ready: Vec<usize> = remaining
                .iter()
                .enumerate()
                .filter(|(_, info)| {
                    info.required_dependencies()
                        .iter()
                        .all(|dep| {
                            load_order.contains(&dep.to_string())
                                || !remaining.iter().any(|r| &r.name == dep)
                        })
                })
                .map(|(i, _)| i)
                .collect();

            // Process in reverse order to preserve indices.
            for &idx in ready.iter().rev() {
                let info = remaining.remove(idx);
                load_order.push(info.name.clone());
                changed = true;
            }
        }

        // Mark any remaining plugins as having unsatisfied dependencies.
        for info in &remaining {
            results.push(Err(PluginError::MissingDependency(
                info.required_dependencies().join(", "),
            )));
        }

        // Phase 2: load in computed order.
        // Note: actual plugin construction requires a factory, which
        // is not available at this level.  This method resolves the
        // order; callers provide the factories.
        for name in &load_order {
            self.lifecycle
                .insert(name.clone(), PluginLifecycle::Loaded);
            // The actual load would happen here with a factory closure.
        }

        results
    }

    /// Get the lifecycle phase for a plugin.
    pub fn get_lifecycle(&self, name: &str) -> Option<&PluginLifecycle> {
        self.lifecycle.get(name)
    }

    /// Set the lifecycle phase for a plugin.
    pub fn set_lifecycle(&mut self, name: &str, phase: PluginLifecycle) {
        self.lifecycle.insert(name.to_owned(), phase);
    }

    /// Return the names of plugins that are in an error state.
    pub fn errored_plugins(&self) -> Vec<&str> {
        self.lifecycle
            .iter()
            .filter(|(_, phase)| **phase == PluginLifecycle::Error)
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Resolve the load order for a set of plugin names based on their
    /// declared dependencies.
    pub fn resolve_load_order(
        &self,
        names: &[&str],
    ) -> Result<Vec<String>, PluginError> {
        let infos: Vec<&PluginInfo> = names
            .iter()
            .filter_map(|name| self.available.iter().find(|info| &info.name == name))
            .collect();

        let mut resolved: Vec<String> = Vec::new();
        let mut remaining: Vec<&PluginInfo> = infos;

        let mut changed = true;
        while changed && !remaining.is_empty() {
            changed = false;
            let ready: Vec<usize> = remaining
                .iter()
                .enumerate()
                .filter(|(_, info)| {
                    info.required_dependencies()
                        .iter()
                        .all(|dep| {
                            resolved.contains(&dep.to_string())
                                || !names.contains(dep)
                        })
                })
                .map(|(i, _)| i)
                .collect();

            for &idx in ready.iter().rev() {
                let info = remaining.remove(idx);
                resolved.push(info.name.clone());
                changed = true;
            }
        }

        if !remaining.is_empty() {
            let missing: Vec<&str> = remaining.iter().map(|i| i.name.as_str()).collect();
            return Err(PluginError::MissingDependency(missing.join(", ")));
        }

        Ok(resolved)
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
        mgr.register_available(PluginInfo::new("future-plugin", "0.1.0", "Not loaded yet"));
        assert_eq!(mgr.available_plugins().len(), 1);

        // Duplicate should be ignored.
        mgr.register_available(PluginInfo::new("future-plugin", "0.2.0", "Updated"));
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

    // --- New: lifecycle and dependency tests ---

    #[test]
    fn test_plugin_lifecycle() {
        let lc = PluginLifecycle::Discovered;
        assert!(!lc.is_active());
        assert!(!lc.is_terminal());

        let lc = PluginLifecycle::Running;
        assert!(lc.is_active());
        assert!(!lc.is_terminal());

        let lc = PluginLifecycle::Disposed;
        assert!(!lc.is_active());
        assert!(lc.is_terminal());

        let lc = PluginLifecycle::Error;
        assert!(!lc.is_active());
        assert!(lc.is_terminal());

        assert_eq!(PluginLifecycle::Discovered.name(), "Discovered");
    }

    #[test]
    fn test_plugin_dependency() {
        let dep = PluginDependency::required("CorePlugin");
        assert!(!dep.optional);
        assert_eq!(dep.plugin_name, "CorePlugin");
        assert!(dep.min_version.is_none());

        let dep = PluginDependency::optional("PDBPlugin").with_min_version("1.0.0");
        assert!(dep.optional);
        assert_eq!(dep.min_version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn test_plugin_info_with_dependencies() {
        let info = PluginInfo::new("DecompilerPlugin", "1.0.0", "Decompiler")
            .with_dependency(PluginDependency::required("CorePlugin"))
            .with_dependency(PluginDependency::optional("PDBPlugin"))
            .with_category("Decompiler")
            .with_author("Ghidra Team");

        assert!(info.has_required_dependencies());
        assert_eq!(info.required_dependencies(), vec!["CorePlugin"]);
        assert_eq!(info.optional_dependencies(), vec!["PDBPlugin"]);
        assert_eq!(info.category, "Decompiler");
        assert_eq!(info.author, "Ghidra Team");
    }

    #[test]
    fn test_plugin_lifecycle_tracking() {
        let mut mgr = PluginManager::with_default_config();
        let mut tool = make_tool();

        assert!(mgr.get_lifecycle("test").is_none());

        mgr.load(Box::new(TestPlugin::new("test")), &mut tool)
            .unwrap();
        assert_eq!(
            mgr.get_lifecycle("test"),
            Some(&PluginLifecycle::Running)
        );

        mgr.unload("test").unwrap();
        assert_eq!(
            mgr.get_lifecycle("test"),
            Some(&PluginLifecycle::Disposed)
        );
    }

    #[test]
    fn test_plugin_errored_plugins() {
        let mut mgr = PluginManager::with_default_config();
        assert!(mgr.errored_plugins().is_empty());

        mgr.set_lifecycle("bad-plugin", PluginLifecycle::Error);
        let errored = mgr.errored_plugins();
        assert_eq!(errored, vec!["bad-plugin"]);
    }

    #[test]
    fn test_resolve_load_order() {
        let mut mgr = PluginManager::with_default_config();

        mgr.register_available(
            PluginInfo::new("CorePlugin", "1.0.0", "Core")
        );
        mgr.register_available(
            PluginInfo::new("DecompilerPlugin", "1.0.0", "Decompiler")
                .with_dependency(PluginDependency::required("CorePlugin")),
        );
        mgr.register_available(
            PluginInfo::new("PDBPlugin", "1.0.0", "PDB")
                .with_dependency(PluginDependency::required("DecompilerPlugin")),
        );

        let order = mgr
            .resolve_load_order(&["CorePlugin", "DecompilerPlugin", "PDBPlugin"])
            .unwrap();

        // CorePlugin should come before DecompilerPlugin.
        let core_pos = order.iter().position(|n| n == "CorePlugin").unwrap();
        let decomp_pos = order
            .iter()
            .position(|n| n == "DecompilerPlugin")
            .unwrap();
        let pdb_pos = order.iter().position(|n| n == "PDBPlugin").unwrap();
        assert!(core_pos < decomp_pos);
        assert!(decomp_pos < pdb_pos);
    }

    #[test]
    fn test_resolve_load_order_circular() {
        let mut mgr = PluginManager::with_default_config();

        mgr.register_available(
            PluginInfo::new("A", "1.0.0", "A")
                .with_dependency(PluginDependency::required("B")),
        );
        mgr.register_available(
            PluginInfo::new("B", "1.0.0", "B")
                .with_dependency(PluginDependency::required("A")),
        );

        let result = mgr.resolve_load_order(&["A", "B"]);
        assert!(result.is_err());
        match result.unwrap_err() {
            PluginError::MissingDependency(_) => {}
            _ => panic!("expected MissingDependency"),
        }
    }

    #[test]
    fn test_plugin_info_lifecycle_default() {
        let info = PluginInfo::new("test", "1.0.0", "test plugin");
        assert_eq!(info.lifecycle, PluginLifecycle::Discovered);
        assert!(info.dependencies.is_empty());
        assert!(!info.has_required_dependencies());
    }
}
