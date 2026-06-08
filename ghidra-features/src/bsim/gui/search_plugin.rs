//! BSim search plugin: orchestrates similarity search across BSim databases.
//!
//! Ports `ghidra.features.bsim.gui.BSimSearchPlugin` which is the main entry
//! point for BSim search functionality in the Ghidra GUI.
//!
//! The plugin manages:
//! - Server connections (via [`BSimServerManager`])
//! - Search result providers
//! - Overview providers
//! - Task lifecycle for search operations

use std::collections::HashMap;

use super::{BSimSearchSettings, BSimServerInfo};

/// Manager for BSim server connections.
///
/// Ports `ghidra.features.bsim.gui.BSimServerManager`.
/// Maintains a registry of known BSim database servers and their
/// connection state.
#[derive(Debug)]
pub struct BSimServerManager {
    /// Registered servers by name.
    servers: HashMap<String, BSimServerEntry>,
    /// The currently active server (if any).
    active_server: Option<String>,
}

/// Entry for a registered BSim server.
#[derive(Debug, Clone)]
pub struct BSimServerEntry {
    /// Server connection info.
    pub info: BSimServerInfo,
    /// Whether the server is currently connected.
    pub connected: bool,
    /// Database information (loaded on connect).
    pub database_info: Option<BSimDatabaseInfo>,
    /// Last error message (if any).
    pub last_error: Option<String>,
}

/// Summary information about a BSim database.
#[derive(Debug, Clone)]
pub struct BSimDatabaseInfo {
    /// Database name.
    pub name: String,
    /// Number of executables indexed.
    pub executable_count: usize,
    /// Total number of functions indexed.
    pub function_count: usize,
    /// Whether the database tracks call-graph information.
    pub tracks_callgraph: bool,
    /// Available executable categories.
    pub categories: Vec<String>,
    /// Date column name (if customized).
    pub date_column: Option<String>,
    /// Available function tags.
    pub function_tags: Vec<String>,
}

impl BSimServerManager {
    /// Create a new server manager.
    pub fn new() -> Self {
        Self {
            servers: HashMap::new(),
            active_server: None,
        }
    }

    /// Register a server.
    pub fn add_server(&mut self, name: impl Into<String>, info: BSimServerInfo) {
        let name = name.into();
        self.servers.insert(
            name.clone(),
            BSimServerEntry {
                info,
                connected: false,
                database_info: None,
                last_error: None,
            },
        );
        if self.active_server.is_none() {
            self.active_server = Some(name);
        }
    }

    /// Remove a server by name.
    pub fn remove_server(&mut self, name: &str) -> bool {
        let removed = self.servers.remove(name).is_some();
        if self.active_server.as_deref() == Some(name) {
            self.active_server = self.servers.keys().next().cloned();
        }
        removed
    }

    /// Get a server entry by name.
    pub fn get_server(&self, name: &str) -> Option<&BSimServerEntry> {
        self.servers.get(name)
    }

    /// Get all registered server names.
    pub fn server_names(&self) -> Vec<&str> {
        self.servers.keys().map(|s| s.as_str()).collect()
    }

    /// Set the active server.
    pub fn set_active_server(&mut self, name: &str) -> bool {
        if self.servers.contains_key(name) {
            self.active_server = Some(name.to_string());
            true
        } else {
            false
        }
    }

    /// Get the active server name.
    pub fn active_server(&self) -> Option<&str> {
        self.active_server.as_deref()
    }

    /// Get the active server entry.
    pub fn active_server_entry(&self) -> Option<&BSimServerEntry> {
        self.active_server
            .as_ref()
            .and_then(|name| self.servers.get(name))
    }

    /// Get the number of registered servers.
    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Get a mutable reference to a server entry.
    pub fn get_server_mut(&mut self, name: &str) -> Option<&mut BSimServerEntry> {
        self.servers.get_mut(name)
    }
}

impl Default for BSimServerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// A task that can be executed by the BSim search plugin.
///
/// Ports the abstract task lifecycle from `BSimSearchPlugin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BSimTaskState {
    /// No task running.
    Idle,
    /// Connecting to a server.
    Connecting,
    /// Executing a search query.
    Searching,
    /// Applying search results.
    Applying,
    /// Loading overview data.
    LoadingOverview,
    /// Task was cancelled.
    Cancelled,
    /// Task completed successfully.
    Completed,
    /// Task failed with an error.
    Failed,
}

impl Default for BSimTaskState {
    fn default() -> Self {
        Self::Idle
    }
}

/// The BSim search plugin state.
///
/// Ports `ghidra.features.bsim.gui.BSimSearchPlugin`.
/// Manages the lifecycle of search operations and result providers.
#[derive(Debug)]
pub struct BSimSearchPlugin {
    /// Server manager.
    pub server_manager: BSimServerManager,
    /// Current task state.
    task_state: BSimTaskState,
    /// Last used search settings.
    last_settings: BSimSearchSettings,
    /// Registered search result providers.
    result_providers: Vec<String>,
    /// Registered overview providers.
    overview_providers: Vec<String>,
}

impl BSimSearchPlugin {
    /// Create a new search plugin.
    pub fn new() -> Self {
        Self {
            server_manager: BSimServerManager::new(),
            task_state: BSimTaskState::Idle,
            last_settings: BSimSearchSettings::default(),
            result_providers: Vec::new(),
            overview_providers: Vec::new(),
        }
    }

    /// Get the current task state.
    pub fn task_state(&self) -> BSimTaskState {
        self.task_state
    }

    /// Set the task state.
    pub fn set_task_state(&mut self, state: BSimTaskState) {
        self.task_state = state;
    }

    /// Whether a task is currently running.
    pub fn is_busy(&self) -> bool {
        matches!(
            self.task_state,
            BSimTaskState::Connecting
                | BSimTaskState::Searching
                | BSimTaskState::Applying
                | BSimTaskState::LoadingOverview
        )
    }

    /// Get the last used search settings.
    pub fn last_settings(&self) -> &BSimSearchSettings {
        &self.last_settings
    }

    /// Update the last used search settings.
    pub fn set_last_settings(&mut self, settings: BSimSearchSettings) {
        self.last_settings = settings;
    }

    /// Register a search result provider.
    pub fn register_result_provider(&mut self, name: impl Into<String>) {
        self.result_providers.push(name.into());
    }

    /// Register an overview provider.
    pub fn register_overview_provider(&mut self, name: impl Into<String>) {
        self.overview_providers.push(name.into());
    }

    /// Get the number of registered result providers.
    pub fn result_provider_count(&self) -> usize {
        self.result_providers.len()
    }

    /// Get the number of registered overview providers.
    pub fn overview_provider_count(&self) -> usize {
        self.overview_providers.len()
    }
}

impl Default for BSimSearchPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ConnectionType;

    fn sample_server_info() -> BSimServerInfo {
        BSimServerInfo {
            url: "localhost:5432".to_string(),
            database_name: "test_bsim".to_string(),
            connection_type: ConnectionType::PostgreSQL,
            use_ssl: false,
            username: Some("user".to_string()),
        }
    }

    // ---- BSimServerManager tests ----

    #[test]
    fn server_manager_add_and_get() {
        let mut mgr = BSimServerManager::new();
        mgr.add_server("local", sample_server_info());
        assert_eq!(mgr.server_count(), 1);
        assert!(mgr.get_server("local").is_some());
        assert_eq!(mgr.get_server("local").unwrap().info.url, "localhost:5432");
    }

    #[test]
    fn server_manager_active_server() {
        let mut mgr = BSimServerManager::new();
        assert!(mgr.active_server().is_none());

        mgr.add_server("s1", sample_server_info());
        assert_eq!(mgr.active_server(), Some("s1"));

        mgr.add_server("s2", sample_server_info());
        // First added server stays active
        assert_eq!(mgr.active_server(), Some("s1"));

        mgr.set_active_server("s2");
        assert_eq!(mgr.active_server(), Some("s2"));
    }

    #[test]
    fn server_manager_set_active_nonexistent() {
        let mut mgr = BSimServerManager::new();
        assert!(!mgr.set_active_server("nonexistent"));
    }

    #[test]
    fn server_manager_remove() {
        let mut mgr = BSimServerManager::new();
        mgr.add_server("s1", sample_server_info());
        mgr.add_server("s2", sample_server_info());
        mgr.set_active_server("s1");

        assert!(mgr.remove_server("s1"));
        assert_eq!(mgr.server_count(), 1);
        // Active server should switch to s2
        assert_eq!(mgr.active_server(), Some("s2"));
    }

    #[test]
    fn server_manager_remove_nonexistent() {
        let mut mgr = BSimServerManager::new();
        assert!(!mgr.remove_server("ghost"));
    }

    #[test]
    fn server_manager_remove_active_goes_to_next() {
        let mut mgr = BSimServerManager::new();
        mgr.add_server("s1", sample_server_info());
        mgr.set_active_server("s1");
        mgr.remove_server("s1");
        assert!(mgr.active_server().is_none());
    }

    #[test]
    fn server_manager_server_names() {
        let mut mgr = BSimServerManager::new();
        mgr.add_server("alpha", sample_server_info());
        mgr.add_server("beta", sample_server_info());
        let names = mgr.server_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
    }

    #[test]
    fn server_manager_active_entry() {
        let mut mgr = BSimServerManager::new();
        assert!(mgr.active_server_entry().is_none());

        mgr.add_server("local", sample_server_info());
        let entry = mgr.active_server_entry().unwrap();
        assert_eq!(entry.info.database_name, "test_bsim");
        assert!(!entry.connected);
    }

    #[test]
    fn server_entry_mutable() {
        let mut mgr = BSimServerManager::new();
        mgr.add_server("local", sample_server_info());

        let entry = mgr.get_server_mut("local").unwrap();
        entry.connected = true;
        entry.last_error = None;

        assert!(mgr.get_server("local").unwrap().connected);
    }

    // ---- BSimTaskState tests ----

    #[test]
    fn task_state_default() {
        assert_eq!(BSimTaskState::default(), BSimTaskState::Idle);
    }

    // ---- BSimSearchPlugin tests ----

    #[test]
    fn search_plugin_new() {
        let plugin = BSimSearchPlugin::new();
        assert_eq!(plugin.task_state(), BSimTaskState::Idle);
        assert!(!plugin.is_busy());
        assert_eq!(plugin.result_provider_count(), 0);
        assert_eq!(plugin.overview_provider_count(), 0);
    }

    #[test]
    fn search_plugin_busy_states() {
        let mut plugin = BSimSearchPlugin::new();

        plugin.set_task_state(BSimTaskState::Connecting);
        assert!(plugin.is_busy());

        plugin.set_task_state(BSimTaskState::Searching);
        assert!(plugin.is_busy());

        plugin.set_task_state(BSimTaskState::Applying);
        assert!(plugin.is_busy());

        plugin.set_task_state(BSimTaskState::LoadingOverview);
        assert!(plugin.is_busy());

        plugin.set_task_state(BSimTaskState::Completed);
        assert!(!plugin.is_busy());

        plugin.set_task_state(BSimTaskState::Cancelled);
        assert!(!plugin.is_busy());

        plugin.set_task_state(BSimTaskState::Failed);
        assert!(!plugin.is_busy());
    }

    #[test]
    fn search_plugin_settings() {
        let mut plugin = BSimSearchPlugin::new();
        let settings = BSimSearchSettings::with_similarity(0.95).with_max_results(10);
        plugin.set_last_settings(settings);
        assert!((plugin.last_settings().min_similarity - 0.95).abs() < 1e-6);
        assert_eq!(plugin.last_settings().max_results, 10);
    }

    #[test]
    fn search_plugin_register_providers() {
        let mut plugin = BSimSearchPlugin::new();
        plugin.register_result_provider("Provider1");
        plugin.register_result_provider("Provider2");
        plugin.register_overview_provider("Overview1");

        assert_eq!(plugin.result_provider_count(), 2);
        assert_eq!(plugin.overview_provider_count(), 1);
    }

    #[test]
    fn search_plugin_server_manager() {
        let mut plugin = BSimSearchPlugin::new();
        plugin
            .server_manager
            .add_server("main", sample_server_info());
        assert_eq!(plugin.server_manager.server_count(), 1);
    }

    // ---- BSimDatabaseInfo tests ----

    #[test]
    fn database_info_fields() {
        let info = BSimDatabaseInfo {
            name: "mydb".to_string(),
            executable_count: 100,
            function_count: 50000,
            tracks_callgraph: true,
            categories: vec!["firmware".to_string(), "malware".to_string()],
            date_column: Some("build_date".to_string()),
            function_tags: vec!["KNOWN_LIBRARY".to_string()],
        };
        assert_eq!(info.name, "mydb");
        assert_eq!(info.executable_count, 100);
        assert_eq!(info.function_count, 50000);
        assert!(info.tracks_callgraph);
        assert_eq!(info.categories.len(), 2);
        assert_eq!(info.date_column, Some("build_date".to_string()));
        assert_eq!(info.function_tags.len(), 1);
    }
}
