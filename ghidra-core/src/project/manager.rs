//! Project lifecycle management.
//!
//! Provides the [`ProjectManager`] trait for creating, opening, closing, and
//! deleting Ghidra projects. Also includes stub types for repository adapters,
//! tool management, and server information which are referenced by the project
//! interfaces.
//!
//! Corresponds to `ghidra.framework.model.ProjectManager` and related types.

use std::collections::HashMap;

use crate::error::GhidraError;

use super::{Project, ProjectLocator, ProjectResult};

// ============================================================================
// Stub types for external Ghidra concepts
// ============================================================================

/// A tool chest containing user tool configurations.
///
/// Corresponds to `ghidra.framework.model.ToolChest`.
pub trait ToolChest: Send + Sync {
    /// The name of this tool chest.
    fn name(&self) -> &str;
    /// List all tool templates in this chest.
    fn tool_names(&self) -> Vec<String>;
}

/// A tool template stored in a project.
///
/// Corresponds to `ghidra.framework.model.ToolTemplate`.
pub trait ToolTemplate: Send + Sync {
    /// The name/tag of this template.
    fn name(&self) -> &str;
    /// A description of this tool template.
    fn description(&self) -> &str;
}

/// Service for tool-related operations within a project.
///
/// Corresponds to `ghidra.framework.model.ToolServices`.
pub trait ToolServices: Send + Sync {
    /// Display a tool by name.
    fn display_tool(&self, name: &str) -> ProjectResult<()>;
    /// Close a tool by name.
    fn close_tool(&self, name: &str) -> ProjectResult<()>;
}

/// Lifecycle management for tools within a project.
///
/// Corresponds to `ghidra.framework.model.ToolManager`.
pub trait ToolManager: Send + Sync {
    /// The tool services for this manager.
    fn tool_services(&self) -> &dyn ToolServices;
    /// List running tool names.
    fn running_tools(&self) -> Vec<String>;
    /// Save all tool configurations.
    fn save_tools(&self) -> ProjectResult<()>;
}

/// Repository adapter providing shared project repository access.
///
/// Corresponds to `ghidra.framework.client.RepositoryAdapter`.
pub trait RepositoryAdapter: Send + Sync {
    /// The repository name.
    fn name(&self) -> &str;
    /// The server info for the repository.
    fn server_info(&self) -> &ServerInfo;
    /// Returns `true` when connected to the repository server.
    fn is_connected(&self) -> bool;
    /// Connect to the repository server.
    fn connect(&self) -> ProjectResult<()>;
    /// Disconnect from the repository server.
    fn disconnect(&self);
}

/// Server connection information.
///
/// Corresponds to `ghidra.framework.client.RepositoryServerAdapter`.
pub trait RepositoryServerAdapter: Send + Sync {
    /// The hostname or IP address.
    fn host(&self) -> &str;
    /// The port number.
    fn port(&self) -> u16;
    /// Returns `true` when connected.
    fn is_connected(&self) -> bool;
    /// Connect to the server.
    fn connect(&self) -> ProjectResult<()>;
    /// Disconnect from the server.
    fn disconnect(&self);
    /// List available repositories on the server.
    fn list_repositories(&self) -> ProjectResult<Vec<String>>;
}

/// Information about a repository server.
///
/// Corresponds to `ghidra.framework.model.ServerInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// The server hostname.
    pub host: String,
    /// The server port.
    pub port: u16,
    /// Additional metadata.
    pub properties: HashMap<String, String>,
}

impl ServerInfo {
    /// Create a new `ServerInfo`.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            properties: HashMap::new(),
        }
    }

    /// Returns `true` when this has a valid host and port.
    pub fn is_valid(&self) -> bool {
        !self.host.is_empty() && self.port > 0
    }
}

/// Listener notified when a visible project view is added or removed.
///
/// Corresponds to `ghidra.framework.model.ProjectViewListener`.
pub trait ProjectViewListener: Send + Sync {
    /// Called when a project view is added.
    fn view_added(&self, project_locator: &ProjectLocator);
    /// Called when a project view is removed.
    fn view_removed(&self, project_locator: &ProjectLocator);
}

/// Container for saveable/restorable user data.
///
/// Corresponds to `ghidra.framework.options.SaveState`.
#[derive(Debug, Clone, Default)]
pub struct SaveState {
    data: HashMap<String, String>,
}

impl SaveState {
    /// Create an empty `SaveState`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Put a string value.
    pub fn put_string(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.data.insert(key.into(), value.into());
    }

    /// Get a string value.
    pub fn get_string(&self, key: &str, default: &str) -> String {
        self.data
            .get(key)
            .cloned()
            .unwrap_or_else(|| default.to_string())
    }

    /// Put a boolean value.
    pub fn put_boolean(&mut self, key: impl Into<String>, value: bool) {
        self.data.insert(key.into(), value.to_string());
    }

    /// Get a boolean value.
    pub fn get_boolean(&self, key: &str, default: bool) -> bool {
        self.data
            .get(key)
            .map(|s| s.parse().unwrap_or(default))
            .unwrap_or(default)
    }

    /// Put an integer value.
    pub fn put_int(&mut self, key: impl Into<String>, value: i32) {
        self.data.insert(key.into(), value.to_string());
    }

    /// Get an integer value.
    pub fn get_int(&self, key: &str, default: i32) -> i32 {
        self.data
            .get(key)
            .and_then(|s| s.parse().ok())
            .unwrap_or(default)
    }

    /// Returns `true` when this `SaveState` is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// All keys in this `SaveState`.
    pub fn keys(&self) -> Vec<&String> {
        self.data.keys().collect()
    }
}

// ============================================================================
// ProjectManager trait
// ============================================================================

/// Manages the lifecycle of Ghidra projects: creation, opening, deletion,
/// and tracking of recently opened/viewed projects.
///
/// A single [`ProjectManager`] instance is typically associated with the
/// Ghidra application and maintains the currently active project.
///
/// Corresponds to `ghidra.framework.model.ProjectManager`.
pub trait ProjectManager: Send + Sync {
    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------

    /// Default extension for application tool files.
    const APPLICATION_TOOL_EXTENSION: &'static str = ".tcd";
    /// Directory name for tool storage within a project.
    const APPLICATION_TOOLS_DIR_NAME: &'static str = "tools";

    // ------------------------------------------------------------------
    // Project lifecycle
    // ------------------------------------------------------------------

    /// Create a new project on the local filesystem.
    ///
    /// * `project_locator` -- location for the new project.
    /// * `rep_adapter` -- optional repository adapter for shared projects.
    /// * `remember` -- if `false` the project should not be remembered
    ///   in the recently-opened list.
    ///
    /// Returns the newly created [`Project`].
    fn create_project(
        &self,
        project_locator: &ProjectLocator,
        rep_adapter: Option<&dyn RepositoryAdapter>,
        remember: bool,
    ) -> ProjectResult<Box<dyn Project>>;

    /// Open a project from the filesystem and add it to the list of known
    /// projects.
    ///
    /// * `project_locator` -- location of the project to open.
    /// * `do_restore` -- if `true`, restore the project state.
    /// * `reset_owner` -- if `true`, change the project owner to the current user.
    ///
    /// Returns the opened [`Project`].
    fn open_project(
        &self,
        project_locator: &ProjectLocator,
        do_restore: bool,
        reset_owner: bool,
    ) -> ProjectResult<Box<dyn Project>>;

    /// Delete the project at the given location.
    ///
    /// Returns `true` if a project was deleted, `false` if none existed.
    fn delete_project(&self, project_locator: &ProjectLocator) -> bool;

    /// Returns `true` when a project exists at the given location.
    fn project_exists(&self, project_locator: &ProjectLocator) -> bool;

    // ------------------------------------------------------------------
    // Active project
    // ------------------------------------------------------------------

    /// The currently active/open project, or `None` if no project is open.
    fn active_project(&self) -> Option<&dyn Project>;

    /// The [`ProjectLocator`] of the last project opened by the user.
    ///
    /// Returns `None` if a project was never opened or the last project
    /// is no longer valid.
    fn last_opened_project(&self) -> Option<&ProjectLocator>;

    /// Set the last opened project locator.
    ///
    /// Pass `None` to signal that the user closed the project.
    fn set_last_opened_project(&self, project_locator: Option<&ProjectLocator>);

    // ------------------------------------------------------------------
    // Recent projects tracking
    // ------------------------------------------------------------------

    /// The list of projects the user most recently opened.
    fn recent_projects(&self) -> Vec<ProjectLocator>;

    /// The list of projects the user most recently viewed.
    fn recent_viewed_projects(&self) -> Vec<String>;

    /// Add a project locator to the list of known projects.
    fn remember_project(&self, project_locator: &ProjectLocator);

    /// Add a project URL to the list of known viewed projects.
    fn remember_viewed_project(&self, url: &str);

    /// Remove a project URL from the list of known viewed projects.
    fn forget_viewed_project(&self, url: &str);

    // ------------------------------------------------------------------
    // Repository access
    // ------------------------------------------------------------------

    /// Establish a connection to a Ghidra server and return a handle to
    /// the remote server containing shared repositories.
    ///
    /// * `host` -- server name or IP address.
    /// * `port` -- server port, or `0` for default.
    /// * `force_connect` -- if `true` and currently not connected, attempt
    ///   to connect.
    fn get_repository_server(
        &self,
        host: &str,
        port: u16,
        force_connect: bool,
    ) -> ProjectResult<Box<dyn RepositoryServerAdapter>>;

    /// Information about the most recently used repository server.
    fn most_recent_server_info(&self) -> Option<ServerInfo>;

    // ------------------------------------------------------------------
    // Tool chest
    // ------------------------------------------------------------------

    /// The user's [`ToolChest`].
    fn user_tool_chest(&self) -> &dyn ToolChest;
}

// ============================================================================
// SimpleProjectManager -- a basic implementation of ProjectManager
// ============================================================================

/// A basic in-memory implementation of [`ProjectManager`].
///
/// This is suitable for testing and scenarios where a full filesystem-backed
/// project manager is not required.
#[derive(Default)]
pub struct SimpleProjectManager {
    /// All known projects (open and closed).
    projects: Vec<Box<dyn Project>>,
    /// Index of the active project.
    active_index: Option<usize>,
    /// Recent project locators.
    recent: Vec<ProjectLocator>,
    /// Recent viewed project URLs.
    recent_viewed: Vec<String>,
    /// Last opened project locator.
    last_opened: Option<ProjectLocator>,
    /// Most recent server info.
    recent_server: Option<ServerInfo>,
    /// User tool chest.
    tool_chest: Option<Box<dyn ToolChest>>,
}

impl SimpleProjectManager {
    /// Create an empty `SimpleProjectManager`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a project in the project list.
    pub fn register_project(&mut self, project: Box<dyn Project>) {
        self.projects.push(project);
    }

    /// Set the user tool chest.
    pub fn set_tool_chest(&mut self, chest: Box<dyn ToolChest>) {
        self.tool_chest = Some(chest);
    }

    /// Set the most recent server info.
    pub fn set_recent_server(&mut self, info: ServerInfo) {
        self.recent_server = Some(info);
    }
}

impl ProjectManager for SimpleProjectManager {
    fn create_project(
        &self,
        _project_locator: &ProjectLocator,
        _rep_adapter: Option<&dyn RepositoryAdapter>,
        _remember: bool,
    ) -> ProjectResult<Box<dyn Project>> {
        Err(GhidraError::NotSupported(
            "SimpleProjectManager::create_project: use a full implementation".into(),
        ))
    }

    fn open_project(
        &self,
        _project_locator: &ProjectLocator,
        _do_restore: bool,
        _reset_owner: bool,
    ) -> ProjectResult<Box<dyn Project>> {
        Err(GhidraError::NotSupported(
            "SimpleProjectManager::open_project: use a full implementation".into(),
        ))
    }

    fn delete_project(&self, _project_locator: &ProjectLocator) -> bool {
        false
    }

    fn project_exists(&self, project_locator: &ProjectLocator) -> bool {
        project_locator.exists()
    }

    fn active_project(&self) -> Option<&dyn Project> {
        self.active_index
            .and_then(|i| self.projects.get(i))
            .map(|p| p.as_ref())
    }

    fn last_opened_project(&self) -> Option<&ProjectLocator> {
        self.last_opened.as_ref()
    }

    fn set_last_opened_project(&self, _project_locator: Option<&ProjectLocator>) {
        // In a real implementation this would persist to user settings.
    }

    fn recent_projects(&self) -> Vec<ProjectLocator> {
        self.recent.clone()
    }

    fn recent_viewed_projects(&self) -> Vec<String> {
        self.recent_viewed.clone()
    }

    fn remember_project(&self, _project_locator: &ProjectLocator) {
        // In a real implementation this would persist and deduplicate.
    }

    fn remember_viewed_project(&self, _url: &str) {
        // In a real implementation this would persist and deduplicate.
    }

    fn forget_viewed_project(&self, _url: &str) {
        // In a real implementation this would persist and remove.
    }

    fn get_repository_server(
        &self,
        _host: &str,
        _port: u16,
        _force_connect: bool,
    ) -> ProjectResult<Box<dyn RepositoryServerAdapter>> {
        Err(GhidraError::NotSupported(
            "SimpleProjectManager: repository server not supported".into(),
        ))
    }

    fn most_recent_server_info(&self) -> Option<ServerInfo> {
        self.recent_server.clone()
    }

    fn user_tool_chest(&self) -> &dyn ToolChest {
        // Return a no-op default if none set
        struct DefaultToolChest;
        impl ToolChest for DefaultToolChest {
            fn name(&self) -> &str {
                "Default"
            }
            fn tool_names(&self) -> Vec<String> {
                Vec::new()
            }
        }
        static DEFAULT: std::sync::LazyLock<DefaultToolChest> =
            std::sync::LazyLock::new(|| DefaultToolChest);
        self.tool_chest.as_deref().unwrap_or(&*DEFAULT)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_info() {
        let info = ServerInfo::new("localhost", 13100);
        assert_eq!(info.host, "localhost");
        assert_eq!(info.port, 13100);
        assert!(info.is_valid());

        let invalid = ServerInfo::new("", 0);
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_save_state() {
        let mut state = SaveState::new();
        assert!(state.is_empty());

        state.put_string("key1", "value1");
        state.put_boolean("flag", true);
        state.put_int("count", 42);

        assert!(!state.is_empty());
        assert_eq!(state.get_string("key1", ""), "value1");
        assert!(state.get_boolean("flag", false));
        assert_eq!(state.get_int("count", 0), 42);
        assert_eq!(state.get_string("missing", "default"), "default");
        assert!(!state.get_boolean("missing", false));
    }

    #[test]
    fn test_simple_project_manager_default() {
        let mgr = SimpleProjectManager::new();
        assert!(mgr.active_project().is_none());
        assert!(mgr.last_opened_project().is_none());
        assert!(mgr.recent_projects().is_empty());
        assert!(mgr.most_recent_server_info().is_none());
    }

    #[test]
    fn test_simple_project_manager_project_exists() {
        let mgr = SimpleProjectManager::new();
        let loc = ProjectLocator::new("/nonexistent/path", "NoProject").unwrap();
        assert!(!mgr.project_exists(&loc));
    }

    #[test]
    fn test_simple_project_manager_with_server() {
        let mut mgr = SimpleProjectManager::new();
        let info = ServerInfo::new("ghidra.example.com", 13100);
        mgr.set_recent_server(info);

        let server = mgr.most_recent_server_info().unwrap();
        assert_eq!(server.host, "ghidra.example.com");
        assert_eq!(server.port, 13100);
    }
}
