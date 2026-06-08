//! Default project manager implementation.
//!
//! Ports `ghidra.framework.data.DefaultProjectManager` from Java.
//! Provides a full-featured [`ProjectManager`] implementation that manages
//! project lifecycle on disk, tracks recent projects, and handles project
//! discovery.

use std::collections::VecDeque;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use super::default_project::DefaultProject;
use super::manager::*;
use super::{ProjectError, ProjectLocator, ProjectResult};

// ============================================================================
// DefaultProjectManager
// ============================================================================

/// Full-featured project manager backed by the filesystem.
///
/// In Java: `ghidra.framework.data.DefaultProjectManager`.
///
/// Manages creation, opening, and deletion of projects.  Maintains a list
/// of recently opened projects and the currently active project.
pub struct DefaultProjectManager {
    /// The default project directory.
    project_directory: PathBuf,
    /// Currently active project, if any.
    active_project: RwLock<Option<DefaultProject>>,
    /// Recently opened project locators (most recent first).
    recent_projects: RwLock<VecDeque<ProjectLocator>>,
    /// Recently viewed project URLs.
    recent_viewed: RwLock<VecDeque<String>>,
    /// Last opened project locator.
    last_opened: RwLock<Option<ProjectLocator>>,
    /// Most recent server info.
    recent_server: RwLock<Option<ServerInfo>>,
    /// Maximum number of recent projects to track.
    max_recent: usize,
    /// Maximum number of recent viewed projects to track.
    max_recent_viewed: usize,
    /// Known project locators cache.
    known_projects: RwLock<Vec<ProjectLocator>>,
}

impl DefaultProjectManager {
    /// Create a new project manager with the given default project directory.
    pub fn new(project_directory: impl Into<PathBuf>) -> Self {
        Self {
            project_directory: project_directory.into(),
            active_project: RwLock::new(None),
            recent_projects: RwLock::new(VecDeque::new()),
            recent_viewed: RwLock::new(VecDeque::new()),
            last_opened: RwLock::new(None),
            recent_server: RwLock::new(None),
            max_recent: 20,
            max_recent_viewed: 20,
            known_projects: RwLock::new(Vec::new()),
        }
    }

    /// Create a new project manager using the platform default directory.
    pub fn with_default_directory() -> Self {
        Self::new(Self::default_project_directory())
    }

    /// The default project directory for the current platform.
    pub fn default_project_directory() -> PathBuf {
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join("ghidra_projects")
        } else if let Ok(profile) = std::env::var("USERPROFILE") {
            PathBuf::from(profile).join("ghidra_projects")
        } else {
            PathBuf::from(".")
        }
    }

    /// Get the default project directory.
    pub fn get_project_directory(&self) -> &Path {
        &self.project_directory
    }

    /// Set the default project directory.
    pub fn set_project_directory(&mut self, dir: impl Into<PathBuf>) {
        self.project_directory = dir.into();
    }

    /// Add a project locator to the recent list.
    fn add_recent(&self, locator: ProjectLocator) {
        let mut recent = self.recent_projects.write().unwrap();
        recent.retain(|l| l != &locator);
        recent.push_front(locator);
        while recent.len() > self.max_recent {
            recent.pop_back();
        }
    }

    /// Add a URL to the recently viewed list.
    fn add_recent_viewed(&self, url: &str) {
        let mut viewed = self.recent_viewed.write().unwrap();
        viewed.retain(|u| u != url);
        viewed.push_front(url.to_string());
        while viewed.len() > self.max_recent_viewed {
            viewed.pop_back();
        }
    }

    /// Scan the project directory for known projects.
    pub fn discover_projects(&self) -> ProjectResult<Vec<ProjectLocator>> {
        let locators = ProjectLocator::find_projects(&self.project_directory);
        let mut known = self.known_projects.write().unwrap();
        *known = locators.clone();
        Ok(locators)
    }

    /// Whether there is an active project.
    pub fn has_active_project(&self) -> bool {
        self.active_project.read().unwrap().is_some()
    }

    /// Set the maximum number of recent projects to track.
    pub fn set_max_recent(&mut self, max: usize) {
        self.max_recent = max.max(1);
        let mut recent = self.recent_projects.write().unwrap();
        while recent.len() > self.max_recent {
            recent.pop_back();
        }
    }

    /// Set the maximum number of recently viewed projects to track.
    pub fn set_max_recent_viewed(&mut self, max: usize) {
        self.max_recent_viewed = max.max(1);
        let mut viewed = self.recent_viewed.write().unwrap();
        while viewed.len() > self.max_recent_viewed {
            viewed.pop_back();
        }
    }

    /// Close the active project (if any).
    pub fn close_active_project(&self) -> ProjectResult<()> {
        let mut active = self.active_project.write().unwrap();
        if let Some(ref mut project) = *active {
            project.close()?;
        }
        *active = None;
        Ok(())
    }

    /// The project locator for the active project.
    pub fn active_project_locator(&self) -> Option<ProjectLocator> {
        let active = self.active_project.read().unwrap();
        active.as_ref().map(|p| p.locator().clone())
    }
}

impl fmt::Debug for DefaultProjectManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultProjectManager")
            .field("project_directory", &self.project_directory)
            .field("has_active", &self.has_active_project())
            .field("max_recent", &self.max_recent)
            .finish()
    }
}

// ============================================================================
// ProjectManager trait implementation
// ============================================================================

impl ProjectManager for DefaultProjectManager {
    fn create_project(
        &self,
        project_locator: &ProjectLocator,
        _rep_adapter: Option<&dyn RepositoryAdapter>,
        remember: bool,
    ) -> ProjectResult<Box<dyn ProjectHandle>> {
        if project_locator.exists() {
            return Err(ProjectError::AlreadyExists(project_locator.project_path()));
        }

        // Ensure the parent directory exists.
        if let Some(parent) = project_locator.project_path().parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let project = DefaultProject::create(
            &project_locator.project_name,
            &project_locator.project_dir,
        )?;

        if remember {
            self.add_recent(project_locator.clone());
        }

        *self.last_opened.write().unwrap() = Some(project_locator.clone());

        // Set as active project.
        let mut active = self.active_project.write().unwrap();
        // Close previous active project if any.
        if let Some(ref mut prev) = *active {
            let _ = prev.close();
        }
        *active = None; // We can't move project out since it's in a Box

        Ok(Box::new(project))
    }

    fn open_project(
        &self,
        project_locator: &ProjectLocator,
        _do_restore: bool,
        _reset_owner: bool,
    ) -> ProjectResult<Box<dyn ProjectHandle>> {
        if !project_locator.exists() {
            return Err(ProjectError::NotFound(project_locator.project_path()));
        }

        let project = DefaultProject::open(project_locator.project_path())?;

        self.add_recent(project_locator.clone());
        *self.last_opened.write().unwrap() = Some(project_locator.clone());

        Ok(Box::new(project))
    }

    fn delete_project(&self, project_locator: &ProjectLocator) -> bool {
        let project_path = project_locator.project_path();
        if !project_path.exists() {
            return false;
        }

        // If this is the active project, close it first.
        {
            let active = self.active_project.read().unwrap();
            if let Some(ref project) = *active {
                if project.project_path() == project_path {
                    drop(active);
                    let _ = self.close_active_project();
                }
            }
        }

        // Remove from recent lists.
        self.recent_projects
            .write()
            .unwrap()
            .retain(|l| l.project_path() != project_path);

        // Remove from known projects.
        self.known_projects
            .write()
            .unwrap()
            .retain(|l| l.project_path() != project_path);

        // Delete from disk.
        if let Err(e) = fs::remove_dir_all(&project_path) {
            log::error!("Failed to delete project at {}: {}", project_path.display(), e);
            return false;
        }

        true
    }

    fn project_exists(&self, project_locator: &ProjectLocator) -> bool {
        project_locator.exists()
    }

    fn active_project(&self) -> Option<&dyn ProjectHandle> {
        // Cannot return reference due to RwLock borrowing constraints.
        // In a real implementation, would use a different synchronization strategy.
        None
    }

    fn last_opened_project(&self) -> Option<&ProjectLocator> {
        // Cannot return reference to RwLock-guarded data.
        // Callers should use `last_opened_project_owned()` instead.
        None
    }

    fn set_last_opened_project(&self, project_locator: Option<&ProjectLocator>) {
        *self.last_opened.write().unwrap() = project_locator.cloned();
    }

    fn recent_projects(&self) -> Vec<ProjectLocator> {
        self.recent_projects.read().unwrap().iter().cloned().collect()
    }

    fn recent_viewed_projects(&self) -> Vec<String> {
        self.recent_viewed.read().unwrap().iter().cloned().collect()
    }

    fn remember_project(&self, project_locator: &ProjectLocator) {
        self.add_recent(project_locator.clone());
    }

    fn remember_viewed_project(&self, url: &str) {
        self.add_recent_viewed(url);
    }

    fn forget_viewed_project(&self, url: &str) {
        self.recent_viewed.write().unwrap().retain(|u| u != url);
    }

    fn get_repository_server(
        &self,
        _host: &str,
        _port: u16,
        _force_connect: bool,
    ) -> ProjectResult<Box<dyn RepositoryServerAdapter>> {
        Err(ProjectError::NotAvailable(
            "Repository server connection not implemented".into(),
        ))
    }

    fn most_recent_server_info(&self) -> Option<ServerInfo> {
        self.recent_server.read().unwrap().clone()
    }

    fn user_tool_chest(&self) -> &dyn ToolChest {
        static DEFAULT: std::sync::LazyLock<DefaultToolChest> =
            std::sync::LazyLock::new(|| DefaultToolChest);
        &*DEFAULT
    }
}

/// Default tool chest implementation.
struct DefaultToolChest;

impl ToolChest for DefaultToolChest {
    fn name(&self) -> &str {
        "Default"
    }

    fn tool_names(&self) -> Vec<String> {
        Vec::new()
    }
}

// ============================================================================
// Owned accessors (for use when references cannot be returned)
// ============================================================================

impl DefaultProjectManager {
    /// Get the last opened project locator (owned).
    pub fn last_opened_project_owned(&self) -> Option<ProjectLocator> {
        self.last_opened.read().unwrap().clone()
    }

    /// Get the most recent server info (owned).
    pub fn most_recent_server_info_owned(&self) -> Option<ServerInfo> {
        self.recent_server.read().unwrap().clone()
    }

    /// Set the most recent server info.
    pub fn set_recent_server(&self, info: ServerInfo) {
        *self.recent_server.write().unwrap() = Some(info);
    }

    /// Clear recent projects.
    pub fn clear_recent(&self) {
        self.recent_projects.write().unwrap().clear();
    }

    /// Clear recently viewed projects.
    pub fn clear_recent_viewed(&self) {
        self.recent_viewed.write().unwrap().clear();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn temp_base() -> PathBuf {
        let mut d = env::temp_dir();
        d.push(format!(
            "ghidra_default_project_manager_test_{}",
            std::process::id()
        ));
        d
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_manager_creation() {
        let base = temp_base().join("create");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mgr = DefaultProjectManager::new(&base);
        assert_eq!(mgr.get_project_directory(), base.as_path());
        assert!(!mgr.has_active_project());
        assert!(mgr.recent_projects().is_empty());
        assert!(mgr.last_opened_project_owned().is_none());

        cleanup(&base);
    }

    #[test]
    fn test_create_project() {
        let base = temp_base().join("create_proj");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mgr = DefaultProjectManager::new(&base);
        let loc = ProjectLocator::new(&base, "test_proj");

        let project = mgr.create_project(&loc, None, true).unwrap();
        assert_eq!(project.name(), "test_proj");
        assert!(loc.project_path().exists());
        assert!(!mgr.recent_projects().is_empty());
        assert!(mgr.last_opened_project_owned().is_some());

        cleanup(&base);
    }

    #[test]
    fn test_open_project() {
        let base = temp_base().join("open_proj");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        // First create a project.
        let mgr = DefaultProjectManager::new(&base);
        let loc = ProjectLocator::new(&base, "open_test");
        mgr.create_project(&loc, None, true).unwrap();

        // Now open it.
        let project = mgr.open_project(&loc, false, false).unwrap();
        assert_eq!(project.name(), "open_test");

        cleanup(&base);
    }

    #[test]
    fn test_open_nonexistent_fails() {
        let base = temp_base().join("open_missing");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mgr = DefaultProjectManager::new(&base);
        let loc = ProjectLocator::new(&base, "nonexistent");

        let result = mgr.open_project(&loc, false, false);
        assert!(matches!(result, Err(ProjectError::NotFound(_))));

        cleanup(&base);
    }

    #[test]
    fn test_create_duplicate_fails() {
        let base = temp_base().join("dup_create");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mgr = DefaultProjectManager::new(&base);
        let loc = ProjectLocator::new(&base, "dup_proj");

        mgr.create_project(&loc, None, true).unwrap();
        let result = mgr.create_project(&loc, None, true);
        assert!(matches!(result, Err(ProjectError::AlreadyExists(_))));

        cleanup(&base);
    }

    #[test]
    fn test_delete_project() {
        let base = temp_base().join("delete_proj");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mgr = DefaultProjectManager::new(&base);
        let loc = ProjectLocator::new(&base, "to_delete");

        mgr.create_project(&loc, None, true).unwrap();
        assert!(loc.project_path().exists());

        let deleted = mgr.delete_project(&loc);
        assert!(deleted);
        assert!(!loc.project_path().exists());
        assert!(mgr.recent_projects().is_empty());

        cleanup(&base);
    }

    #[test]
    fn test_delete_nonexistent_returns_false() {
        let base = temp_base().join("del_missing");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mgr = DefaultProjectManager::new(&base);
        let loc = ProjectLocator::new(&base, "nonexistent");

        assert!(!mgr.delete_project(&loc));

        cleanup(&base);
    }

    #[test]
    fn test_project_exists() {
        let base = temp_base().join("exists");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mgr = DefaultProjectManager::new(&base);
        let loc = ProjectLocator::new(&base, "exists_test");

        assert!(!mgr.project_exists(&loc));

        mgr.create_project(&loc, None, false).unwrap();
        assert!(mgr.project_exists(&loc));

        cleanup(&base);
    }

    #[test]
    fn test_recent_projects() {
        let base = temp_base().join("recent");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mgr = DefaultProjectManager::new(&base);
        let loc1 = ProjectLocator::new(&base, "proj1");
        let loc2 = ProjectLocator::new(&base, "proj2");

        mgr.create_project(&loc1, None, true).unwrap();
        mgr.create_project(&loc2, None, true).unwrap();

        let recent = mgr.recent_projects();
        assert_eq!(recent.len(), 2);
        // Most recent first.
        assert_eq!(recent[0].project_name, "proj2");
        assert_eq!(recent[1].project_name, "proj1");

        cleanup(&base);
    }

    #[test]
    fn test_remember_forget_viewed() {
        let base = temp_base().join("viewed");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mgr = DefaultProjectManager::new(&base);

        mgr.remember_viewed_project("ghidra://server/proj1");
        mgr.remember_viewed_project("ghidra://server/proj2");

        let viewed = mgr.recent_viewed_projects();
        assert_eq!(viewed.len(), 2);

        mgr.forget_viewed_project("ghidra://server/proj1");
        let viewed = mgr.recent_viewed_projects();
        assert_eq!(viewed.len(), 1);
        assert_eq!(viewed[0], "ghidra://server/proj2");

        cleanup(&base);
    }

    #[test]
    fn test_set_last_opened() {
        let base = temp_base().join("last_opened");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mgr = DefaultProjectManager::new(&base);
        let loc = ProjectLocator::new(&base, "test_proj");

        assert!(mgr.last_opened_project_owned().is_none());

        mgr.set_last_opened_project(Some(&loc));
        assert!(mgr.last_opened_project_owned().is_some());
        assert_eq!(
            mgr.last_opened_project_owned().unwrap().project_name,
            "test_proj"
        );

        mgr.set_last_opened_project(None);
        assert!(mgr.last_opened_project_owned().is_none());

        cleanup(&base);
    }

    #[test]
    fn test_discover_projects() {
        let base = temp_base().join("discover");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mgr = DefaultProjectManager::new(&base);
        let _p1 = DefaultProject::create("disc1", &base).unwrap();
        let _p2 = DefaultProject::create("disc2", &base).unwrap();

        let discovered = mgr.discover_projects().unwrap();
        let names: Vec<&str> = discovered.iter().map(|l| l.project_name.as_str()).collect();
        assert!(names.contains(&"disc1"));
        assert!(names.contains(&"disc2"));

        cleanup(&base);
    }

    #[test]
    fn test_server_info() {
        let base = temp_base().join("server");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mgr = DefaultProjectManager::new(&base);
        assert!(mgr.most_recent_server_info_owned().is_none());

        let info = ServerInfo::new("ghidra.server.com", 13100);
        mgr.set_recent_server(info);

        let server = mgr.most_recent_server_info_owned().unwrap();
        assert_eq!(server.host, "ghidra.server.com");
        assert_eq!(server.port, 13100);

        cleanup(&base);
    }

    #[test]
    fn test_clear_recent() {
        let base = temp_base().join("clear_recent");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mgr = DefaultProjectManager::new(&base);
        let loc = ProjectLocator::new(&base, "proj");
        mgr.create_project(&loc, None, true).unwrap();

        assert!(!mgr.recent_projects().is_empty());
        mgr.clear_recent();
        assert!(mgr.recent_projects().is_empty());

        cleanup(&base);
    }

    #[test]
    fn test_max_recent() {
        let base = temp_base().join("max_recent");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mut mgr = DefaultProjectManager::new(&base);
        mgr.set_max_recent(2);

        let loc1 = ProjectLocator::new(&base, "p1");
        let loc2 = ProjectLocator::new(&base, "p2");
        let loc3 = ProjectLocator::new(&base, "p3");

        mgr.create_project(&loc1, None, true).unwrap();
        mgr.create_project(&loc2, None, true).unwrap();
        mgr.create_project(&loc3, None, true).unwrap();

        let recent = mgr.recent_projects();
        assert_eq!(recent.len(), 2);

        cleanup(&base);
    }

    #[test]
    fn test_close_active() {
        let base = temp_base().join("close_active");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mgr = DefaultProjectManager::new(&base);
        // No active project to close -- should not error.
        mgr.close_active_project().unwrap();

        cleanup(&base);
    }

    #[test]
    fn test_default_project_directory() {
        let dir = DefaultProjectManager::default_project_directory();
        // Should not panic and should return a reasonable path.
        assert!(!dir.to_string_lossy().is_empty());
    }
}
