//! Default project implementation.
//!
//! Ports `ghidra.framework.data.DefaultProject` from Java.  Provides a
//! concrete [`Project`] implementation that manages project data through
//! a [`DefaultProjectData`] instance, integrates with the project manager,
//! and supports undo/redo of project-level operations.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use super::default_project_data::DefaultProjectData;
use super::manager::ProjectHandle;
use super::model::*;
use super::project_data::ProjectDataConfig;
use super::{DomainFolder, ProjectData, ProjectError, ProjectLocator, ProjectResult};

// ============================================================================
// DefaultProject
// ============================================================================

/// Full-featured project implementation backed by the filesystem.
///
/// In Java: `ghidra.framework.data.DefaultProject`.
///
/// This extends the basic [`Project`] struct with:
/// - Integrated [`DefaultProjectData`] for data management
/// - Project-level tool state persistence
/// - Undo/redo support for project metadata changes
/// - Repository connection tracking
/// - Listener-based change notification
pub struct DefaultProject {
    /// The underlying project data.
    project_data: DefaultProjectData,
    /// The project locator.
    locator: ProjectLocator,
    /// The project name.
    name: String,
    /// Whether the project has unsaved changes.
    changed: bool,
    /// Whether the project is closed.
    closed: bool,
    /// In-memory metadata (key-value pairs persisted to the marker file).
    metadata: HashMap<String, String>,
    /// List of registered change listeners.
    listeners: RwLock<Vec<Arc<dyn DomainFolderChangeListener>>>,
    /// Undo stack for project-level metadata changes.
    undo_stack: Vec<ProjectSnapshot>,
    /// Redo stack for project-level metadata changes.
    redo_stack: Vec<ProjectSnapshot>,
    /// Repository adapter, if connected.
    repository_connected: bool,
    /// Project lock state.
    locked: bool,
}

/// A snapshot of project-level metadata for undo/redo.
#[derive(Debug, Clone)]
struct ProjectSnapshot {
    metadata: HashMap<String, String>,
    description: String,
}

impl DefaultProject {
    /// Create a new project on disk with full data support.
    pub fn create(
        name: impl Into<String>,
        project_dir: impl Into<PathBuf>,
    ) -> ProjectResult<Self> {
        let name: String = name.into();
        let project_dir: PathBuf = project_dir.into();
        let locator = ProjectLocator::new(&project_dir, &name);
        let project_path = locator.project_path();

        if project_path.exists() {
            return Err(ProjectError::AlreadyExists(project_path));
        }

        fs::create_dir_all(&project_path)?;

        // Write marker file.
        fs::write(
            locator.marker_path(),
            format!("ghidra_project_version=1\nname={}\n", name),
        )?;

        // Initialize project data.
        let config = ProjectDataConfig::new(locator.clone());
        let project_data = DefaultProjectData::with_config(config)?;

        Ok(Self {
            project_data,
            locator,
            name,
            changed: false,
            closed: false,
            metadata: HashMap::new(),
            listeners: RwLock::new(Vec::new()),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            repository_connected: false,
            locked: true,
        })
    }

    /// Open an existing project from its directory path.
    pub fn open(path: impl AsRef<Path>) -> ProjectResult<Self> {
        let path = path.as_ref();
        let locator = ProjectLocator::from_project_path(path)?;

        if !locator.exists() {
            return Err(ProjectError::NotFound(path.to_owned()));
        }

        let name = locator.project_name.clone();

        // Read metadata from marker file.
        let marker_content = fs::read_to_string(locator.marker_path())?;
        let mut metadata = HashMap::new();
        for line in marker_content.lines() {
            if let Some((key, value)) = line.split_once('=') {
                metadata.insert(key.trim().to_owned(), value.trim().to_owned());
            }
        }

        // Initialize project data.
        let config = ProjectDataConfig::new(locator.clone());
        let project_data = DefaultProjectData::with_config(config)?;

        Ok(Self {
            project_data,
            locator,
            name,
            changed: false,
            closed: false,
            metadata,
            listeners: RwLock::new(Vec::new()),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            repository_connected: false,
            locked: true,
        })
    }

    /// The project name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The project locator.
    pub fn locator(&self) -> &ProjectLocator {
        &self.locator
    }

    /// Whether the project has unsaved changes.
    pub fn is_changed(&self) -> bool {
        self.changed
    }

    /// Whether the project is closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// The project data instance.
    pub fn project_data(&self) -> &DefaultProjectData {
        &self.project_data
    }

    /// The mutable project data instance.
    pub fn project_data_mut(&mut self) -> &mut DefaultProjectData {
        &mut self.project_data
    }

    /// Set project metadata.
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key_str: String = key.into();
        // Snapshot for undo.
        self.capture_snapshot(&format!("set metadata {}", key_str));
        self.metadata.insert(key_str, value.into());
        self.changed = true;
    }

    /// Get a metadata value.
    pub fn metadata(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(|s| s.as_str())
    }

    /// Remove a metadata key.
    pub fn remove_metadata(&mut self, key: &str) {
        self.capture_snapshot(&format!("remove metadata {}", key));
        self.metadata.remove(key);
        self.changed = true;
    }

    /// All metadata keys.
    pub fn metadata_keys(&self) -> Vec<&String> {
        self.metadata.keys().collect()
    }

    /// Save the project to disk.
    pub fn save(&mut self) -> ProjectResult<()> {
        if !self.changed {
            return Ok(());
        }

        // Write metadata to marker file.
        let mut content = String::new();
        for (key, value) in &self.metadata {
            content.push_str(&format!("{}={}\n", key, value));
        }
        fs::write(self.locator.marker_path(), &content)?;

        self.changed = false;
        Ok(())
    }

    /// Close the project.
    pub fn close(&mut self) -> ProjectResult<()> {
        if self.closed {
            return Ok(());
        }

        if self.changed {
            self.save()?;
        }

        self.project_data.close();
        self.locked = false;
        self.closed = true;

        Ok(())
    }

    /// Whether this project has an active repository connection.
    pub fn is_repository_connected(&self) -> bool {
        self.repository_connected
    }

    /// Set the repository connection state.
    pub fn set_repository_connected(&mut self, connected: bool) {
        self.repository_connected = connected;
    }

    /// Register a change listener.
    pub fn add_listener(&self, listener: Arc<dyn DomainFolderChangeListener>) {
        self.listeners.write().unwrap().push(listener);
    }

    /// Notify all listeners that a file was added.
    pub fn fire_file_added(&self, file_path: &str) {
        let listeners = self.listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.domain_file_added(file_path);
        }
    }

    /// Notify all listeners that a folder was added.
    pub fn fire_folder_added(&self, folder_path: &str) {
        let listeners = self.listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.domain_folder_added(folder_path);
        }
    }

    /// Capture a snapshot of the current metadata state.
    fn capture_snapshot(&mut self, description: &str) {
        let snapshot = ProjectSnapshot {
            metadata: self.metadata.clone(),
            description: description.to_string(),
        };
        self.undo_stack.push(snapshot);
        self.redo_stack.clear();
    }

    /// Whether undo is available.
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Whether redo is available.
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Undo the last metadata change.
    pub fn undo(&mut self) -> ProjectResult<()> {
        let snapshot = self
            .undo_stack
            .pop()
            .ok_or_else(|| ProjectError::InvalidState("Nothing to undo".into()))?;

        // Save current state to redo stack.
        self.redo_stack.push(ProjectSnapshot {
            metadata: self.metadata.clone(),
            description: "redo".to_string(),
        });

        self.metadata = snapshot.metadata;
        self.changed = true;
        Ok(())
    }

    /// Redo the last undone metadata change.
    pub fn redo(&mut self) -> ProjectResult<()> {
        let snapshot = self
            .redo_stack
            .pop()
            .ok_or_else(|| ProjectError::InvalidState("Nothing to redo".into()))?;

        // Save current state to undo stack.
        self.undo_stack.push(ProjectSnapshot {
            metadata: self.metadata.clone(),
            description: "undo".to_string(),
        });

        self.metadata = snapshot.metadata;
        self.changed = true;
        Ok(())
    }

    /// Description of the change that would be undone.
    pub fn undo_description(&self) -> Option<&str> {
        self.undo_stack.last().map(|s| s.description.as_str())
    }

    /// Description of the change that would be redone.
    pub fn redo_description(&self) -> Option<&str> {
        self.redo_stack.last().map(|s| s.description.as_str())
    }

    /// Full path to this project's directory.
    pub fn project_path(&self) -> PathBuf {
        self.locator.project_path()
    }

    /// Whether the project lock is held.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Get a reference to the root folder.
    pub fn root_folder(&self) -> &dyn DomainFolder {
        self.project_data.root_folder()
    }
}

impl fmt::Debug for DefaultProject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultProject")
            .field("name", &self.name)
            .field("locator", &self.locator)
            .field("changed", &self.changed)
            .field("closed", &self.closed)
            .field("locked", &self.locked)
            .field("repository_connected", &self.repository_connected)
            .finish()
    }
}

// ============================================================================
// ProjectHandle impl
// ============================================================================

impl ProjectHandle for DefaultProject {
    fn name(&self) -> &str {
        &self.name
    }

    fn locator(&self) -> &ProjectLocator {
        &self.locator
    }

    fn is_modified(&self) -> bool {
        self.changed
    }

    fn project_path(&self) -> PathBuf {
        self.locator.project_path()
    }

    fn save(&mut self) -> ProjectResult<()> {
        DefaultProject::save(self)
    }

    fn close(&mut self) -> ProjectResult<()> {
        DefaultProject::close(self)
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
        d.push(format!("ghidra_default_project_test_{}", std::process::id()));
        d
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_create_and_open() {
        let base = temp_base().join("create_open");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        {
            let proj = DefaultProject::create("my_project", &base).unwrap();
            assert_eq!(proj.name(), "my_project");
            assert!(proj.is_locked());
            assert!(!proj.is_changed());
            assert!(proj.project_path().exists());
        }

        {
            let proj = DefaultProject::open(base.join("my_project")).unwrap();
            assert_eq!(proj.name(), "my_project");
            assert!(!proj.is_changed());
        }

        cleanup(&base);
    }

    #[test]
    fn test_duplicate_create_fails() {
        let base = temp_base().join("dup");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let _p1 = DefaultProject::create("dup_proj", &base).unwrap();
        let result = DefaultProject::create("dup_proj", &base);
        assert!(matches!(result, Err(ProjectError::AlreadyExists(_))));

        cleanup(&base);
    }

    #[test]
    fn test_metadata() {
        let base = temp_base().join("meta");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mut proj = DefaultProject::create("meta_proj", &base).unwrap();
        assert!(!proj.is_changed());

        proj.set_metadata("author", "Alice");
        assert!(proj.is_changed());
        assert_eq!(proj.metadata("author"), Some("Alice"));

        proj.save().unwrap();
        assert!(!proj.is_changed());

        drop(proj);

        let proj2 = DefaultProject::open(base.join("meta_proj")).unwrap();
        assert_eq!(proj2.metadata("author"), Some("Alice"));

        cleanup(&base);
    }

    #[test]
    fn test_remove_metadata() {
        let base = temp_base().join("remove_meta");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mut proj = DefaultProject::create("rm_proj", &base).unwrap();
        proj.set_metadata("key1", "value1");
        assert_eq!(proj.metadata("key1"), Some("value1"));

        proj.remove_metadata("key1");
        assert!(proj.metadata("key1").is_none());
        assert!(proj.is_changed());

        cleanup(&base);
    }

    #[test]
    fn test_undo_redo() {
        let base = temp_base().join("undo");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mut proj = DefaultProject::create("undo_proj", &base).unwrap();

        proj.set_metadata("key", "value1");
        proj.set_metadata("key", "value2");
        assert_eq!(proj.metadata("key"), Some("value2"));

        // Undo: back to "value1"
        assert!(proj.can_undo());
        proj.undo().unwrap();
        assert_eq!(proj.metadata("key"), Some("value1"));

        // Redo: back to "value2"
        assert!(proj.can_redo());
        proj.redo().unwrap();
        assert_eq!(proj.metadata("key"), Some("value2"));

        cleanup(&base);
    }

    #[test]
    fn test_undo_empty_fails() {
        let base = temp_base().join("undo_empty");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mut proj = DefaultProject::create("undo_empty_proj", &base).unwrap();
        assert!(!proj.can_undo());
        assert!(proj.undo().is_err());

        cleanup(&base);
    }

    #[test]
    fn test_close() {
        let base = temp_base().join("close");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mut proj = DefaultProject::create("close_proj", &base).unwrap();
        assert!(!proj.is_closed());

        proj.close().unwrap();
        assert!(proj.is_closed());

        cleanup(&base);
    }

    #[test]
    fn test_repository_connected() {
        let base = temp_base().join("repo");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mut proj = DefaultProject::create("repo_proj", &base).unwrap();
        assert!(!proj.is_repository_connected());

        proj.set_repository_connected(true);
        assert!(proj.is_repository_connected());

        cleanup(&base);
    }

    #[test]
    fn test_project_path() {
        let base = temp_base().join("path");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let proj = DefaultProject::create("path_proj", &base).unwrap();
        assert!(proj.project_path().ends_with("path_proj"));

        cleanup(&base);
    }

    #[test]
    fn test_project_handle_trait() {
        let base = temp_base().join("handle");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mut proj = DefaultProject::create("handle_proj", &base).unwrap();

        // Test ProjectHandle methods
        assert_eq!(ProjectHandle::name(&proj), "handle_proj");
        assert!(!ProjectHandle::is_modified(&proj));

        proj.set_metadata("x", "y");
        assert!(ProjectHandle::is_modified(&proj));

        cleanup(&base);
    }

    #[test]
    fn test_project_data_access() {
        let base = temp_base().join("pd_access");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let proj = DefaultProject::create("pd_proj", &base).unwrap();
        assert_eq!(proj.project_data().state(),
            super::super::project_data::ProjectDataState::Open);

        let root = proj.root_folder();
        assert!(root.is_root());

        cleanup(&base);
    }

    #[test]
    fn test_undo_description() {
        let base = temp_base().join("undo_desc");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mut proj = DefaultProject::create("desc_proj", &base).unwrap();
        proj.set_metadata("author", "Bob");

        let desc = proj.undo_description();
        assert!(desc.is_some());
        assert!(desc.unwrap().contains("author"));

        cleanup(&base);
    }
}
