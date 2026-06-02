//! Project management for Ghidra Rust.
//!
//! A [`Project`] represents a Ghidra workspace -- a directory containing
//! imported programs, analysis caches, and metadata.  The [`ProjectManager`]
//! orchestrates project lifecycle: creation, opening, deletion, and
//! discovery of recent projects on disk.
//!
//! ## Core types
//!
//! | Type              | Purpose                                    |
//! |-------------------|--------------------------------------------|
//! | [`ProjectManager`]| Global registry of projects                |
//! | [`Project`]       | A single Ghidra workspace                  |
//! | [`ProjectLocator`]| Filesystem path + marker used to find a project |
//! | [`ProjectFile`]   | A file or folder within the project        |
//! | [`DomainFile`]    | Trait for an individual project file       |
//! | [`DomainFolder`]  | Trait for a folder within a project        |
//! | [`ProjectData`]   | Trait for root-level data access           |

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::error::GhidraError;

// ============================================================================
// Error / result types
// ============================================================================

/// Errors that can occur during project operations.
#[derive(Debug)]
pub enum ProjectError {
    /// The project directory already exists.
    AlreadyExists(PathBuf),
    /// The project directory or marker file was not found.
    NotFound(PathBuf),
    /// An I/O error occurred.
    Io(std::io::Error),
    /// The project is locked by another process.
    Locked(PathBuf),
    /// The project file is in an invalid state.
    InvalidState(String),
    /// A required resource is not available.
    NotAvailable(String),
}

impl fmt::Display for ProjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists(p) => write!(f, "Project already exists: {}", p.display()),
            Self::NotFound(p) => write!(f, "Project not found: {}", p.display()),
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Locked(p) => write!(f, "Project is locked: {}", p.display()),
            Self::InvalidState(s) => write!(f, "Invalid project state: {}", s),
            Self::NotAvailable(s) => write!(f, "Resource not available: {}", s),
        }
    }
}

impl std::error::Error for ProjectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ProjectError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<GhidraError> for ProjectError {
    fn from(e: GhidraError) -> Self {
        Self::InvalidState(format!("{}", e))
    }
}

/// Result alias for project operations.
pub type ProjectResult<T> = Result<T, ProjectError>;

// ============================================================================
// Marker file constants
// ============================================================================

/// Name of the marker file placed inside every project directory.
pub const PROJECT_MARKER: &str = ".ghidra_project";
/// File extension for the project marker file (Ghidra *.gpr convention).
pub const PROJECT_FILE_SUFFIX: &str = ".gpr";
/// Suffix appended to a project directory for data storage.
pub const PROJECT_DIR_SUFFIX: &str = ".rep";
/// Lock file suffix.
pub const LOCK_FILE_SUFFIX: &str = ".lock";

// ============================================================================
// ProjectLocator
// ============================================================================

/// Describes the filesystem location of a project.
///
/// A locator holds a parent directory and a project name.  The actual project
/// directory is `<project_dir>/<project_name>/` and must contain a
/// [`PROJECT_MARKER`] file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectLocator {
    /// Parent directory that contains project folders.
    pub project_dir: PathBuf,
    /// Name of the project (subdirectory within `project_dir`).
    pub project_name: String,
    /// Marker file expected inside the project directory.
    pub marker_file: String,
}

impl ProjectLocator {
    /// Create a new locator.
    ///
    /// The marker defaults to [`PROJECT_MARKER`].
    pub fn new(project_dir: impl Into<PathBuf>, project_name: impl Into<String>) -> Self {
        Self {
            project_dir: project_dir.into(),
            project_name: project_name.into(),
            marker_file: PROJECT_MARKER.to_owned(),
        }
    }

    /// Build from an existing project path (the directory containing the
    /// marker file).  Infers `project_dir` as the parent and `project_name`
    /// as the final component.
    pub fn from_project_path(project_path: impl AsRef<Path>) -> ProjectResult<Self> {
        let path = project_path.as_ref();
        let project_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| ProjectError::NotFound(path.to_owned()))?
            .to_owned();
        let project_dir = path
            .parent()
            .ok_or_else(|| ProjectError::NotFound(path.to_owned()))?
            .to_path_buf();
        Ok(Self {
            project_dir,
            project_name,
            marker_file: PROJECT_MARKER.to_owned(),
        })
    }

    /// Returns the full path to the project directory.
    pub fn project_path(&self) -> PathBuf {
        self.project_dir.join(&self.project_name)
    }

    /// Returns the full path to the marker file.
    pub fn marker_path(&self) -> PathBuf {
        self.project_path().join(&self.marker_file)
    }

    /// Returns the full path to the lock file.
    pub fn lock_path(&self) -> PathBuf {
        self.project_path().join(".ghidra_lock")
    }

    /// Check whether the marker file exists on disk.
    pub fn exists(&self) -> bool {
        self.marker_path().exists() && self.project_path().is_dir()
    }

    /// The project name.
    pub fn name(&self) -> &str {
        &self.project_name
    }

    /// The parent directory as a string.
    pub fn location(&self) -> String {
        self.project_dir.to_string_lossy().to_string()
    }

    /// Set a custom marker file name.
    pub fn with_marker(mut self, marker: &str) -> Self {
        self.marker_file = marker.to_owned();
        self
    }

    // ---- static helpers ----

    /// Returns `true` when the given file is a project directory
    /// (its name ends with `PROJECT_DIR_SUFFIX`).
    pub fn is_project_dir(path: &Path) -> bool {
        path.is_dir()
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(PROJECT_DIR_SUFFIX))
                .unwrap_or(false)
    }

    /// Scan a directory (non-recursively) for Ghidra project marker files.
    pub fn find_projects(dir: &Path) -> Vec<ProjectLocator> {
        let mut projects = Vec::new();
        if !dir.is_dir() {
            return projects;
        }
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let marker = path.join(PROJECT_MARKER);
                    if marker.exists() {
                        if let Ok(loc) = Self::from_project_path(&path) {
                            projects.push(loc);
                        }
                    }
                }
            }
        }
        projects
    }
}

impl Default for ProjectLocator {
    fn default() -> Self {
        Self {
            project_dir: PathBuf::from("."),
            project_name: "untitled".to_owned(),
            marker_file: PROJECT_MARKER.to_owned(),
        }
    }
}

impl fmt::Display for ProjectLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.project_path().display())
    }
}

// ============================================================================
// ProjectFile -- file/folder tree
// ============================================================================

/// Metadata for one file or directory inside a project.
#[derive(Debug, Clone)]
pub struct ProjectFile {
    /// Relative path within the project.
    pub path: String,
    /// Display name.
    pub name: String,
    /// Icon identifier (platform-dependent).
    pub icon: Option<String>,
    /// Arbitrary key-value metadata.
    pub metadata: HashMap<String, String>,
    /// Parent folder, if any.
    pub parent: Option<Box<ProjectFile>>,
    /// Children (sub-folders and files).
    pub children: Vec<ProjectFile>,
}

impl ProjectFile {
    /// Create a leaf file entry.
    pub fn new(path: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            name: name.into(),
            icon: None,
            metadata: HashMap::new(),
            parent: None,
            children: Vec::new(),
        }
    }

    /// Create a folder entry.
    pub fn folder(path: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            name: name.into(),
            icon: Some("folder".into()),
            metadata: HashMap::new(),
            parent: None,
            children: Vec::new(),
        }
    }

    /// Add a child entry and set its parent pointer.
    pub fn add_child(&mut self, mut child: ProjectFile) {
        child.parent = Some(Box::new(self.clone()));
        self.children.push(child);
    }

    /// Returns `true` if this entry represents a folder.
    pub fn is_folder(&self) -> bool {
        self.icon.as_deref() == Some("folder") || !self.children.is_empty()
    }

    /// Walk the tree and collect all descendants.
    pub fn flatten(&self) -> Vec<&ProjectFile> {
        let mut result = vec![self];
        for child in &self.children {
            result.extend(child.flatten());
        }
        result
    }

    /// Find a child by relative path segments.
    pub fn find(&self, segments: &[&str]) -> Option<&ProjectFile> {
        if segments.is_empty() {
            return Some(self);
        }
        self.children
            .iter()
            .find(|c| c.name == segments[0])
            .and_then(|c| c.find(&segments[1..]))
    }

    /// Returns `true` when this file is a Ghidra program.
    pub fn is_program(&self) -> bool {
        self.metadata
            .get("content_type")
            .map(|s| s == "Program")
            .unwrap_or(false)
    }

    /// Returns `true` when the file is marked read-only.
    pub fn is_read_only(&self) -> bool {
        self.metadata
            .get("read_only")
            .map(|s| s == "true")
            .unwrap_or(false)
    }

    /// Returns `true` when the file is version-controlled.
    pub fn is_versioned(&self) -> bool {
        self.metadata
            .get("versioned")
            .map(|s| s == "true")
            .unwrap_or(false)
    }

    /// Returns the file extension, if any.
    pub fn extension(&self) -> Option<&str> {
        Path::new(&self.name).extension().and_then(|e| e.to_str())
    }

    /// Get the parent directory path.
    pub fn parent_path(&self) -> &str {
        match self.path.rfind('/') {
            Some(pos) => &self.path[..pos],
            None => "/",
        }
    }
}

// ============================================================================
// FileMetadata
// ============================================================================

/// Metadata describing the attributes of a [`ProjectFile`].
#[derive(Debug, Clone, Default)]
pub struct FileMetadata {
    /// Content type string (e.g., `"Program"`, `"DataTypes"`, `"Tool"`).
    pub content_type: Option<String>,
    /// Size of the file in bytes.
    pub size_bytes: Option<u64>,
    /// Last-modified timestamp (milliseconds since epoch, UTC).
    pub modified_timestamp: Option<i64>,
    /// Whether the file is read-only.
    pub read_only: bool,
    /// Whether the file is version-controlled.
    pub versioned: bool,
    /// Latest version number, if versioned.
    pub latest_version: Option<i32>,
    /// Whether the file is currently checked out.
    pub checked_out: bool,
    /// Whether the file has unsaved changes.
    pub changed: bool,
    /// Unique file identifier.
    pub file_id: Option<String>,
    /// Arbitrary user-defined tags.
    pub tags: Vec<String>,
    /// Custom key-value properties.
    pub properties: HashMap<String, String>,
}

impl FileMetadata {
    /// Create program-type metadata.
    pub fn for_program() -> Self {
        Self {
            content_type: Some("Program".to_string()),
            ..Default::default()
        }
    }

    /// Create data-type-archive metadata.
    pub fn for_data_types() -> Self {
        Self {
            content_type: Some("DataTypes".to_string()),
            ..Default::default()
        }
    }

    /// Create tool metadata.
    pub fn for_tool() -> Self {
        Self {
            content_type: Some("Tool".to_string()),
            ..Default::default()
        }
    }

    /// Set a custom property.
    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(key.into(), value.into());
    }

    /// Get a custom property value.
    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }

    /// Add a tag.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    /// Returns `true` when this file has the given tag.
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }

    /// Set the file size.
    pub fn set_size(&mut self, bytes: u64) {
        self.size_bytes = Some(bytes);
    }

    /// Mark as modified at the current time.
    pub fn touch(&mut self) {
        self.modified_timestamp = Some(
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
        );
    }
}

// ============================================================================
// Project lock
// ============================================================================

/// Internal type tracking whether a project is locked (single-writer
/// semantics).
#[derive(Debug)]
struct ProjectLock {
    lock_path: PathBuf,
    locked: bool,
}

impl ProjectLock {
    fn new(project_path: &Path) -> Self {
        Self {
            lock_path: project_path.join(".ghidra_lock"),
            locked: false,
        }
    }

    /// Try to acquire the lock by creating the lock file.
    fn acquire(&mut self) -> ProjectResult<()> {
        if self.lock_path.exists() {
            return Err(ProjectError::Locked(self.lock_path.clone()));
        }
        fs::File::create(&self.lock_path)?;
        self.locked = true;
        Ok(())
    }

    /// Release the lock by deleting the lock file.
    fn release(&mut self) {
        if self.locked {
            let _ = fs::remove_file(&self.lock_path);
            self.locked = false;
        }
    }

    fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for ProjectLock {
    fn drop(&mut self) {
        self.release();
    }
}

// ============================================================================
// Project
// ============================================================================

/// Represents an open Ghidra workspace.
///
/// A project lives in a directory on disk and holds imported programs,
/// analysis data, and user configuration.
pub struct Project {
    /// Human-readable name.
    pub name: String,
    /// Location on disk.
    pub location: ProjectLocator,
    /// In-memory cache of loaded programs (by name).
    pub program_cache: Vec<String>,
    /// Data manager for project data access (optional, may be set later).
    pub data_manager: Option<Box<dyn ProjectData>>,
    /// Arbitrary metadata (user properties, tool state, etc.).
    pub metadata_map: HashMap<String, String>,
    /// File-level lock to prevent concurrent modification.
    project_lock: ProjectLock,
    /// Whether the project has unsaved changes.
    modified_flag: bool,
}

impl fmt::Debug for Project {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Project")
            .field("name", &self.name)
            .field("location", &self.location)
            .field("program_cache", &self.program_cache)
            .field("data_manager", &self.data_manager.as_ref().map(|_| "ProjectData"))
            .field("metadata_map", &self.metadata_map)
            .field("project_lock", &self.project_lock)
            .field("modified_flag", &self.modified_flag)
            .finish()
    }
}

impl Project {
    /// Create a new project on disk.
    ///
    /// Creates the project directory, writes the marker file, and acquires
    /// the project lock.  Returns an error if the directory already exists.
    pub fn create(
        name: impl Into<String>,
        project_dir: impl Into<PathBuf>,
    ) -> ProjectResult<Self> {
        let name: String = name.into();
        let project_dir: PathBuf = project_dir.into();
        let locator = ProjectLocator::new(project_dir, &name);
        let project_path = locator.project_path();

        if project_path.exists() {
            return Err(ProjectError::AlreadyExists(project_path));
        }

        fs::create_dir_all(&project_path)?;

        // Write marker file.
        let marker_path = locator.marker_path();
        fs::write(
            &marker_path,
            format!("ghidra_project_version=1\nname={}\n", name),
        )?;

        let mut lock = ProjectLock::new(&project_path);
        lock.acquire()?;

        Ok(Self {
            name,
            location: locator,
            program_cache: Vec::new(),
            data_manager: None,
            metadata_map: HashMap::new(),
            project_lock: lock,
            modified_flag: false,
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
        let mut lock = ProjectLock::new(&locator.project_path());
        lock.acquire()?;

        // Read metadata from the marker file.
        let marker_content = fs::read_to_string(locator.marker_path())?;
        let mut metadata_map = HashMap::new();
        for line in marker_content.lines() {
            if let Some((key, value)) = line.split_once('=') {
                metadata_map.insert(key.trim().to_owned(), value.trim().to_owned());
            }
        }

        Ok(Self {
            name,
            location: locator,
            program_cache: Vec::new(),
            data_manager: None,
            metadata_map,
            project_lock: lock,
            modified_flag: false,
        })
    }

    /// Save any pending changes.
    pub fn save(&mut self) -> ProjectResult<()> {
        if !self.modified_flag {
            return Ok(());
        }

        // Persist metadata to marker file.
        let mut content = String::new();
        for (key, value) in &self.metadata_map {
            content.push_str(&format!("{}={}\n", key, value));
        }
        fs::write(self.location.marker_path(), &content)?;

        if let Some(ref dm) = self.data_manager {
            dm.refresh(false);
        }

        self.modified_flag = false;
        Ok(())
    }

    /// Close the project, releasing the lock and saving if modified.
    pub fn close(mut self) -> ProjectResult<()> {
        if self.modified_flag {
            self.save()?;
        }
        if let Some(ref dm) = self.data_manager {
            dm.close();
        }
        self.project_lock.release();
        Ok(())
    }

    /// Returns `true` if there are unsaved changes.
    pub fn is_modified(&self) -> bool {
        self.modified_flag
    }

    /// Mark the project as modified.
    pub fn mark_modified(&mut self) {
        self.modified_flag = true;
    }

    /// Get a metadata value by key.
    pub fn metadata(&self, key: &str) -> Option<&str> {
        self.metadata_map.get(key).map(|s| s.as_str())
    }

    /// Set a metadata value (marks as modified).
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata_map.insert(key.into(), value.into());
        self.modified_flag = true;
    }

    /// Remove a metadata key (marks as modified).
    pub fn remove_metadata(&mut self, key: &str) {
        self.metadata_map.remove(key);
        self.modified_flag = true;
    }

    /// Add a program to the in-memory cache.
    pub fn cache_program(&mut self, program_name: impl Into<String>) {
        self.program_cache.push(program_name.into());
    }

    /// Remove a program from the cache.
    pub fn evict_program(&mut self, program_name: &str) {
        self.program_cache.retain(|p| p != program_name);
    }

    /// Full path to this project's directory.
    pub fn project_path(&self) -> PathBuf {
        self.location.project_path()
    }

    /// Returns `true` if the project lock is held.
    pub fn is_locked(&self) -> bool {
        self.project_lock.is_locked()
    }

    /// Set the data manager.
    pub fn set_data_manager(&mut self, dm: Box<dyn ProjectData>) {
        self.data_manager = Some(dm);
    }

    /// List files in the project's data directory.
    pub fn list_data_files(&self) -> io::Result<Vec<PathBuf>> {
        let data_dir = self.location.project_path().join("data");
        if !data_dir.exists() {
            return Ok(Vec::new());
        }
        let entries: Vec<PathBuf> = fs::read_dir(&data_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        Ok(entries)
    }
}

// ============================================================================
// ProjectManager
// ============================================================================

/// Global registry that tracks known projects and the active one.
///
/// ```rust,ignore
/// let mut pm = ProjectManager::new("/home/user/ghidra_projects");
/// let p = pm.create_project("my_analysis")?;
/// assert!(pm.get_active_project().is_some());
/// ```
#[derive(Debug)]
pub struct ProjectManager {
    /// Directory where projects are stored.
    project_directory: PathBuf,
    /// All projects that have been opened or created during this session.
    projects: Vec<Project>,
    /// Index into `projects` of the currently active project.
    active_project: Option<usize>,
    /// Recently-opened project paths (most recent first).
    recent_projects: VecDeque<PathBuf>,
    /// Maximum number of recent projects to track.
    max_recent: usize,
}

impl ProjectManager {
    /// Create a new manager.
    ///
    /// `project_directory` is the default parent for new projects and the root
    /// directory scanned by [`locate_projects`].
    pub fn new(project_directory: impl Into<PathBuf>) -> Self {
        Self {
            project_directory: project_directory.into(),
            projects: Vec::new(),
            active_project: None,
            recent_projects: VecDeque::new(),
            max_recent: 20,
        }
    }

    // ---- lifecycle --------------------------------------------------------

    /// Create a new project on disk and register it.
    pub fn create_project(
        &mut self,
        name: impl Into<String>,
    ) -> ProjectResult<&mut Project> {
        let name: String = name.into();
        let project = Project::create(&name, &self.project_directory)?;
        self.projects.push(project);
        let idx = self.projects.len() - 1;
        self.active_project = Some(idx);
        let path = self.projects[idx].project_path();
        self.add_recent(path);
        Ok(&mut self.projects[idx])
    }

    /// Create a new project in a custom directory.
    pub fn create_project_in(
        &mut self,
        name: impl Into<String>,
        directory: impl Into<PathBuf>,
    ) -> ProjectResult<&mut Project> {
        let name: String = name.into();
        let project = Project::create(&name, directory)?;
        self.projects.push(project);
        let idx = self.projects.len() - 1;
        self.active_project = Some(idx);
        let path = self.projects[idx].project_path();
        self.add_recent(path);
        Ok(&mut self.projects[idx])
    }

    /// Open an existing project by path.
    pub fn open_project(
        &mut self,
        path: impl AsRef<Path>,
    ) -> ProjectResult<&mut Project> {
        let project = Project::open(path)?;
        self.projects.push(project);
        let idx = self.projects.len() - 1;
        self.active_project = Some(idx);
        let path = self.projects[idx].project_path();
        self.add_recent(path);
        Ok(&mut self.projects[idx])
    }

    /// Delete a project: close it (if open) and remove its directory from
    /// disk.
    pub fn delete_project(&mut self, index: usize) -> ProjectResult<()> {
        if index >= self.projects.len() {
            return Err(ProjectError::NotFound(PathBuf::from(format!(
                "Project index {} out of bounds",
                index
            ))));
        }

        let project_path = self.projects[index].project_path();

        if self.active_project == Some(index) {
            self.active_project = None;
        }
        self.projects.remove(index);
        if let Some(ref mut active) = self.active_project {
            if *active >= index {
                *active = active.saturating_sub(1);
            }
        }

        if project_path.exists() {
            fs::remove_dir_all(&project_path)?;
        }
        self.recent_projects.retain(|p| p != &project_path);

        Ok(())
    }

    /// Delete a project by name.
    pub fn delete_project_by_name(&mut self, name: &str) -> ProjectResult<()> {
        let idx = self
            .projects
            .iter()
            .position(|p| p.name == name)
            .ok_or_else(|| ProjectError::NotFound(PathBuf::from(name)))?;
        self.delete_project(idx)
    }

    /// Close a project without deleting it from disk.
    pub fn close_project(&mut self, index: usize) -> ProjectResult<()> {
        if index >= self.projects.len() {
            return Err(ProjectError::NotFound(PathBuf::from(format!(
                "Project index {} out of bounds",
                index
            ))));
        }
        if self.active_project == Some(index) {
            self.active_project = None;
        }
        let project = self.projects.remove(index);
        project.close()?;
        Ok(())
    }

    // ---- accessors --------------------------------------------------------

    /// Return a reference to the active project, if any.
    pub fn get_active_project(&self) -> Option<&Project> {
        self.active_project.and_then(|i| self.projects.get(i))
    }

    /// Return a mutable reference to the active project, if any.
    pub fn get_active_project_mut(&mut self) -> Option<&mut Project> {
        self.active_project.and_then(|i| self.projects.get_mut(i))
    }

    /// Set the active project by index.
    pub fn set_active(&mut self, index: usize) -> bool {
        if index < self.projects.len() {
            self.active_project = Some(index);
            self.add_recent(self.projects[index].project_path());
            true
        } else {
            false
        }
    }

    /// Set the active project by name.
    pub fn set_active_by_name(&mut self, name: &str) -> bool {
        if let Some(idx) = self.projects.iter().position(|p| p.name == name) {
            self.set_active(idx)
        } else {
            false
        }
    }

    /// Number of registered projects.
    pub fn project_count(&self) -> usize {
        self.projects.len()
    }

    /// Iterate over all registered projects.
    pub fn projects(&self) -> impl Iterator<Item = &Project> {
        self.projects.iter()
    }

    /// Get a project by name.
    pub fn get_project_by_name(&self, name: &str) -> Option<&Project> {
        self.projects.iter().find(|p| p.name == name)
    }

    /// Get a project by its filesystem path.
    pub fn get_project_by_path(&self, path: &Path) -> Option<&Project> {
        self.projects
            .iter()
            .find(|p| p.location.project_path() == path)
    }

    // ---- project directory ------------------------------------------------

    /// Get the default project directory.
    pub fn get_project_directory(&self) -> &Path {
        &self.project_directory
    }

    /// Change the default project directory.
    pub fn set_project_directory(&mut self, dir: impl Into<PathBuf>) {
        self.project_directory = dir.into();
    }

    // ---- recent projects ---------------------------------------------------

    /// List recently-opened project paths (most recent first).
    pub fn get_recent_projects(&self) -> Vec<&Path> {
        self.recent_projects.iter().map(|p| p.as_path()).collect()
    }

    /// Return the most recent project path, if any.
    pub fn most_recent_project(&self) -> Option<&Path> {
        self.recent_projects.front().map(|p| p.as_path())
    }

    fn add_recent(&mut self, path: PathBuf) {
        self.recent_projects.retain(|p| p != &path);
        self.recent_projects.push_front(path);
        if self.recent_projects.len() > self.max_recent {
            self.recent_projects.pop_back();
        }
    }

    /// Set the maximum number of recent projects to remember.
    pub fn set_max_recent(&mut self, max: usize) {
        self.max_recent = max.max(1);
        while self.recent_projects.len() > self.max_recent {
            self.recent_projects.pop_back();
        }
    }

    /// Clear the recent projects list.
    pub fn clear_recent(&mut self) {
        self.recent_projects.clear();
    }

    // ---- discovery --------------------------------------------------------

    /// Scan `project_directory` for valid project folders.
    pub fn locate_projects(&self) -> ProjectResult<Vec<ProjectLocator>> {
        Ok(ProjectLocator::find_projects(&self.project_directory))
    }

    /// Locate all projects under a custom directory.
    pub fn locate_projects_in(
        &self,
        directory: impl AsRef<Path>,
    ) -> ProjectResult<Vec<ProjectLocator>> {
        Ok(ProjectLocator::find_projects(directory.as_ref()))
    }

    /// Return the default project directory for the current platform.
    pub fn default_project_directory() -> PathBuf {
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join("ghidra_projects")
        } else if let Ok(profile) = std::env::var("USERPROFILE") {
            PathBuf::from(profile).join("ghidra_projects")
        } else {
            PathBuf::from(".")
        }
    }
}

// ============================================================================
// DomainFile trait
// ============================================================================

/// Represents an individual file within a Ghidra project.
///
/// Corresponds to `ghidra.framework.model.DomainFile`.
pub trait DomainFile: Send + Sync {
    /// The name of this file.
    fn name(&self) -> &str;
    /// Returns `true` when the file exists in storage.
    fn exists(&self) -> bool;
    /// A unique file-ID, or `None` if not established.
    fn file_id(&self) -> Option<&str>;
    /// The full path to this file within the project.
    fn pathname(&self) -> &str;
    /// The content type string (e.g., `"Program"`, `"DataTypes"`).
    fn content_type(&self) -> &str;
    /// The [`ProjectLocator`] for this file's project.
    fn project_locator(&self) -> &ProjectLocator;
    /// The parent folder of this file, or `None` for root level.
    fn parent_folder(&self) -> Option<&dyn DomainFolder>;
    /// Returns `true` when this file is explicitly marked read-only.
    fn is_read_only(&self) -> bool;
    /// Returns `true` when this file is versioned.
    fn is_versioned(&self) -> bool;
    /// Returns `true` when this file is checked out.
    fn is_checked_out(&self) -> bool;
    /// The latest version number.
    fn latest_version(&self) -> i32;
    /// The version this file currently references.
    fn version(&self) -> i32;
    /// The last-modified timestamp as milliseconds since epoch.
    fn last_modified_time(&self) -> i64;
    /// The length of this file in bytes.
    fn length(&self) -> ProjectResult<u64>;
    /// Save this file.
    fn save(&self) -> ProjectResult<()> {
        Err(ProjectError::NotAvailable("save not implemented".into()))
    }
    /// Delete this file.
    fn delete(&self) -> ProjectResult<()> {
        Err(ProjectError::NotAvailable(
            "delete not implemented".into(),
        ))
    }
}

// ============================================================================
// DomainFolder trait
// ============================================================================

/// Represents a folder within a Ghidra project.
pub trait DomainFolder: Send + Sync {
    /// The name of this folder.
    fn name(&self) -> &str;
    /// The full path to this folder.
    fn pathname(&self) -> &str;
    /// The [`ProjectLocator`] for this folder's project.
    fn project_locator(&self) -> &ProjectLocator;
    /// Returns `true` when this is the root folder.
    fn is_root(&self) -> bool;
    /// Get a child folder by name.
    fn get_folder(&self, _name: &str) -> Option<Box<dyn DomainFolder>> {
        None
    }
    /// Get a file within this folder by name.
    fn get_file(&self, _name: &str) -> Option<Box<dyn DomainFile>> {
        None
    }
    /// List all files in this folder.
    fn files(&self) -> ProjectResult<Vec<Box<dyn DomainFile>>>;
    /// List all sub-folders.
    fn folders(&self) -> ProjectResult<Vec<Box<dyn DomainFolder>>>;
}

// ============================================================================
// ProjectData trait
// ============================================================================

/// Provides access to all the data files and folders in a project.
pub trait ProjectData: Send + Sync {
    /// The root folder of the project.
    fn root_folder(&self) -> &dyn DomainFolder;
    /// Get a folder by absolute path.
    fn get_folder(&self, path: &str) -> Option<Box<dyn DomainFolder>>;
    /// Get a file by absolute path.
    fn get_file(&self, path: &str) -> Option<Box<dyn DomainFile>>;
    /// Get a file by its unique file ID.
    fn get_file_by_id(&self, file_id: &str) -> Option<Box<dyn DomainFile>>;
    /// Approximate number of files, or `-1` if unknown.
    fn file_count(&self) -> i32;
    /// The [`ProjectLocator`] for this project data.
    fn project_locator(&self) -> &ProjectLocator;
    /// Maximum name length for folders or items.
    fn max_name_length(&self) -> usize {
        256
    }
    /// Validate a folder/item name or path.
    fn test_valid_name(&self, _name: &str, _is_path: bool) -> ProjectResult<()> {
        Ok(())
    }
    /// Transform a name into an acceptable folder or file item name.
    fn make_valid_name(&self, name: &str) -> String {
        name.to_string()
    }
    /// Sync the folder/file structure with underlying storage.
    fn refresh(&self, _force: bool) {}
    /// Close this project data instance.
    fn close(&self) {}
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
        d.push(format!("ghidra_project_test_{}", std::process::id()));
        d
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    // ---- ProjectLocator ----

    #[test]
    fn test_locator_paths() {
        let loc = ProjectLocator::new("/tmp/projects", "testproj");
        assert_eq!(loc.project_path(), PathBuf::from("/tmp/projects/testproj"));
        assert_eq!(
            loc.marker_path(),
            PathBuf::from("/tmp/projects/testproj/.ghidra_project")
        );
    }

    #[test]
    fn test_locator_from_path() {
        let loc = ProjectLocator::from_project_path("/home/user/projects/my_proj").unwrap();
        assert_eq!(loc.project_dir, PathBuf::from("/home/user/projects"));
        assert_eq!(loc.project_name, "my_proj");
    }

    #[test]
    fn test_is_project_dir() {
        let tmp = env::temp_dir();
        let rep_dir = tmp.join("test_proj.rep");
        fs::create_dir_all(&rep_dir).unwrap();
        assert!(ProjectLocator::is_project_dir(&rep_dir));
        assert!(!ProjectLocator::is_project_dir(&tmp));
        fs::remove_dir_all(&rep_dir).unwrap();
    }

    // ---- ProjectFile ----

    #[test]
    fn test_project_file_tree() {
        let mut root = ProjectFile::folder("", "root");
        let mut src = ProjectFile::folder("src", "src");
        src.add_child(ProjectFile::new("src/main.rs", "main.rs"));
        root.add_child(src);

        assert_eq!(root.children.len(), 1);
        assert_eq!(root.children[0].children.len(), 1);
        assert_eq!(root.children[0].children[0].name, "main.rs");

        let found = root.find(&["src", "main.rs"]);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "main.rs");

        let all = root.flatten();
        assert_eq!(all.len(), 3);
    }

    // ---- Project ----

    #[test]
    fn test_project_create_open_close() {
        let base = temp_base().join("create_test");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        {
            let proj = Project::create("my_analysis", &base).unwrap();
            assert_eq!(proj.name, "my_analysis");
            assert!(proj.is_locked());
            assert!(!proj.is_modified());
            assert!(proj.location.exists());
        }

        {
            let proj = Project::open(base.join("my_analysis")).unwrap();
            assert_eq!(proj.name, "my_analysis");
            assert!(proj.is_locked());
        }

        cleanup(&base);
    }

    #[test]
    fn test_project_metadata() {
        let base = temp_base().join("meta_test");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mut proj = Project::create("meta_proj", &base).unwrap();
        assert!(!proj.is_modified());

        proj.set_metadata("author", "Alice");
        assert!(proj.is_modified());
        assert_eq!(proj.metadata("author"), Some("Alice"));

        proj.save().unwrap();
        assert!(!proj.is_modified());

        drop(proj);
        let proj2 = Project::open(base.join("meta_proj")).unwrap();
        assert_eq!(proj2.metadata("author"), Some("Alice"));

        drop(proj2);
        cleanup(&base);
    }

    #[test]
    fn test_project_duplicate_fails() {
        let base = temp_base().join("dup_test");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let _proj = Project::create("dup_proj", &base).unwrap();
        let result = Project::create("dup_proj", &base);
        assert!(matches!(result, Err(ProjectError::AlreadyExists(_))));

        drop(_proj);
        cleanup(&base);
    }

    // ---- ProjectManager ----

    #[test]
    fn test_manager_create_and_active() {
        let base = temp_base().join("mgr_test");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mut mgr = ProjectManager::new(&base);
        assert_eq!(mgr.get_project_directory(), base.as_path());

        mgr.create_project("proj_a").unwrap();
        assert_eq!(mgr.project_count(), 1);
        assert!(mgr.get_active_project().is_some());
        assert_eq!(mgr.get_active_project().unwrap().name, "proj_a");

        mgr.create_project("proj_b").unwrap();
        assert_eq!(mgr.project_count(), 2);
        assert_eq!(mgr.get_active_project().unwrap().name, "proj_b");

        assert!(mgr.set_active(0));
        assert_eq!(mgr.get_active_project().unwrap().name, "proj_a");

        assert!(mgr.set_active_by_name("proj_b"));
        assert_eq!(mgr.get_active_project().unwrap().name, "proj_b");

        let recents = mgr.get_recent_projects();
        assert!(recents.len() >= 2);

        mgr.close_project(1).ok();
        mgr.close_project(0).ok();
        assert_eq!(mgr.project_count(), 0);

        drop(mgr);
        cleanup(&base);
    }

    #[test]
    fn test_manager_delete_project() {
        let base = temp_base().join("del_test");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mut mgr = ProjectManager::new(&base);
        mgr.create_project("to_delete").unwrap();
        let proj_path = mgr.get_active_project().unwrap().project_path();
        assert!(proj_path.exists());

        mgr.delete_project(0).unwrap();
        assert_eq!(mgr.project_count(), 0);
        assert!(!proj_path.exists());

        drop(mgr);
        cleanup(&base);
    }

    #[test]
    fn test_manager_delete_by_name() {
        let base = temp_base().join("delname_test");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mut mgr = ProjectManager::new(&base);
        mgr.create_project("remove_me").unwrap();
        let proj_path = mgr.get_active_project().unwrap().project_path();

        mgr.delete_project_by_name("remove_me").unwrap();
        assert_eq!(mgr.project_count(), 0);
        assert!(!proj_path.exists());

        drop(mgr);
        cleanup(&base);
    }

    #[test]
    fn test_locate_projects() {
        let base = temp_base().join("locate_test");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        {
            let _a = Project::create("alpha", &base).unwrap();
            let _b = Project::create("beta", &base).unwrap();
        }

        let mgr = ProjectManager::new(&base);
        let located = mgr.locate_projects().unwrap();
        assert!(located.len() >= 2);
        let names: Vec<&str> = located
            .iter()
            .map(|l| l.project_name.as_str())
            .collect();
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));

        drop(mgr);
        cleanup(&base);
    }

    #[test]
    fn test_set_project_directory() {
        let mut mgr = ProjectManager::new("/tmp/old");
        assert_eq!(mgr.get_project_directory(), Path::new("/tmp/old"));
        mgr.set_project_directory("/tmp/new");
        assert_eq!(mgr.get_project_directory(), Path::new("/tmp/new"));
    }

    #[test]
    fn test_create_project_in_custom_dir() {
        let base = temp_base().join("custom_test");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let custom = base.join("custom_location");
        let mut mgr = ProjectManager::new(&base);
        mgr.create_project_in("custom_proj", &custom).unwrap();

        let proj = mgr.get_active_project().unwrap();
        assert!(proj.project_path().starts_with(&custom));
        assert!(proj.project_path().exists());

        drop(mgr);
        cleanup(&base);
    }

    #[test]
    fn test_recent_projects_limit() {
        let base = temp_base().join("recent_test");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let mut mgr = ProjectManager::new(&base);
        mgr.set_max_recent(3);

        for i in 1..=4 {
            mgr.create_project(format!("r{}", i)).unwrap();
        }

        let recents = mgr.get_recent_projects();
        assert_eq!(recents.len(), 3);

        while mgr.project_count() > 0 {
            mgr.delete_project(0).ok();
        }
        drop(mgr);
        cleanup(&base);
    }

    #[test]
    fn test_project_lock_release() {
        let base = temp_base().join("lock_test");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let proj = Project::create("lock_proj", &base).unwrap();
        let lock_path = proj.project_path().join(".ghidra_lock");
        assert!(proj.is_locked());
        assert!(lock_path.exists());

        proj.close().unwrap();
        assert!(!lock_path.exists());

        cleanup(&base);
    }

    // ---- FileMetadata ----

    #[test]
    fn test_file_metadata() {
        let mut meta = FileMetadata::for_program();
        assert_eq!(meta.content_type.as_deref(), Some("Program"));
        meta.add_tag("firmware");
        assert!(meta.has_tag("firmware"));
        meta.set_size(1024);
        assert_eq!(meta.size_bytes, Some(1024));
        meta.touch();
        assert!(meta.modified_timestamp.is_some());
    }
}
