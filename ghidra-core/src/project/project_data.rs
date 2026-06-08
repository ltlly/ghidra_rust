//! Project data access layer.
//!
//! Ports key types from `ghidra.framework.data.DefaultProjectData` that are
//! shared across the project data management infrastructure:
//! [`ProjectDataManager`] -- the trait that all concrete `ProjectData`
//! implementations satisfy -- and supporting structures.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use super::model::*;
use super::{ProjectData, ProjectLocator, ProjectResult};

// ============================================================================
// ProjectDataManager trait
// ============================================================================

/// Extended trait for managing project data at the manager level.
///
/// In Java: the management interface that `DefaultProjectData` implements
/// in addition to `ProjectData`.  Provides operations that are typically
/// called by the project manager or the framework layer rather than
/// by individual plugins.
pub trait ProjectDataManager: ProjectData + fmt::Debug {
    /// Rename a file within the project.
    fn rename_file(&self, old_path: &str, new_name: &str) -> ProjectResult<String>;

    /// Move a file to a different folder.
    fn move_file(
        &self,
        file_path: &str,
        dest_folder_path: &str,
    ) -> ProjectResult<String>;

    /// Copy a file to a different folder.
    fn copy_file(
        &self,
        file_path: &str,
        dest_folder_path: &str,
        new_name: &str,
    ) -> ProjectResult<String>;

    /// Create a link (shortcut) to a file or folder.
    fn create_link(
        &self,
        link_path: &str,
        dest_path: &str,
    ) -> ProjectResult<String>;

    /// Whether this project data is connected to a repository.
    fn is_connected_to_repository(&self) -> bool {
        false
    }

    /// Get the folder metadata map.
    fn folder_metadata(&self, folder_path: &str) -> HashMap<String, String>;

    /// Get the file metadata map.
    fn file_metadata(&self, file_path: &str) -> ProjectResult<HashMap<String, String>>;
}

// ============================================================================
// FileStatus
// ============================================================================

/// Represents the status of a domain file within the project.
///
/// This is used for status display and for determining which actions
/// are available on a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStatus {
    /// Whether the file is currently open.
    pub is_open: bool,
    /// Whether the file has been modified since last save.
    pub is_changed: bool,
    /// Whether the file is checked out.
    pub is_checked_out: bool,
    /// Whether the file is versioned.
    pub is_versioned: bool,
    /// Whether the file is read-only.
    pub is_read_only: bool,
    /// Whether the file exists on disk.
    pub exists: bool,
    /// Content type string.
    pub content_type: String,
    /// Human-readable status text.
    pub status_text: String,
}

impl FileStatus {
    /// Create a file status for a non-existent file.
    pub fn missing(content_type: impl Into<String>) -> Self {
        Self {
            is_open: false,
            is_changed: false,
            is_checked_out: false,
            is_versioned: false,
            is_read_only: false,
            exists: false,
            content_type: content_type.into(),
            status_text: "Missing".to_string(),
        }
    }

    /// Create a file status for a normal (unmodified) file.
    pub fn normal(content_type: impl Into<String>) -> Self {
        Self {
            is_open: false,
            is_changed: false,
            is_checked_out: false,
            is_versioned: false,
            is_read_only: false,
            exists: true,
            content_type: content_type.into(),
            status_text: "OK".to_string(),
        }
    }

    /// Returns `true` when any status flags indicate the file needs attention.
    pub fn needs_attention(&self) -> bool {
        self.is_changed || (self.is_versioned && !self.is_checked_out) || !self.exists
    }
}

impl Default for FileStatus {
    fn default() -> Self {
        Self::missing("Unknown")
    }
}

impl fmt::Display for FileStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.status_text)
    }
}

// ============================================================================
// ProjectDataState
// ============================================================================

/// Represents the state of a [`ProjectData`] instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectDataState {
    /// The project data has not yet been initialized.
    Uninitialized,
    /// The project data is open and accessible.
    Open,
    /// The project data has been closed.
    Closed,
    /// An error occurred while accessing the project data.
    Error,
}

impl fmt::Display for ProjectDataState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialized => write!(f, "Uninitialized"),
            Self::Open => write!(f, "Open"),
            Self::Closed => write!(f, "Closed"),
            Self::Error => write!(f, "Error"),
        }
    }
}

// ============================================================================
// ProjectDataConfig
// ============================================================================

/// Configuration for creating a [`ProjectData`] instance.
#[derive(Debug, Clone)]
pub struct ProjectDataConfig {
    /// The project locator.
    pub locator: ProjectLocator,
    /// The base path on disk where the project data is stored.
    pub data_path: PathBuf,
    /// Maximum number of open domain objects to cache.
    pub max_open_objects: usize,
    /// Whether to automatically lock files on open.
    pub auto_lock_on_open: bool,
    /// Whether to enable version control features.
    pub version_control_enabled: bool,
}

impl ProjectDataConfig {
    /// Create a new config from a project locator.
    pub fn new(locator: ProjectLocator) -> Self {
        let data_path = locator.project_path().join("data");
        Self {
            locator,
            data_path,
            max_open_objects: 64,
            auto_lock_on_open: false,
            version_control_enabled: false,
        }
    }

    /// Set the data path.
    pub fn with_data_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.data_path = path.into();
        self
    }

    /// Set the maximum number of open objects.
    pub fn with_max_open_objects(mut self, max: usize) -> Self {
        self.max_open_objects = max;
        self
    }

    /// Enable or disable auto-lock.
    pub fn with_auto_lock(mut self, auto_lock: bool) -> Self {
        self.auto_lock_on_open = auto_lock;
        self
    }

    /// Enable or disable version control.
    pub fn with_version_control(mut self, enabled: bool) -> Self {
        self.version_control_enabled = enabled;
        self
    }
}

// ============================================================================
// ChangeListenerRegistration
// ============================================================================

/// Tracks a registered domain folder change listener with an associated ID.
#[derive(Debug)]
pub struct ChangeListenerRegistration {
    /// The unique listener ID.
    pub id: u64,
    /// The listener instance.
    pub listener: Arc<dyn DomainFolderChangeListener>,
}

impl ChangeListenerRegistration {
    /// Create a new registration.
    pub fn new(id: u64, listener: Arc<dyn DomainFolderChangeListener>) -> Self {
        Self { id, listener }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_status_missing() {
        let status = FileStatus::missing("Program");
        assert!(!status.exists);
        assert!(!status.is_open);
        assert!(status.needs_attention());
        assert_eq!(status.status_text, "Missing");
    }

    #[test]
    fn test_file_status_normal() {
        let status = FileStatus::normal("Program");
        assert!(status.exists);
        assert!(!status.needs_attention());
        assert_eq!(status.status_text, "OK");
    }

    #[test]
    fn test_file_status_needs_attention() {
        let mut status = FileStatus::normal("Program");
        status.is_changed = true;
        assert!(status.needs_attention());

        status.is_changed = false;
        status.is_versioned = true;
        status.is_checked_out = false;
        assert!(status.needs_attention());
    }

    #[test]
    fn test_file_status_display() {
        let status = FileStatus::normal("Program");
        assert_eq!(format!("{}", status), "OK");
    }

    #[test]
    fn test_project_data_state() {
        assert_ne!(ProjectDataState::Open, ProjectDataState::Closed);
        assert_eq!(format!("{}", ProjectDataState::Open), "Open");
        assert_eq!(format!("{}", ProjectDataState::Uninitialized), "Uninitialized");
        assert_eq!(format!("{}", ProjectDataState::Error), "Error");
    }

    #[test]
    fn test_project_data_config() {
        let locator = ProjectLocator::new("/tmp/projects", "my_proj");
        let config = ProjectDataConfig::new(locator)
            .with_max_open_objects(128)
            .with_auto_lock(true)
            .with_version_control(true);

        assert_eq!(config.max_open_objects, 128);
        assert!(config.auto_lock_on_open);
        assert!(config.version_control_enabled);
        assert_eq!(config.locator.project_name, "my_proj");
    }

    #[test]
    fn test_file_status_default() {
        let status = FileStatus::default();
        assert_eq!(status.status_text, "Missing");
    }
}
