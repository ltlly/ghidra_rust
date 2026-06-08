//! Domain file abstraction for the Ghidra framework.
//!
//! Ports Ghidra's `framework.model.DomainFile` interface. A `DomainFile`
//! represents a single persistent file within a Ghidra project, tracking
//! its metadata, version, checkout state, and associated domain object.

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use super::domain_object::DomainObject;

// ============================================================================
// DomainFile
// ============================================================================

/// Represents a single file within a Ghidra project.
///
/// Each domain file has a unique path within the project, tracks its
/// version and checkout state, and can hold an open reference to its
/// backing [`DomainObject`].
#[derive(Debug)]
#[allow(dead_code)]
pub struct DomainFile {
    /// Full path within the project (e.g., "/folder/file.gzf").
    path: String,
    /// Display name (filename only).
    name: String,
    /// Path to the parent folder.
    parent_path: String,
    /// Domain type identifier (e.g., "Program", "DataTypeArchive").
    domain_type: String,
    /// Unique file ID.
    file_id: u64,
    /// Current version number.
    version: u32,
    /// Minimum supported version.
    min_version: u32,
    /// Latest available version.
    latest_version: u32,
    /// Whether this file is currently checked out.
    checked_out: bool,
    /// The user who has this file checked out.
    checked_out_by: Option<String>,
    /// Timestamp when this file was created.
    created_at: SystemTime,
    /// Timestamp of last modification.
    last_modified: SystemTime,
    /// Whether this file is read-only.
    read_only: bool,
    /// Whether this file exists on disk.
    exists: bool,
    /// Whether this file has unsaved changes.
    changed: bool,
    /// Open domain object, if any.
    open_object: Option<Arc<RwLock<dyn DomainObject>>>,
    /// Set of active consumers.
    consumers: HashSet<String>,
}

impl DomainFile {
    /// Create a new domain file with the given path and metadata.
    pub fn new(
        path: impl Into<String>,
        name: impl Into<String>,
        domain_type: impl Into<String>,
        file_id: u64,
    ) -> Self {
        let path_str: String = path.into();
        let name_str: String = name.into();
        let parent = {
            let trimmed = path_str.trim_end_matches('/');
            match trimmed.rfind('/') {
                Some(pos) => trimmed[..pos].to_string(),
                None => "/".to_string(),
            }
        };
        Self {
            path: path_str,
            name: name_str,
            parent_path: parent,
            domain_type: domain_type.into(),
            file_id,
            version: 1,
            min_version: 1,
            latest_version: 1,
            checked_out: false,
            checked_out_by: None,
            created_at: SystemTime::now(),
            last_modified: SystemTime::now(),
            read_only: false,
            exists: false,
            changed: false,
            open_object: None,
            consumers: HashSet::new(),
        }
    }

    /// Returns the full path within the project.
    pub fn get_pathname(&self) -> &str {
        &self.path
    }

    /// Returns the display name (filename only).
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns the parent folder path.
    pub fn get_parent_path(&self) -> &str {
        &self.parent_path
    }

    /// Returns the domain type identifier.
    pub fn get_domain_type(&self) -> &str {
        &self.domain_type
    }

    /// Returns the unique file ID.
    pub fn get_file_id(&self) -> u64 {
        self.file_id
    }

    /// Returns the current version number.
    pub fn get_version(&self) -> u32 {
        self.version
    }

    /// Sets the version number.
    pub fn set_version(&mut self, v: u32) {
        self.version = v;
    }

    /// Returns the latest available version.
    pub fn get_latest_version(&self) -> u32 {
        self.latest_version
    }

    /// Returns `true` if this file exists on disk.
    pub fn exists(&self) -> bool {
        self.exists
    }

    /// Set whether this file exists on disk.
    pub fn set_exists(&mut self, e: bool) {
        self.exists = e;
    }

    /// Returns `true` if this file is checked out.
    pub fn is_checked_out(&self) -> bool {
        self.checked_out
    }

    /// Returns the user who has this file checked out, if any.
    pub fn get_checked_out_by(&self) -> Option<&str> {
        self.checked_out_by.as_deref()
    }

    /// Check out this file for the given user.
    pub fn checkout(&mut self, user_id: impl Into<String>) -> Result<(), DomainFileError> {
        if self.checked_out {
            return Err(DomainFileError::AlreadyCheckedOut(self.name.clone()));
        }
        self.checked_out = true;
        self.checked_out_by = Some(user_id.into());
        Ok(())
    }

    /// Check in this file, incrementing the version.
    pub fn checkin(&mut self) {
        self.checked_out = false;
        self.checked_out_by = None;
        self.version += 1;
        self.latest_version = self.version;
        self.changed = false;
        self.last_modified = SystemTime::now();
    }

    /// Undo a checkout, reverting to the previous state.
    pub fn undo_checkout(&mut self) {
        self.checked_out = false;
        self.checked_out_by = None;
        self.changed = false;
    }

    /// Returns `true` if this file is read-only.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Set whether this file is read-only.
    pub fn set_read_only(&mut self, ro: bool) {
        self.read_only = ro;
    }

    /// Returns `true` if this file has unsaved changes.
    pub fn is_changed(&self) -> bool {
        self.changed
    }

    /// Mark this file as changed or unchanged.
    pub fn set_changed(&mut self, c: bool) {
        self.changed = c;
        if c {
            self.last_modified = SystemTime::now();
        }
    }

    /// Returns `true` if a domain object is currently open.
    pub fn is_open(&self) -> bool {
        self.open_object.is_some()
    }

    /// Get a reference to the open domain object, if any.
    pub fn get_domain_object(&self) -> Option<&Arc<RwLock<dyn DomainObject>>> {
        self.open_object.as_ref()
    }

    /// Set the open domain object.
    pub fn set_domain_object(&mut self, obj: Arc<RwLock<dyn DomainObject>>) {
        self.open_object = Some(obj);
    }

    /// Clear the open domain object reference.
    pub fn clear_domain_object(&mut self) {
        self.open_object = None;
    }

    /// Add a consumer to this file.
    pub fn add_consumer(&mut self, consumer: impl Into<String>) {
        self.consumers.insert(consumer.into());
    }

    /// Remove a consumer. Returns `true` if no consumers remain.
    pub fn release_consumer(&mut self, consumer: &str) -> bool {
        self.consumers.remove(consumer);
        self.consumers.is_empty()
    }

    /// Returns the set of active consumers.
    pub fn get_consumers(&self) -> &HashSet<String> {
        &self.consumers
    }

    /// Returns `true` if the file can be closed (no active consumers).
    pub fn can_close(&self) -> bool {
        self.consumers.is_empty()
    }

    /// Returns the creation timestamp.
    pub fn get_created_at(&self) -> SystemTime {
        self.created_at
    }

    /// Returns the last modification timestamp.
    pub fn get_last_modified(&self) -> SystemTime {
        self.last_modified
    }
}

// ============================================================================
// DomainFileError
// ============================================================================

/// Errors that can occur when operating on a domain file.
#[derive(Debug, Clone)]
pub enum DomainFileError {
    /// The file is already checked out.
    AlreadyCheckedOut(String),
    /// The file is read-only.
    ReadOnly(String),
    /// The file does not exist.
    NotFound(String),
    /// The file is locked by another consumer.
    Locked(String),
    /// An I/O error occurred.
    IoError(String),
    /// A generic error.
    Other(String),
}

impl fmt::Display for DomainFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainFileError::AlreadyCheckedOut(name) => {
                write!(f, "Already checked out: {}", name)
            }
            DomainFileError::ReadOnly(name) => write!(f, "Read-only: {}", name),
            DomainFileError::NotFound(name) => write!(f, "Not found: {}", name),
            DomainFileError::Locked(name) => write!(f, "Locked: {}", name),
            DomainFileError::IoError(msg) => write!(f, "I/O error: {}", msg),
            DomainFileError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for DomainFileError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_file_new() {
        let f = DomainFile::new("/folder/test.gzf", "test.gzf", "Program", 42);
        assert_eq!(f.get_pathname(), "/folder/test.gzf");
        assert_eq!(f.get_name(), "test.gzf");
        assert_eq!(f.get_parent_path(), "/folder");
        assert_eq!(f.get_domain_type(), "Program");
        assert_eq!(f.get_file_id(), 42);
        assert_eq!(f.get_version(), 1);
    }

    #[test]
    fn test_domain_file_root_parent() {
        let f = DomainFile::new("/test.gzf", "test.gzf", "Program", 1);
        assert_eq!(f.get_parent_path(), "/");
    }

    #[test]
    fn test_domain_file_checkout() {
        let mut f = DomainFile::new("/test.gzf", "test.gzf", "Program", 1);
        assert!(!f.is_checked_out());
        f.checkout("user1").unwrap();
        assert!(f.is_checked_out());
        assert_eq!(f.get_checked_out_by(), Some("user1"));

        // Double checkout should fail
        assert!(f.checkout("user2").is_err());

        f.undo_checkout();
        assert!(!f.is_checked_out());
        assert!(f.get_checked_out_by().is_none());
    }

    #[test]
    fn test_domain_file_checkin() {
        let mut f = DomainFile::new("/test.gzf", "test.gzf", "Program", 1);
        f.checkout("user1").unwrap();
        f.set_changed(true);
        f.checkin();
        assert!(!f.is_checked_out());
        assert!(!f.is_changed());
        assert_eq!(f.get_version(), 2);
        assert_eq!(f.get_latest_version(), 2);
    }

    #[test]
    fn test_domain_file_consumers() {
        let mut f = DomainFile::new("/test.gzf", "test.gzf", "Program", 1);
        assert!(f.can_close());

        f.add_consumer("tool1");
        f.add_consumer("tool2");
        assert!(!f.can_close());
        assert_eq!(f.get_consumers().len(), 2);

        assert!(!f.release_consumer("tool1"));
        assert!(f.release_consumer("tool2"));
        assert!(f.can_close());
    }

    #[test]
    fn test_domain_file_read_only() {
        let mut f = DomainFile::new("/test.gzf", "test.gzf", "Program", 1);
        assert!(!f.is_read_only());
        f.set_read_only(true);
        assert!(f.is_read_only());
    }

    #[test]
    fn test_domain_file_exists() {
        let mut f = DomainFile::new("/test.gzf", "test.gzf", "Program", 1);
        assert!(!f.exists());
        f.set_exists(true);
        assert!(f.exists());
    }

    #[test]
    fn test_domain_file_error_display() {
        let err = DomainFileError::AlreadyCheckedOut("test".to_string());
        assert!(err.to_string().contains("Already checked out"));

        let err = DomainFileError::ReadOnly("test".to_string());
        assert!(err.to_string().contains("Read-only"));
    }
}
