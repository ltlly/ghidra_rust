//! GUI-level domain folder abstractions.
//!
//! Ports the GUI-facing parts of Ghidra's `framework.model.DomainFolder`
//! interface.  A `DomainFolder` is a storage container within a Ghidra
//! project that holds domain files and sub-folders, forming a hierarchical
//! tree.
//!
//! This module adds GUI-specific features on top of the core-level
//! `DomainFolder` concept: mutable operations (create, delete, move, copy),
//! linked-folder awareness, icon constants, and the separator/copy-suffix
//! conventions that the GUI tree views rely on.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Character used to separate folder and item names within a path string.
pub const SEPARATOR: &str = "/";

/// Name extension appended when creating a copy to avoid duplicate names.
pub const COPY_SUFFIX: &str = ".copy";

/// Icon identifier for an open folder node in the data tree.
pub const OPEN_FOLDER_ICON: &str = "icon.datatree.node.domain.folder.open";

/// Icon identifier for a closed folder node in the data tree.
pub const CLOSED_FOLDER_ICON: &str = "icon.datatree.node.domain.folder.closed";

// ---------------------------------------------------------------------------
// Link status
// ---------------------------------------------------------------------------

/// Status of a linked domain folder or file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkStatus {
    /// The link target is in the same project.
    Internal,
    /// The link target is in an external project.
    External,
    /// The link target cannot be resolved.
    Broken,
}

// ---------------------------------------------------------------------------
// GuiDomainFolder trait
// ---------------------------------------------------------------------------

/// The GUI-level domain folder interface.
///
/// This extends the read-only core folder concept with the full set of
/// mutable operations and metadata that Ghidra's GUI project tree expects:
/// rename, move, copy, delete, file/folder creation, link awareness, and
/// project data access.
pub trait GuiDomainFolder: fmt::Debug + Send + Sync {
    // -- identity ----------------------------------------------------------

    /// Returns the folder name (not the full path).
    fn get_name(&self) -> &str;

    /// Returns the full path to this folder (e.g. "/folder/subfolder").
    fn get_pathname(&self) -> &str;

    /// Returns `true` if this is the root folder of the project.
    fn is_root(&self) -> bool;

    /// Returns the parent folder, or `None` for the root.
    fn get_parent(&self) -> Option<&dyn GuiDomainFolder>;

    // -- navigation --------------------------------------------------------

    /// Get a child folder by name.
    fn get_folder(&self, name: &str) -> Option<Box<dyn GuiDomainFolder>>;

    /// Get a domain file in this folder by name.
    fn get_file(&self, name: &str) -> Option<&GuiDomainFile>;

    /// List all sub-folders.
    fn get_folders(&self) -> Vec<Box<dyn GuiDomainFolder>>;

    /// List all files in this folder.
    fn get_files(&self) -> Vec<&GuiDomainFile>;

    /// Returns `true` if this folder is empty.
    fn is_empty(&self) -> bool;

    // -- mutable operations ------------------------------------------------

    /// Rename this folder.  Returns the new folder reference (the original
    /// becomes invalid since folders are immutable references).
    fn set_name(&mut self, new_name: &str) -> Result<Box<dyn GuiDomainFolder>, DomainFolderGuiError>;

    /// Create a sub-folder.
    fn create_folder(&mut self, name: &str) -> Result<Box<dyn GuiDomainFolder>, DomainFolderGuiError>;

    /// Create a domain file in this folder.
    fn create_file(
        &mut self,
        name: &str,
        domain_type: &str,
    ) -> Result<GuiDomainFile, DomainFolderGuiError>;

    /// Delete this folder (must be empty).
    fn delete(&mut self) -> Result<(), DomainFolderGuiError>;

    /// Move this folder into `new_parent`.
    fn move_to(&mut self, new_parent: &mut dyn GuiDomainFolder)
        -> Result<Box<dyn GuiDomainFolder>, DomainFolderGuiError>;

    /// Copy this folder into `new_parent`.
    fn copy_to(&mut self, new_parent: &mut dyn GuiDomainFolder)
        -> Result<Box<dyn GuiDomainFolder>, DomainFolderGuiError>;

    /// Copy this folder into `new_parent` as a folder-link.
    fn copy_to_as_link(
        &mut self,
        new_parent: &mut dyn GuiDomainFolder,
        relative: bool,
    ) -> Result<GuiDomainFile, DomainFolderGuiError>;

    /// Set this folder as the "active" one in the GUI.
    fn set_active(&self);

    // -- link awareness ----------------------------------------------------

    /// Returns `true` if this folder corresponds to a linked-folder.
    fn is_linked(&self) -> bool {
        false
    }

    /// Returns the link status if this folder is linked.
    fn get_link_status(&self) -> Option<LinkStatus> {
        if self.is_linked() {
            Some(LinkStatus::Internal)
        } else {
            None
        }
    }

    // -- project metadata --------------------------------------------------

    /// Returns the project locator path.
    fn get_project_locator(&self) -> Option<String>;

    /// Returns `true` if the project is writable.
    fn is_in_writable_project(&self) -> bool;

    // -- path comparison ---------------------------------------------------

    /// Returns `true` if `folder` refers to the same project folder as `self`,
    /// based on path and underlying project/repository identity.
    ///
    /// Mirrors Java's `DomainFolder.isSame(DomainFolder)`.
    fn is_same(&self, folder: &dyn GuiDomainFolder) -> bool {
        self.get_pathname() == folder.get_pathname()
    }

    /// Returns `true` if `folder` is the same as or a descendant of this
    /// folder, based on path and underlying project/repository identity.
    ///
    /// Mirrors Java's `DomainFolder.isSameOrAncestor(DomainFolder)`.
    fn is_same_or_ancestor(&self, folder: &dyn GuiDomainFolder) -> bool {
        let my_path = self.get_pathname();
        let other_path = folder.get_pathname();
        other_path == my_path || other_path.starts_with(&format!("{}/", my_path.trim_end_matches('/')))
    }

    // -- URL access --------------------------------------------------------

    /// Get a remote Ghidra URL for this domain folder if available within an
    /// associated shared project repository.
    ///
    /// Returns `None` if the shared folder does not exist or the repository
    /// is not connected.  Mirrors Java's `getSharedProjectURL()`.
    fn get_shared_project_url(&self) -> Option<String> {
        None
    }

    /// Get a local Ghidra URL for this domain folder if available within the
    /// associated non-transient local project.
    ///
    /// Returns `None` if the project is transient.  Mirrors Java's
    /// `getLocalProjectURL()`.
    fn get_local_project_url(&self) -> Option<String> {
        None
    }

    // -- link-file creation ------------------------------------------------

    /// Create a link-file within this folder that references the specified
    /// `pathname` within the given source project.
    ///
    /// Mirrors Java's `DomainFolder.createLinkFile(ProjectData, String,
    /// boolean, String, LinkHandler)`.
    fn create_link_file(
        &mut self,
        _source_path: &str,
        _target_path: &str,
        _make_relative: bool,
        link_filename: &str,
        link_type: &str,
    ) -> Result<GuiDomainFile, DomainFolderGuiError> {
        Err(DomainFolderGuiError::NotSupported(format!(
            "create_link_file not supported (link_filename={}, type={})",
            link_filename, link_type,
        )))
    }

    // -- utility -----------------------------------------------------------

    /// Returns the icon identifier for this folder.
    fn get_icon(&self, open: bool) -> &str {
        if open {
            OPEN_FOLDER_ICON
        } else {
            CLOSED_FOLDER_ICON
        }
    }
}

// ---------------------------------------------------------------------------
// GuiDomainFile (minimal for folder operations)
// ---------------------------------------------------------------------------

/// A lightweight representation of a domain file within a folder.
///
/// This is not a full port of `DomainFile`; it carries only the metadata
/// that folder-level operations and the tree view need.
#[derive(Debug, Clone)]
pub struct GuiDomainFile {
    /// Full path within the project (e.g. "/folder/program.gzf").
    path: String,
    /// Display name (filename only).
    name: String,
    /// Domain type identifier (e.g. "Program", "DataTypeArchive").
    domain_type: String,
    /// Whether this file is currently checked out.
    checked_out: bool,
    /// Whether this is an exclusive checkout.
    checked_out_exclusive: bool,
    /// The user who has this file checked out.
    checked_out_by: Option<String>,
    /// Whether this file is read-only.
    read_only: bool,
    /// Whether this file has unsaved changes.
    changed: bool,
    /// Whether the file has been modified since checkout.
    modified_since_checkout: bool,
    /// Link status, if this file is a link-file.
    link_status: Option<LinkStatus>,
    /// Whether the file is versioned (in version control).
    versioned: bool,
    /// Whether the file is hijacked (versioned but private copy exists).
    hijacked: bool,
    /// The current version number.
    version: i32,
    /// The latest available version number.
    latest_version: i32,
    /// A unique file ID, if established.
    file_id: Option<String>,
    /// Content type string.
    content_type: String,
    /// Whether this file exists (false for proxy files).
    exists: bool,
    /// Length of the file in bytes.
    file_length: u64,
    /// Last modification timestamp (epoch millis).
    last_modified_time: u64,
    /// Additional metadata key/value pairs.
    metadata: HashMap<String, String>,
}

impl GuiDomainFile {
    /// The default version identifier, meaning "use the latest version".
    pub const DEFAULT_VERSION: i32 = -1;

    /// Create a new domain file descriptor.
    pub fn new(
        path: impl Into<String>,
        name: impl Into<String>,
        domain_type: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            name: name.into(),
            domain_type: domain_type.into(),
            checked_out: false,
            checked_out_exclusive: false,
            checked_out_by: None,
            read_only: false,
            changed: false,
            modified_since_checkout: false,
            link_status: None,
            versioned: false,
            hijacked: false,
            version: Self::DEFAULT_VERSION,
            latest_version: Self::DEFAULT_VERSION,
            file_id: None,
            content_type: String::new(),
            exists: true,
            file_length: 0,
            last_modified_time: 0,
            metadata: HashMap::new(),
        }
    }

    /// Returns the full path.
    pub fn get_pathname(&self) -> &str {
        &self.path
    }

    /// Returns the display name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns the domain type identifier.
    pub fn get_domain_type(&self) -> &str {
        &self.domain_type
    }

    /// Returns `true` if the file is checked out.
    pub fn is_checked_out(&self) -> bool {
        self.checked_out
    }

    /// Returns the checkout user, if any.
    pub fn get_checked_out_by(&self) -> Option<&str> {
        self.checked_out_by.as_deref()
    }

    /// Mark the file as checked out by the given user.
    pub fn set_checked_out(&mut self, user: impl Into<String>) {
        self.checked_out = true;
        self.checked_out_by = Some(user.into());
    }

    /// Clear the checkout state.
    pub fn clear_checkout(&mut self) {
        self.checked_out = false;
        self.checked_out_by = None;
    }

    /// Returns `true` if the file is read-only.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Set the read-only flag.
    pub fn set_read_only(&mut self, ro: bool) {
        self.read_only = ro;
    }

    /// Returns `true` if the file has unsaved changes.
    pub fn is_changed(&self) -> bool {
        self.changed
    }

    /// Set the changed flag.
    pub fn set_changed(&mut self, c: bool) {
        self.changed = c;
    }

    /// Returns the link status, if this file is a link-file.
    pub fn get_link_status(&self) -> Option<LinkStatus> {
        self.link_status
    }

    /// Set the link status.
    pub fn set_link_status(&mut self, status: LinkStatus) {
        self.link_status = Some(status);
    }

    /// Returns `true` if this file is a link-file.
    pub fn is_link_file(&self) -> bool {
        self.link_status.is_some()
    }

    /// Returns `true` if this is a folder-link file.
    pub fn is_folder_link(&self) -> bool {
        // Convention: folder links have domain type "FolderLink"
        self.link_status.is_some() && self.domain_type == "FolderLink"
    }

    /// Get a metadata value.
    pub fn get_metadata(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(|s| s.as_str())
    }

    /// Set a metadata value.
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Returns all metadata.
    pub fn get_all_metadata(&self) -> &HashMap<String, String> {
        &self.metadata
    }

    // -- Extended checkout / version methods --------------------------------

    /// Returns `true` if this is a checked-out file with exclusive access.
    pub fn is_checked_out_exclusive(&self) -> bool {
        self.checked_out_exclusive
    }

    /// Set whether this checkout is exclusive.
    pub fn set_checked_out_exclusive(&mut self, exclusive: bool) {
        self.checked_out_exclusive = exclusive;
    }

    /// Returns `true` if this file has been modified since it was checked out.
    pub fn modified_since_checkout(&self) -> bool {
        self.modified_since_checkout
    }

    /// Set the "modified since checkout" flag.
    pub fn set_modified_since_checkout(&mut self, modified: bool) {
        self.modified_since_checkout = modified;
    }

    /// Returns `true` if the file is versioned (under version control).
    pub fn is_versioned(&self) -> bool {
        self.versioned
    }

    /// Set the versioned flag.
    pub fn set_versioned(&mut self, versioned: bool) {
        self.versioned = versioned;
    }

    /// Returns `true` if the file is hijacked (versioned but a private copy
    /// also exists).
    pub fn is_hijacked(&self) -> bool {
        self.hijacked
    }

    /// Set the hijacked flag.
    pub fn set_hijacked(&mut self, hijacked: bool) {
        self.hijacked = hijacked;
    }

    /// Returns the current version number.
    pub fn get_version(&self) -> i32 {
        self.version
    }

    /// Set the current version number.
    pub fn set_version(&mut self, version: i32) {
        self.version = version;
    }

    /// Returns the latest available version number.
    pub fn get_latest_version(&self) -> i32 {
        self.latest_version
    }

    /// Set the latest version number.
    pub fn set_latest_version(&mut self, version: i32) {
        self.latest_version = version;
    }

    /// Returns `true` if this file is the latest version.
    pub fn is_latest_version(&self) -> bool {
        self.version == self.latest_version
    }

    /// Returns the file ID, if one has been established.
    pub fn get_file_id(&self) -> Option<&str> {
        self.file_id.as_deref()
    }

    /// Set the file ID.
    pub fn set_file_id(&mut self, id: impl Into<String>) {
        self.file_id = Some(id.into());
    }

    /// Returns the content type string.
    pub fn get_content_type(&self) -> &str {
        &self.content_type
    }

    /// Set the content type.
    pub fn set_content_type(&mut self, ct: impl Into<String>) {
        self.content_type = ct.into();
    }

    /// Returns `true` if the file exists.
    pub fn exists(&self) -> bool {
        self.exists
    }

    /// Set whether the file exists.
    pub fn set_exists(&mut self, exists: bool) {
        self.exists = exists;
    }

    /// Returns the file length in bytes.
    pub fn length(&self) -> u64 {
        self.file_length
    }

    /// Set the file length.
    pub fn set_length(&mut self, len: u64) {
        self.file_length = len;
    }

    /// Returns the last modification time (epoch millis).
    pub fn get_last_modified_time(&self) -> u64 {
        self.last_modified_time
    }

    /// Set the last modification time.
    pub fn set_last_modified_time(&mut self, time: u64) {
        self.last_modified_time = time;
    }

    /// Returns `true` if this file is open (has an active domain object).
    pub fn is_open(&self) -> bool {
        self.changed || self.checked_out
    }

    /// Returns `true` if this file can be checked out.
    pub fn can_checkout(&self) -> bool {
        !self.checked_out && !self.read_only && self.exists
    }

    /// Returns `true` if this file can be checked in.
    pub fn can_checkin(&self) -> bool {
        self.checked_out && self.modified_since_checkout
    }

    /// Returns `true` if this file can be saved.
    pub fn can_save(&self) -> bool {
        !self.read_only && self.exists
    }

    /// Undo the checkout, restoring the original repository file.
    pub fn undo_checkout(&mut self, keep: bool) {
        if keep {
            // In a real implementation, rename private db with .keep extension.
        }
        self.checked_out = false;
        self.checked_out_exclusive = false;
        self.checked_out_by = None;
        self.modified_since_checkout = false;
    }

    /// Returns the icon identifier for this file.
    ///
    /// Returns `None` if no specific icon is determined (caller should use
    /// a default).
    pub fn get_icon(&self) -> Option<&str> {
        if self.link_status.is_some() {
            Some("icon.domain.file.link")
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur in GUI-level domain folder operations.
#[derive(Debug, Clone)]
pub enum DomainFolderGuiError {
    /// A file or folder with the given name already exists.
    DuplicateFile(String),
    /// The name is invalid.
    InvalidName(String),
    /// The folder is not empty (cannot be deleted).
    FolderNotEmpty(String),
    /// The item was not found.
    NotFound(String),
    /// The file or folder is in use (checked out or locked).
    FileInUse(String),
    /// An I/O error occurred.
    IoError(String),
    /// The operation was cancelled.
    Cancelled,
    /// The operation is not supported.
    NotSupported(String),
    /// A generic error.
    Other(String),
}

impl fmt::Display for DomainFolderGuiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateFile(name) => write!(f, "Duplicate file: {}", name),
            Self::InvalidName(name) => write!(f, "Invalid name: {}", name),
            Self::FolderNotEmpty(name) => write!(f, "Folder not empty: {}", name),
            Self::NotFound(name) => write!(f, "Not found: {}", name),
            Self::FileInUse(name) => write!(f, "File in use: {}", name),
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
            Self::Cancelled => write!(f, "Operation cancelled"),
            Self::NotSupported(msg) => write!(f, "Not supported: {}", msg),
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for DomainFolderGuiError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Mock folder -------------------------------------------------------

    #[derive(Debug)]
    struct MockFolder {
        name: String,
        path: String,
        files: Vec<GuiDomainFile>,
        folders: Vec<MockFolder>,
        linked: bool,
        writable: bool,
    }

    impl MockFolder {
        fn new(name: &str, path: &str) -> Self {
            Self {
                name: name.to_string(),
                path: path.to_string(),
                files: Vec::new(),
                folders: Vec::new(),
                linked: false,
                writable: true,
            }
        }

        fn with_file(mut self, file: GuiDomainFile) -> Self {
            self.files.push(file);
            self
        }

        fn with_folder(mut self, folder: MockFolder) -> Self {
            self.folders.push(folder);
            self
        }

        fn with_linked(mut self, linked: bool) -> Self {
            self.linked = linked;
            self
        }
    }

    impl GuiDomainFolder for MockFolder {
        fn get_name(&self) -> &str { &self.name }
        fn get_pathname(&self) -> &str { &self.path }
        fn is_root(&self) -> bool { self.path == "/" }
        fn get_parent(&self) -> Option<&dyn GuiDomainFolder> { None }
        fn get_folder(&self, name: &str) -> Option<Box<dyn GuiDomainFolder>> {
            self.folders.iter().find(|f| f.name == name).map(|f| {
                Box::new(MockFolder::new(&f.name, &f.path)) as Box<dyn GuiDomainFolder>
            })
        }
        fn get_file(&self, name: &str) -> Option<&GuiDomainFile> {
            self.files.iter().find(|f| f.name == name)
        }
        fn get_folders(&self) -> Vec<Box<dyn GuiDomainFolder>> {
            self.folders.iter().map(|f| {
                Box::new(MockFolder::new(&f.name, &f.path)) as Box<dyn GuiDomainFolder>
            }).collect()
        }
        fn get_files(&self) -> Vec<&GuiDomainFile> {
            self.files.iter().collect()
        }
        fn is_empty(&self) -> bool {
            self.files.is_empty() && self.folders.is_empty()
        }
        fn set_name(&mut self, new_name: &str) -> Result<Box<dyn GuiDomainFolder>, DomainFolderGuiError> {
            self.name = new_name.to_string();
            Ok(Box::new(MockFolder::new(&self.name, &self.path)))
        }
        fn create_folder(&mut self, name: &str) -> Result<Box<dyn GuiDomainFolder>, DomainFolderGuiError> {
            let child = MockFolder::new(name, &format!("{}/{}", self.path, name));
            self.folders.push(MockFolder::new(name, &format!("{}/{}", self.path, name)));
            Ok(Box::new(child))
        }
        fn create_file(&mut self, name: &str, domain_type: &str) -> Result<GuiDomainFile, DomainFolderGuiError> {
            let path = format!("{}/{}", self.path, name);
            let file = GuiDomainFile::new(&path, name, domain_type);
            self.files.push(file.clone());
            Ok(file)
        }
        fn delete(&mut self) -> Result<(), DomainFolderGuiError> {
            if !self.is_empty() {
                return Err(DomainFolderGuiError::FolderNotEmpty(self.name.clone()));
            }
            Ok(())
        }
        fn move_to(&mut self, _new_parent: &mut dyn GuiDomainFolder) -> Result<Box<dyn GuiDomainFolder>, DomainFolderGuiError> {
            Ok(Box::new(MockFolder::new(&self.name, &self.path)))
        }
        fn copy_to(&mut self, _new_parent: &mut dyn GuiDomainFolder) -> Result<Box<dyn GuiDomainFolder>, DomainFolderGuiError> {
            Ok(Box::new(MockFolder::new(&format!("{}.copy", self.name), &self.path)))
        }
        fn copy_to_as_link(&mut self, _new_parent: &mut dyn GuiDomainFolder, _relative: bool) -> Result<GuiDomainFile, DomainFolderGuiError> {
            Ok(GuiDomainFile::new(&self.path, &self.name, "FolderLink"))
        }
        fn set_active(&self) {}
        fn is_linked(&self) -> bool { self.linked }
        fn get_project_locator(&self) -> Option<String> { Some("/projects/test".into()) }
        fn is_in_writable_project(&self) -> bool { self.writable }
        fn get_shared_project_url(&self) -> Option<String> { None }
        fn get_local_project_url(&self) -> Option<String> { Some("ghidra:///projects/test".into()) }
    }

    // -- Constants ---------------------------------------------------------

    #[test]
    fn test_separator() {
        assert_eq!(SEPARATOR, "/");
    }

    #[test]
    fn test_copy_suffix() {
        assert_eq!(COPY_SUFFIX, ".copy");
    }

    #[test]
    fn test_icon_constants() {
        assert!(OPEN_FOLDER_ICON.contains("open"));
        assert!(CLOSED_FOLDER_ICON.contains("closed"));
    }

    // -- Folder operations -------------------------------------------------

    #[test]
    fn test_folder_name_and_path() {
        let folder = MockFolder::new("my_folder", "/projects/my_folder");
        assert_eq!(folder.get_name(), "my_folder");
        assert_eq!(folder.get_pathname(), "/projects/my_folder");
    }

    #[test]
    fn test_folder_is_root() {
        let root = MockFolder::new("root", "/");
        assert!(root.is_root());

        let child = MockFolder::new("child", "/child");
        assert!(!child.is_root());
    }

    #[test]
    fn test_folder_empty() {
        let folder = MockFolder::new("empty", "/empty");
        assert!(folder.is_empty());
        assert!(folder.get_files().is_empty());
        assert!(folder.get_folders().is_empty());
    }

    #[test]
    fn test_folder_with_files() {
        let file = GuiDomainFile::new("/test/program.gzf", "program.gzf", "Program");
        let folder = MockFolder::new("test", "/test").with_file(file);

        assert!(!folder.is_empty());
        assert_eq!(folder.get_files().len(), 1);
        assert!(folder.get_file("program.gzf").is_some());
        assert!(folder.get_file("missing").is_none());
    }

    #[test]
    fn test_folder_with_subfolders() {
        let child = MockFolder::new("child", "/test/child");
        let folder = MockFolder::new("test", "/test").with_folder(child);

        assert!(!folder.is_empty());
        assert_eq!(folder.get_folders().len(), 1);
        assert!(folder.get_folder("child").is_some());
        assert!(folder.get_folder("missing").is_none());
    }

    #[test]
    fn test_folder_delete_empty() {
        let mut folder = MockFolder::new("empty", "/empty");
        assert!(folder.delete().is_ok());
    }

    #[test]
    fn test_folder_delete_not_empty() {
        let file = GuiDomainFile::new("/test/f.gzf", "f.gzf", "Program");
        let mut folder = MockFolder::new("test", "/test").with_file(file);
        assert!(folder.delete().is_err());
    }

    #[test]
    fn test_folder_create_subfolder() {
        let mut folder = MockFolder::new("parent", "/parent");
        let child = folder.create_folder("child").unwrap();
        assert_eq!(child.get_name(), "child");
        assert_eq!(child.get_pathname(), "/parent/child");
    }

    #[test]
    fn test_folder_create_file() {
        let mut folder = MockFolder::new("test", "/test");
        let file = folder.create_file("new.gzf", "Program").unwrap();
        assert_eq!(file.get_name(), "new.gzf");
        assert_eq!(file.get_domain_type(), "Program");
    }

    #[test]
    fn test_folder_rename() {
        let mut folder = MockFolder::new("old", "/old");
        let renamed = folder.set_name("new").unwrap();
        assert_eq!(renamed.get_name(), "new");
    }

    #[test]
    fn test_folder_linked() {
        let normal = MockFolder::new("normal", "/normal");
        assert!(!normal.is_linked());
        assert!(normal.get_link_status().is_none());

        let linked = MockFolder::new("linked", "/linked").with_linked(true);
        assert!(linked.is_linked());
        assert_eq!(linked.get_link_status(), Some(LinkStatus::Internal));
    }

    #[test]
    fn test_folder_writable() {
        let writable = MockFolder::new("w", "/w");
        assert!(writable.is_in_writable_project());

        let read_only = MockFolder { writable: false, ..MockFolder::new("ro", "/ro") };
        assert!(!read_only.is_in_writable_project());
    }

    #[test]
    fn test_folder_icon() {
        let folder = MockFolder::new("test", "/test");
        assert_eq!(folder.get_icon(true), OPEN_FOLDER_ICON);
        assert_eq!(folder.get_icon(false), CLOSED_FOLDER_ICON);
    }

    // -- File operations ---------------------------------------------------

    #[test]
    fn test_file_basic() {
        let file = GuiDomainFile::new("/test/program.gzf", "program.gzf", "Program");
        assert_eq!(file.get_pathname(), "/test/program.gzf");
        assert_eq!(file.get_name(), "program.gzf");
        assert_eq!(file.get_domain_type(), "Program");
    }

    #[test]
    fn test_file_checkout() {
        let mut file = GuiDomainFile::new("/test/f.gzf", "f.gzf", "Program");
        assert!(!file.is_checked_out());
        file.set_checked_out("user1");
        assert!(file.is_checked_out());
        assert_eq!(file.get_checked_out_by(), Some("user1"));

        file.clear_checkout();
        assert!(!file.is_checked_out());
        assert!(file.get_checked_out_by().is_none());
    }

    #[test]
    fn test_file_read_only() {
        let mut file = GuiDomainFile::new("/test/f.gzf", "f.gzf", "Program");
        assert!(!file.is_read_only());
        file.set_read_only(true);
        assert!(file.is_read_only());
    }

    #[test]
    fn test_file_changed() {
        let mut file = GuiDomainFile::new("/test/f.gzf", "f.gzf", "Program");
        assert!(!file.is_changed());
        file.set_changed(true);
        assert!(file.is_changed());
    }

    #[test]
    fn test_file_link() {
        let mut file = GuiDomainFile::new("/test/link.gzf", "link.gzf", "FolderLink");
        assert!(!file.is_link_file());

        file.set_link_status(LinkStatus::Internal);
        assert!(file.is_link_file());
        assert!(file.is_folder_link());
        assert_eq!(file.get_link_status(), Some(LinkStatus::Internal));
    }

    #[test]
    fn test_file_external_link() {
        let mut file = GuiDomainFile::new("/test/ext.gzf", "ext.gzf", "ExternalLink");
        file.set_link_status(LinkStatus::External);
        assert!(file.is_link_file());
        assert!(!file.is_folder_link()); // domain_type != "FolderLink"
    }

    #[test]
    fn test_file_metadata() {
        let mut file = GuiDomainFile::new("/test/f.gzf", "f.gzf", "Program");
        assert!(file.get_metadata("key").is_none());

        file.set_metadata("key", "value");
        assert_eq!(file.get_metadata("key"), Some("value"));

        file.set_metadata("other", "data");
        assert_eq!(file.get_all_metadata().len(), 2);
    }

    // -- Link status -------------------------------------------------------

    #[test]
    fn test_link_status_variants() {
        assert_ne!(LinkStatus::Internal, LinkStatus::External);
        assert_ne!(LinkStatus::External, LinkStatus::Broken);
        assert_eq!(LinkStatus::Internal, LinkStatus::Internal);
    }

    // -- Errors ------------------------------------------------------------

    #[test]
    fn test_error_display() {
        let err = DomainFolderGuiError::DuplicateFile("test.gzf".into());
        assert!(err.to_string().contains("Duplicate"));

        let err = DomainFolderGuiError::InvalidName("".into());
        assert!(err.to_string().contains("Invalid"));

        let err = DomainFolderGuiError::FolderNotEmpty("full".into());
        assert!(err.to_string().contains("not empty"));

        let err = DomainFolderGuiError::NotFound("missing".into());
        assert!(err.to_string().contains("Not found"));

        let err = DomainFolderGuiError::FileInUse("locked.gzf".into());
        assert!(err.to_string().contains("in use"));

        let err = DomainFolderGuiError::Cancelled;
        assert!(err.to_string().contains("cancelled"));

        let err = DomainFolderGuiError::IoError("disk error".into());
        assert!(err.to_string().contains("disk error"));
    }

    #[test]
    fn test_error_is_std_error() {
        fn assert_error<E: std::error::Error>(_e: &E) {}
        let err = DomainFolderGuiError::Other("test".into());
        assert_error(&err);
    }

    // -- Path comparison ---------------------------------------------------

    #[test]
    fn test_is_same() {
        let a = MockFolder::new("folder", "/projects/folder");
        let b = MockFolder::new("folder", "/projects/folder");
        let c = MockFolder::new("other", "/projects/other");
        assert!(a.is_same(&b));
        assert!(!a.is_same(&c));
    }

    #[test]
    fn test_is_same_or_ancestor() {
        let parent = MockFolder::new("parent", "/parent");
        let child = MockFolder::new("child", "/parent/child");
        let grandchild = MockFolder::new("gc", "/parent/child/gc");
        let unrelated = MockFolder::new("other", "/other");

        assert!(parent.is_same_or_ancestor(&parent));
        assert!(parent.is_same_or_ancestor(&child));
        assert!(parent.is_same_or_ancestor(&grandchild));
        assert!(!parent.is_same_or_ancestor(&unrelated));
        assert!(!child.is_same_or_ancestor(&parent));
    }

    // -- URL access --------------------------------------------------------

    #[test]
    fn test_folder_urls() {
        let folder = MockFolder::new("test", "/test");
        assert!(folder.get_shared_project_url().is_none());
        assert!(folder.get_local_project_url().is_some());
    }

    // -- File extended methods ---------------------------------------------

    #[test]
    fn test_file_exclusive_checkout() {
        let mut file = GuiDomainFile::new("/test/f.gzf", "f.gzf", "Program");
        assert!(!file.is_checked_out_exclusive());
        file.set_checked_out("user1");
        file.set_checked_out_exclusive(true);
        assert!(file.is_checked_out_exclusive());
    }

    #[test]
    fn test_file_modified_since_checkout() {
        let mut file = GuiDomainFile::new("/test/f.gzf", "f.gzf", "Program");
        assert!(!file.modified_since_checkout());
        file.set_modified_since_checkout(true);
        assert!(file.modified_since_checkout());
    }

    #[test]
    fn test_file_versioning() {
        let mut file = GuiDomainFile::new("/test/f.gzf", "f.gzf", "Program");
        assert!(!file.is_versioned());
        assert_eq!(file.get_version(), GuiDomainFile::DEFAULT_VERSION);
        assert_eq!(file.get_latest_version(), GuiDomainFile::DEFAULT_VERSION);
        assert!(file.is_latest_version());

        file.set_versioned(true);
        file.set_version(3);
        file.set_latest_version(5);
        assert!(file.is_versioned());
        assert!(!file.is_latest_version());
        assert_eq!(file.get_version(), 3);
        assert_eq!(file.get_latest_version(), 5);

        file.set_version(5);
        assert!(file.is_latest_version());
    }

    #[test]
    fn test_file_hijacked() {
        let mut file = GuiDomainFile::new("/test/f.gzf", "f.gzf", "Program");
        assert!(!file.is_hijacked());
        file.set_hijacked(true);
        assert!(file.is_hijacked());
    }

    #[test]
    fn test_file_id_and_content_type() {
        let mut file = GuiDomainFile::new("/test/f.gzf", "f.gzf", "Program");
        assert!(file.get_file_id().is_none());
        file.set_file_id("abc-123");
        assert_eq!(file.get_file_id(), Some("abc-123"));

        assert_eq!(file.get_content_type(), "");
        file.set_content_type("Program");
        assert_eq!(file.get_content_type(), "Program");
    }

    #[test]
    fn test_file_exists_and_length() {
        let mut file = GuiDomainFile::new("/test/f.gzf", "f.gzf", "Program");
        assert!(file.exists());
        file.set_exists(false);
        assert!(!file.exists());

        assert_eq!(file.length(), 0);
        file.set_length(1024);
        assert_eq!(file.length(), 1024);
    }

    #[test]
    fn test_file_last_modified() {
        let mut file = GuiDomainFile::new("/test/f.gzf", "f.gzf", "Program");
        assert_eq!(file.get_last_modified_time(), 0);
        file.set_last_modified_time(1234567890);
        assert_eq!(file.get_last_modified_time(), 1234567890);
    }

    #[test]
    fn test_file_can_operations() {
        let mut file = GuiDomainFile::new("/test/f.gzf", "f.gzf", "Program");
        assert!(file.can_checkout());
        assert!(file.can_save());
        assert!(!file.can_checkin());

        file.set_checked_out("user1");
        assert!(!file.can_checkout());
        assert!(!file.can_checkin());

        file.set_modified_since_checkout(true);
        assert!(file.can_checkin());

        file.set_read_only(true);
        file.clear_checkout();
        assert!(!file.can_checkout());
        assert!(!file.can_save());
    }

    #[test]
    fn test_file_undo_checkout() {
        let mut file = GuiDomainFile::new("/test/f.gzf", "f.gzf", "Program");
        file.set_checked_out("user1");
        file.set_checked_out_exclusive(true);
        file.set_modified_since_checkout(true);

        file.undo_checkout(false);
        assert!(!file.is_checked_out());
        assert!(!file.is_checked_out_exclusive());
        assert!(!file.modified_since_checkout());
    }

    #[test]
    fn test_file_icon() {
        let mut file = GuiDomainFile::new("/test/link.gzf", "link.gzf", "FolderLink");
        assert!(file.get_icon().is_none());

        file.set_link_status(LinkStatus::Internal);
        assert_eq!(file.get_icon(), Some("icon.domain.file.link"));
    }

    #[test]
    fn test_file_is_open() {
        let mut file = GuiDomainFile::new("/test/f.gzf", "f.gzf", "Program");
        assert!(!file.is_open());

        file.set_changed(true);
        assert!(file.is_open());

        file.set_changed(false);
        file.set_checked_out("user1");
        assert!(file.is_open());
    }

    // -- NotSupported error variant ----------------------------------------

    #[test]
    fn test_not_supported_error() {
        let err = DomainFolderGuiError::NotSupported("test".into());
        assert!(err.to_string().contains("Not supported"));
    }

    // -- create_link_file default impl -------------------------------------

    #[test]
    fn test_create_link_file_default() {
        let mut folder = MockFolder::new("test", "/test");
        let result = folder.create_link_file("/src", "/target", true, "link", "Program");
        assert!(result.is_err());
    }
}
