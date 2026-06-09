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
    /// The user who has this file checked out.
    checked_out_by: Option<String>,
    /// Whether this file is read-only.
    read_only: bool,
    /// Whether this file has unsaved changes.
    changed: bool,
    /// Link status, if this file is a link-file.
    link_status: Option<LinkStatus>,
    /// Additional metadata key/value pairs.
    metadata: HashMap<String, String>,
}

impl GuiDomainFile {
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
            checked_out_by: None,
            read_only: false,
            changed: false,
            link_status: None,
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
}
