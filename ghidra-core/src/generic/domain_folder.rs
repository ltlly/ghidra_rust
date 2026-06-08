//! Domain folder abstraction for the Ghidra framework.
//!
//! Ports Ghidra's `framework.model.DomainFolder` interface. A `DomainFolder`
//! is a container within a Ghidra project that holds domain files and
//! sub-folders, forming a hierarchical tree structure.

use std::fmt;

use super::domain_file::DomainFile;

// ============================================================================
// DomainFolder trait
// ============================================================================

/// Represents a folder within a Ghidra project.
///
/// Domain folders form a tree structure rooted at the project root. Each
/// folder can contain domain files and sub-folders. This trait provides
/// read access to the folder hierarchy.
pub trait DomainFolder: fmt::Debug + Send + Sync {
    /// Returns the name of this folder (not the full path).
    fn get_name(&self) -> &str;

    /// Returns the full path to this folder (e.g., "/folder/subfolder").
    fn get_pathname(&self) -> &str;

    /// Returns `true` if this is the root folder of the project.
    fn is_root(&self) -> bool;

    /// Returns the parent folder, or `None` if this is the root.
    fn get_parent(&self) -> Option<&dyn DomainFolder>;

    /// Get a child folder by name.
    fn get_folder(&self, name: &str) -> Option<Box<dyn DomainFolder>>;

    /// Get a file within this folder by name.
    fn get_file(&self, name: &str) -> Option<&DomainFile>;

    /// List all files in this folder.
    fn get_files(&self) -> Vec<&DomainFile>;

    /// List all sub-folders.
    fn get_folders(&self) -> Vec<Box<dyn DomainFolder>>;

    /// Returns `true` if this folder contains no files or sub-folders.
    fn is_empty(&self) -> bool {
        self.get_files().is_empty() && self.get_folders().is_empty()
    }

    /// Returns `true` if this folder contains a file with the given name.
    fn contains_file(&self, name: &str) -> bool {
        self.get_file(name).is_some()
    }

    /// Returns `true` if this folder contains a sub-folder with the given name.
    fn contains_folder(&self, name: &str) -> bool {
        self.get_folder(name).is_some()
    }

    /// Returns the number of files in this folder (not recursive).
    fn file_count(&self) -> usize {
        self.get_files().len()
    }

    /// Returns the number of sub-folders in this folder (not recursive).
    fn folder_count(&self) -> usize {
        self.get_folders().len()
    }
}

// ============================================================================
// MutableDomainFolder trait
// ============================================================================

/// A mutable variant of [`DomainFolder`] that supports structural changes.
pub trait MutableDomainFolder: DomainFolder {
    /// Create a new sub-folder with the given name.
    fn create_folder(&mut self, name: &str) -> Result<Box<dyn MutableDomainFolder>, DomainFolderError>;

    /// Create a new file in this folder.
    fn create_file(
        &mut self,
        name: &str,
        domain_type: &str,
    ) -> Result<DomainFile, DomainFolderError>;

    /// Remove a file by name.
    fn remove_file(&mut self, name: &str) -> Result<DomainFile, DomainFolderError>;

    /// Remove a sub-folder by name (must be empty).
    fn remove_folder(&mut self, name: &str) -> Result<(), DomainFolderError>;

    /// Rename this folder.
    fn rename(&mut self, new_name: &str) -> Result<(), DomainFolderError>;

    /// Move a file from this folder to a destination folder.
    fn move_file(
        &mut self,
        file_name: &str,
        dest: &mut dyn MutableDomainFolder,
        new_name: &str,
    ) -> Result<(), DomainFolderError>;
}

// ============================================================================
// DomainFolderError
// ============================================================================

/// Errors that can occur when operating on a domain folder.
#[derive(Debug, Clone)]
pub enum DomainFolderError {
    /// A folder or file with the given name already exists.
    AlreadyExists(String),
    /// The specified item was not found.
    NotFound(String),
    /// The folder is not empty (cannot be removed).
    NotEmpty(String),
    /// The name is invalid.
    InvalidName(String),
    /// An I/O error occurred.
    IoError(String),
    /// A generic error with a message.
    Other(String),
}

impl fmt::Display for DomainFolderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainFolderError::AlreadyExists(name) => {
                write!(f, "Already exists: {}", name)
            }
            DomainFolderError::NotFound(name) => write!(f, "Not found: {}", name),
            DomainFolderError::NotEmpty(name) => {
                write!(f, "Folder not empty: {}", name)
            }
            DomainFolderError::InvalidName(name) => {
                write!(f, "Invalid name: {}", name)
            }
            DomainFolderError::IoError(msg) => write!(f, "I/O error: {}", msg),
            DomainFolderError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for DomainFolderError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestFolder {
        name: String,
        path: String,
        files: Vec<DomainFile>,
        folders: Vec<TestFolder>,
    }

    impl TestFolder {
        fn new(name: &str, path: &str) -> Self {
            Self {
                name: name.to_string(),
                path: path.to_string(),
                files: Vec::new(),
                folders: Vec::new(),
            }
        }
    }

    impl DomainFolder for TestFolder {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_pathname(&self) -> &str {
            &self.path
        }
        fn is_root(&self) -> bool {
            self.path == "/"
        }
        fn get_parent(&self) -> Option<&dyn DomainFolder> {
            None
        }
        fn get_folder(&self, name: &str) -> Option<Box<dyn DomainFolder>> {
            self.folders
                .iter()
                .find(|f| f.name == name)
                .map(|f| Box::new(TestFolder::new(&f.name, &f.path)) as Box<dyn DomainFolder>)
        }
        fn get_file(&self, name: &str) -> Option<&DomainFile> {
            self.files.iter().find(|f| f.get_name() == name)
        }
        fn get_files(&self) -> Vec<&DomainFile> {
            self.files.iter().collect()
        }
        fn get_folders(&self) -> Vec<Box<dyn DomainFolder>> {
            self.folders
                .iter()
                .map(|f| Box::new(TestFolder::new(&f.name, &f.path)) as Box<dyn DomainFolder>)
                .collect()
        }
    }

    #[test]
    fn test_domain_folder_name() {
        let folder = TestFolder::new("my_folder", "/projects/my_folder");
        assert_eq!(folder.get_name(), "my_folder");
        assert_eq!(folder.get_pathname(), "/projects/my_folder");
    }

    #[test]
    fn test_domain_folder_is_root() {
        let root = TestFolder::new("root", "/");
        assert!(root.is_root());

        let child = TestFolder::new("child", "/child");
        assert!(!child.is_root());
    }

    #[test]
    fn test_domain_folder_empty() {
        let folder = TestFolder::new("empty", "/empty");
        assert!(folder.is_empty());
        assert_eq!(folder.file_count(), 0);
        assert_eq!(folder.folder_count(), 0);
    }

    #[test]
    fn test_domain_folder_error_display() {
        let err = DomainFolderError::AlreadyExists("test.txt".to_string());
        assert!(err.to_string().contains("Already exists"));

        let err = DomainFolderError::NotFound("missing".to_string());
        assert!(err.to_string().contains("Not found"));

        let err = DomainFolderError::NotEmpty("full_folder".to_string());
        assert!(err.to_string().contains("not empty"));
    }
}
