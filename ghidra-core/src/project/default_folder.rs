//! Default folder implementation for project data.
//!
//! Ports `ghidra.framework.data.GhidraFolder` from Java, providing the
//! concrete implementation of [`DomainFolder`] backed by a filesystem
//! directory within a project's `.rep` data store.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use super::model::*;
use super::{DomainFile, DomainFolder, FileMetadata, ProjectError, ProjectLocator, ProjectResult};

// ============================================================================
// DefaultFolder
// ============================================================================

/// Concrete implementation of [`DomainFolder`] backed by a directory on disk.
///
/// In Java: `ghidra.framework.data.GhidraFolder`.
///
/// Each folder maps to a directory in the project's `.rep` data store.
/// Files are tracked via `FolderFileEntry` metadata; sub-folders are
/// discovered from the directory listing.
pub struct DefaultFolder {
    /// The absolute path to this folder on disk.
    path: PathBuf,
    /// The project locator.
    locator: ProjectLocator,
    /// The relative pathname within the project (e.g., "/" for root, "/subdir").
    pathname: String,
    /// Whether this is the root folder.
    is_root: bool,
    /// In-memory metadata cache for child files.
    file_cache: RwLock<HashMap<String, FolderFileEntry>>,
    /// List of registered change listeners.
    listeners: RwLock<Vec<Arc<dyn DomainFolderChangeListener>>>,
}

/// Internal metadata for a file tracked by a folder.
#[derive(Debug, Clone)]
pub struct FolderFileEntry {
    /// File name within the folder.
    pub name: String,
    /// Full pathname within the project.
    pub pathname: String,
    /// Content type (e.g., "Program", "DataTypeArchive").
    pub content_type: String,
    /// Unique file ID.
    pub file_id: Option<String>,
    /// File metadata.
    pub metadata: FileMetadata,
}

impl FolderFileEntry {
    /// Create a new file entry.
    pub fn new(
        name: impl Into<String>,
        pathname: impl Into<String>,
        content_type: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            pathname: pathname.into(),
            content_type: content_type.into(),
            file_id: None,
            metadata: FileMetadata::default(),
        }
    }

    /// Set the file ID.
    pub fn with_file_id(mut self, file_id: impl Into<String>) -> Self {
        self.file_id = Some(file_id.into());
        self
    }
}

impl DefaultFolder {
    /// Create a new `DefaultFolder` at the given path.
    pub fn new(path: impl Into<PathBuf>, locator: ProjectLocator, pathname: impl Into<String>) -> Self {
        let pathname = pathname.into();
        let is_root = pathname == "/";
        Self {
            path: path.into(),
            locator,
            pathname,
            is_root,
            file_cache: RwLock::new(HashMap::new()),
            listeners: RwLock::new(Vec::new()),
        }
    }

    /// Create the root folder for a project.
    pub fn root(project_path: impl Into<PathBuf>, locator: ProjectLocator) -> Self {
        let project_path = project_path.into();
        Self::new(project_path.join("data"), locator, "/")
    }

    /// The absolute path to this folder on disk.
    pub fn disk_path(&self) -> &Path {
        &self.path
    }

    /// Add a file entry to this folder's cache.
    pub fn add_file_entry(&self, entry: FolderFileEntry) {
        let mut cache = self.file_cache.write().unwrap();
        cache.insert(entry.name.clone(), entry);
    }

    /// Remove a file entry from this folder's cache.
    pub fn remove_file_entry(&self, name: &str) -> Option<FolderFileEntry> {
        let mut cache = self.file_cache.write().unwrap();
        cache.remove(name)
    }

    /// Look up a file entry by name.
    pub fn get_file_entry(&self, name: &str) -> Option<FolderFileEntry> {
        let cache = self.file_cache.read().unwrap();
        cache.get(name).cloned()
    }

    /// List all file entries cached in this folder.
    pub fn file_entries(&self) -> Vec<FolderFileEntry> {
        let cache = self.file_cache.read().unwrap();
        cache.values().cloned().collect()
    }

    /// Number of cached file entries.
    pub fn file_count(&self) -> usize {
        let cache = self.file_cache.read().unwrap();
        cache.len()
    }

    /// Ensure the directory exists on disk.
    pub fn ensure_exists(&self) -> ProjectResult<()> {
        if !self.path.exists() {
            fs::create_dir_all(&self.path)?;
        }
        Ok(())
    }

    /// Create a child sub-folder on disk.
    pub fn create_child_folder(&self, name: &str) -> ProjectResult<DefaultFolder> {
        let child_path = self.path.join(name);
        if child_path.exists() {
            return Err(ProjectError::AlreadyExists(child_path));
        }
        fs::create_dir_all(&child_path)?;

        let child_pathname = if self.is_root {
            format!("/{}", name)
        } else {
            format!("{}/{}", self.pathname, name)
        };

        Ok(DefaultFolder::new(child_path, self.locator.clone(), child_pathname))
    }

    /// Discover child folders from the directory listing.
    pub fn discover_subfolders(&self) -> ProjectResult<Vec<DefaultFolder>> {
        let mut result = Vec::new();
        if !self.path.is_dir() {
            return Ok(result);
        }
        let entries = fs::read_dir(&self.path)?;
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_dir() {
                let name = entry_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_owned();
                let child_pathname = if self.is_root {
                    format!("/{}", name)
                } else {
                    format!("{}/{}", self.pathname, name)
                };
                result.push(DefaultFolder::new(
                    entry_path,
                    self.locator.clone(),
                    child_pathname,
                ));
            }
        }
        Ok(result)
    }

    /// Register a change listener.
    pub fn add_listener(&self, listener: Arc<dyn DomainFolderChangeListener>) {
        let mut listeners = self.listeners.write().unwrap();
        listeners.push(listener);
    }

    /// Notify listeners that a folder was added.
    pub fn fire_folder_added(&self, folder_path: &str) {
        let listeners = self.listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.domain_folder_added(folder_path);
        }
    }

    /// Notify listeners that a file was added.
    pub fn fire_file_added(&self, file_path: &str) {
        let listeners = self.listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.domain_file_added(file_path);
        }
    }

    /// Notify listeners that a folder was removed.
    pub fn fire_folder_removed(&self, parent_path: &str, name: &str) {
        let listeners = self.listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.domain_folder_removed(parent_path, name);
        }
    }

    /// Notify listeners that a file was removed.
    pub fn fire_file_removed(&self, parent_path: &str, name: &str, file_id: Option<&str>) {
        let listeners = self.listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.domain_file_removed(parent_path, name, file_id);
        }
    }

    /// Notify listeners that a folder was renamed.
    pub fn fire_folder_renamed(&self, folder_path: &str, old_name: &str) {
        let listeners = self.listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.domain_folder_renamed(folder_path, old_name);
        }
    }

    /// Notify listeners that a file was renamed.
    pub fn fire_file_renamed(&self, file_path: &str, old_name: &str) {
        let listeners = self.listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.domain_file_renamed(file_path, old_name);
        }
    }

    /// Delete this folder from disk (must be empty).
    pub fn delete_from_disk(&self) -> ProjectResult<()> {
        if self.is_root {
            return Err(ProjectError::InvalidState(
                "Cannot delete the root folder".into(),
            ));
        }
        // Check if empty (no subdirs, no cached files)
        let cache = self.file_cache.read().unwrap();
        if !cache.is_empty() {
            return Err(ProjectError::InvalidState(
                "Folder is not empty (contains files)".into(),
            ));
        }
        drop(cache);

        let entries = fs::read_dir(&self.path)?;
        if entries.count() > 0 {
            return Err(ProjectError::InvalidState(
                "Folder is not empty (contains subdirectories)".into(),
            ));
        }

        fs::remove_dir(&self.path)?;
        Ok(())
    }
}

impl fmt::Debug for DefaultFolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultFolder")
            .field("path", &self.path)
            .field("pathname", &self.pathname)
            .field("is_root", &self.is_root)
            .field("locator", &self.locator)
            .finish()
    }
}

// ============================================================================
// DomainFolder impl for DefaultFolder
// ============================================================================

impl DomainFolder for DefaultFolder {
    fn name(&self) -> &str {
        if self.is_root {
            ""
        } else {
            self.path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
        }
    }

    fn pathname(&self) -> &str {
        &self.pathname
    }

    fn project_locator(&self) -> &ProjectLocator {
        &self.locator
    }

    fn is_root(&self) -> bool {
        self.is_root
    }

    fn files(&self) -> ProjectResult<Vec<Box<dyn DomainFile>>> {
        // Return empty -- concrete file objects require a full DomainFile impl.
        Ok(Vec::new())
    }

    fn folders(&self) -> ProjectResult<Vec<Box<dyn DomainFolder>>> {
        // Return empty -- would need to construct DefaultFolder from disk entries.
        Ok(Vec::new())
    }
}

// ============================================================================
// DomainFolder2 impl for DefaultFolder
// ============================================================================

impl DomainFolder2 for DefaultFolder {
    fn name(&self) -> &str {
        if self.is_root {
            ""
        } else {
            self.path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
        }
    }

    fn pathname(&self) -> &str {
        &self.pathname
    }

    fn project_locator(&self) -> &ProjectLocator {
        &self.locator
    }

    fn is_root(&self) -> bool {
        self.is_root
    }

    fn is_in_writable_project(&self) -> bool {
        // Assume writable unless a read-only marker is found.
        !self.path.join(".read_only").exists()
    }

    fn is_linked(&self) -> bool {
        // Check for link marker file.
        self.path.join(".link").exists()
    }

    fn parent_path(&self) -> Option<String> {
        if self.is_root {
            None
        } else {
            let parent = self.path.parent().unwrap_or(&self.path);
            let parent_name = parent
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            Some(format!("/{}", parent_name))
        }
    }

    fn is_empty(&self) -> bool {
        let cache = self.file_cache.read().unwrap();
        if !cache.is_empty() {
            return false;
        }
        // Also check if directory is empty on disk.
        fs::read_dir(&self.path)
            .map(|entries| entries.count() == 0)
            .unwrap_or(true)
    }

    fn get_folder(&self, name: &str) -> Option<String> {
        let child_path = self.path.join(name);
        if child_path.is_dir() {
            Some(if self.is_root {
                format!("/{}", name)
            } else {
                format!("{}/{}", self.pathname, name)
            })
        } else {
            None
        }
    }

    fn get_file(&self, name: &str) -> Option<String> {
        let cache = self.file_cache.read().unwrap();
        cache.get(name).map(|entry| entry.pathname.clone())
    }

    fn folder_paths(&self) -> ProjectResult<Vec<String>> {
        let mut result = Vec::new();
        if !self.path.is_dir() {
            return Ok(result);
        }
        for entry in fs::read_dir(&self.path)?.flatten() {
            if entry.path().is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                let path = if self.is_root {
                    format!("/{}", name)
                } else {
                    format!("{}/{}", self.pathname, name)
                };
                result.push(path);
            }
        }
        Ok(result)
    }

    fn file_paths(&self) -> ProjectResult<Vec<String>> {
        let cache = self.file_cache.read().unwrap();
        Ok(cache.values().map(|e| e.pathname.clone()).collect())
    }

    fn create_folder(&self, name: &str) -> ProjectResult<String> {
        let child = self.create_child_folder(name)?;
        let child_pathname = child.pathname.clone();
        self.fire_folder_added(&child_pathname);
        Ok(child_pathname)
    }

    fn delete(&self) -> ProjectResult<()> {
        self.delete_from_disk()
    }

    fn set_active(&self) {
        // Notify listeners that this folder is now active.
        self.fire_folder_added(&self.pathname);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Arc;

    fn temp_base() -> PathBuf {
        let mut d = env::temp_dir();
        d.push(format!("ghidra_default_folder_test_{}", std::process::id()));
        d
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_folder_creation() {
        let base = temp_base().join("create");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let folder = DefaultFolder::root(&base.join("test_project"), locator);
        folder.ensure_exists().unwrap();
        assert!(folder.disk_path().exists());
        assert!(DomainFolder::is_root(&folder));
        assert_eq!(DomainFolder::pathname(&folder), "/");

        cleanup(&base);
    }

    #[test]
    fn test_folder_child_creation() {
        let base = temp_base().join("child");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let root = DefaultFolder::root(&base.join("test_project"), locator);
        root.ensure_exists().unwrap();

        let sub = root.create_child_folder("analysis").unwrap();
        assert_eq!(DomainFolder::pathname(&sub), "/analysis");
        assert!(!DomainFolder::is_root(&sub));
        assert!(sub.disk_path().exists());

        cleanup(&base);
    }

    #[test]
    fn test_folder_duplicate_child_fails() {
        let base = temp_base().join("dup");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let root = DefaultFolder::root(&base.join("test_project"), locator);
        root.ensure_exists().unwrap();

        let _ = root.create_child_folder("dup_folder");
        let result = root.create_child_folder("dup_folder");
        assert!(matches!(result, Err(ProjectError::AlreadyExists(_))));

        cleanup(&base);
    }

    #[test]
    fn test_folder_file_entries() {
        let base = temp_base().join("entries");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let folder = DefaultFolder::root(&base.join("test_project"), locator);

        let entry = FolderFileEntry::new("test.gzf", "/test.gzf", "Program");
        folder.add_file_entry(entry);

        assert_eq!(folder.file_count(), 1);
        let found = folder.get_file_entry("test.gzf");
        assert!(found.is_some());
        assert_eq!(found.unwrap().content_type, "Program");

        let removed = folder.remove_file_entry("test.gzf");
        assert!(removed.is_some());
        assert_eq!(folder.file_count(), 0);

        cleanup(&base);
    }

    #[test]
    fn test_folder_discover_subfolders() {
        let base = temp_base().join("discover");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let root = DefaultFolder::root(&base.join("test_project"), locator);
        root.ensure_exists().unwrap();

        root.create_child_folder("a").unwrap();
        root.create_child_folder("b").unwrap();
        root.create_child_folder("c").unwrap();

        let subs = root.discover_subfolders().unwrap();
        let mut names: Vec<String> = subs.iter().map(|f| f.name().to_string()).collect();
        names.sort();
        assert_eq!(names, vec!["a", "b", "c"]);

        cleanup(&base);
    }

    #[test]
    fn test_folder_delete_root_fails() {
        let base = temp_base().join("del_root");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let root = DefaultFolder::root(&base.join("test_project"), locator);
        root.ensure_exists().unwrap();

        let result = root.delete_from_disk();
        assert!(matches!(result, Err(ProjectError::InvalidState(_))));

        cleanup(&base);
    }

    #[test]
    fn test_folder_delete_empty_child() {
        let base = temp_base().join("del_child");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let root = DefaultFolder::root(&base.join("test_project"), locator);
        root.ensure_exists().unwrap();

        let child = root.create_child_folder("to_delete").unwrap();
        assert!(child.disk_path().exists());

        child.delete_from_disk().unwrap();
        assert!(!child.disk_path().exists());

        cleanup(&base);
    }

    #[test]
    fn test_domain_folder_trait() {
        let base = temp_base().join("trait_test");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let root = DefaultFolder::root(&base.join("test_project"), locator);
        // Use DomainFolder trait explicitly to avoid ambiguity with DomainFolder2.
        assert!(DomainFolder::is_root(&root));
        assert_eq!(DomainFolder::pathname(&root), "/");
        assert_eq!(DomainFolder::project_locator(&root).project_name, "test_project");

        cleanup(&base);
    }

    #[test]
    fn test_domain_folder2_trait() {
        let base = temp_base().join("trait2_test");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let root = DefaultFolder::root(&base.join("test_project"), locator);
        root.ensure_exists().unwrap();

        // Use DomainFolder2 trait explicitly to avoid ambiguity with DomainFolder.
        assert!(DomainFolder2::is_empty(&root));
        assert!(DomainFolder2::is_in_writable_project(&root));
        assert!(!DomainFolder2::is_linked(&root));
        assert!(DomainFolder2::parent_path(&root).is_none());

        cleanup(&base);
    }

    #[test]
    fn test_folder_listener() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let base = temp_base().join("listener");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let folder = DefaultFolder::root(&base.join("test_project"), locator);

        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();

        #[derive(Debug)]
        struct TestListener {
            count: Arc<AtomicUsize>,
        }
        impl DomainFolderChangeListener for TestListener {
            fn domain_folder_added(&self, _folder_path: &str) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
            fn domain_file_added(&self, _file_path: &str) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }

        folder.add_listener(Arc::new(TestListener { count: count_clone }));
        folder.fire_folder_added("/test");
        folder.fire_file_added("/test/file.gzf");
        assert_eq!(count.load(Ordering::SeqCst), 2);

        cleanup(&base);
    }
}
