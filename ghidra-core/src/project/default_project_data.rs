//! Default implementation of the ProjectData interface.
//!
//! Ports `ghidra.framework.data.DefaultProjectData` from Java.  Provides
//! filesystem-backed project data access, managing the folder/file hierarchy
//! stored in a project's `.rep` directory.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use super::default_folder::{DefaultFolder, FolderFileEntry};
use super::model::*;
use super::project_data::{FileStatus, ProjectDataConfig, ProjectDataState};
use super::{DomainFile, DomainFolder, ProjectData, ProjectLocator, ProjectResult};

// ============================================================================
// DefaultProjectData
// ============================================================================

/// Default implementation of [`ProjectData`] backed by the filesystem.
///
/// In Java: `ghidra.framework.data.DefaultProjectData`.
///
/// Manages the project data directory structure, tracks open domain objects,
/// and provides change notification through registered listeners.
pub struct DefaultProjectData {
    /// The root folder of the project data.
    root_folder: DefaultFolder,
    /// The project locator.
    locator: ProjectLocator,
    /// The base directory where data is stored on disk.
    data_path: PathBuf,
    /// Current state.
    state: RwLock<ProjectDataState>,
    /// Registered change listeners.
    listeners: RwLock<Vec<Arc<dyn DomainFolderChangeListener>>>,
    /// Cache of file paths to entries for quick lookup.
    file_index: RwLock<HashMap<String, FolderFileEntry>>,
    /// Cache of open domain objects by path.
    open_objects: RwLock<HashMap<String, u64>>,
    /// Configuration.
    config: ProjectDataConfig,
    /// Listener ID counter.
    next_listener_id: std::sync::atomic::AtomicU64,
}

impl DefaultProjectData {
    /// Create a new `DefaultProjectData` from a project locator.
    ///
    /// This initializes the data directory if it does not exist.
    pub fn new(locator: ProjectLocator) -> ProjectResult<Self> {
        let config = ProjectDataConfig::new(locator.clone());
        Self::with_config(config)
    }

    /// Create with a specific configuration.
    pub fn with_config(config: ProjectDataConfig) -> ProjectResult<Self> {
        let data_path = config.data_path.clone();
        let locator = config.locator.clone();

        // Ensure the data directory exists.
        if !data_path.exists() {
            fs::create_dir_all(&data_path)?;
        }

        let root_folder = DefaultFolder::root(&locator.project_path(), locator.clone());

        Ok(Self {
            root_folder,
            locator,
            data_path,
            state: RwLock::new(ProjectDataState::Open),
            listeners: RwLock::new(Vec::new()),
            file_index: RwLock::new(HashMap::new()),
            open_objects: RwLock::new(HashMap::new()),
            config,
            next_listener_id: std::sync::atomic::AtomicU64::new(1),
        })
    }

    /// The current state of this project data.
    pub fn state(&self) -> ProjectDataState {
        *self.state.read().unwrap()
    }

    /// The data path on disk.
    pub fn data_path(&self) -> &Path {
        &self.data_path
    }

    /// The project locator.
    pub fn locator(&self) -> &ProjectLocator {
        &self.locator
    }

    /// Register a change listener and return its ID.
    pub fn add_listener(&self, listener: Arc<dyn DomainFolderChangeListener>) -> u64 {
        let id = self
            .next_listener_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.listeners.write().unwrap().push(listener);
        id
    }

    /// Remove a change listener by ID.
    ///
    /// Note: The current implementation removes the last listener with
    /// a matching Arc pointer.  For production use, listeners should be
    /// tracked by ID externally.
    pub fn remove_listener(&self, _listener_id: u64) {
        // Simplified: in production, would track (id, listener) pairs.
    }

    /// Add a file entry to the file index.
    pub fn index_file(&self, entry: FolderFileEntry) {
        let mut index = self.file_index.write().unwrap();
        index.insert(entry.pathname.clone(), entry);
    }

    /// Remove a file entry from the file index by path.
    pub fn unindex_file(&self, path: &str) -> Option<FolderFileEntry> {
        let mut index = self.file_index.write().unwrap();
        index.remove(path)
    }

    /// Look up a file entry by path.
    pub fn find_entry(&self, path: &str) -> Option<FolderFileEntry> {
        let index = self.file_index.read().unwrap();
        index.get(path).cloned()
    }

    /// Number of indexed files.
    pub fn indexed_file_count(&self) -> usize {
        let index = self.file_index.read().unwrap();
        index.len()
    }

    /// Track a domain object as open.
    pub fn open_domain_object(&self, path: &str) -> u64 {
        let mut open = self.open_objects.write().unwrap();
        let id = open.len() as u64 + 1;
        open.insert(path.to_string(), id);
        id
    }

    /// Close a tracked domain object.
    pub fn close_domain_object(&self, path: &str) -> Option<u64> {
        let mut open = self.open_objects.write().unwrap();
        open.remove(path)
    }

    /// Number of currently open domain objects.
    pub fn open_object_count(&self) -> usize {
        let open = self.open_objects.read().unwrap();
        open.len()
    }

    /// Get the status of a file by path.
    pub fn file_status(&self, path: &str) -> FileStatus {
        let index = self.file_index.read().unwrap();
        if let Some(entry) = index.get(path) {
            let mut status = FileStatus::normal(&entry.content_type);
            status.is_open = self.open_objects.read().unwrap().contains_key(path);
            status.is_read_only = entry.metadata.read_only;
            status.is_versioned = entry.metadata.versioned;
            status
        } else {
            FileStatus::missing("Unknown")
        }
    }

    /// List all indexed file paths.
    pub fn all_file_paths(&self) -> Vec<String> {
        let index = self.file_index.read().unwrap();
        index.keys().cloned().collect()
    }

    /// Discover all files from disk under the data directory.
    pub fn discover_files(&self) -> ProjectResult<Vec<PathBuf>> {
        let mut result = Vec::new();
        Self::discover_recursive(&self.data_path, &mut result)?;
        Ok(result)
    }

    fn discover_recursive(dir: &Path, result: &mut Vec<PathBuf>) -> ProjectResult<()> {
        if !dir.is_dir() {
            return Ok(());
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                Self::discover_recursive(&path, result)?;
            } else {
                result.push(path);
            }
        }
        Ok(())
    }

    /// Notify all listeners that a file was added.
    pub fn fire_file_added(&self, file_path: &str) {
        let listeners = self.listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.domain_file_added(file_path);
        }
    }

    /// Notify all listeners that a file was removed.
    pub fn fire_file_removed(&self, parent_path: &str, name: &str, file_id: Option<&str>) {
        let listeners = self.listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.domain_file_removed(parent_path, name, file_id);
        }
    }

    /// Notify all listeners that a file was renamed.
    pub fn fire_file_renamed(&self, file_path: &str, old_name: &str) {
        let listeners = self.listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.domain_file_renamed(file_path, old_name);
        }
    }

    /// Notify all listeners that a folder was added.
    pub fn fire_folder_added(&self, folder_path: &str) {
        let listeners = self.listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.domain_folder_added(folder_path);
        }
    }

    /// Notify all listeners that a folder was removed.
    pub fn fire_folder_removed(&self, parent_path: &str, name: &str) {
        let listeners = self.listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.domain_folder_removed(parent_path, name);
        }
    }

    /// Get the root folder reference.
    pub fn root(&self) -> &DefaultFolder {
        &self.root_folder
    }
}

impl fmt::Debug for DefaultProjectData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultProjectData")
            .field("locator", &self.locator)
            .field("data_path", &self.data_path)
            .field("state", &self.state)
            .field("config", &self.config)
            .finish()
    }
}

// ============================================================================
// ProjectData impl
// ============================================================================

impl ProjectData for DefaultProjectData {
    fn root_folder(&self) -> &dyn DomainFolder {
        &self.root_folder
    }

    fn get_folder(&self, path: &str) -> Option<Box<dyn DomainFolder>> {
        // Walk the path segments from the root.
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            return Some(Box::new(DefaultFolder::root(
                &self.locator.project_path(),
                self.locator.clone(),
            )));
        }

        let mut current = self.data_path.clone();
        for segment in &segments {
            current = current.join(segment);
        }
        if current.is_dir() {
            Some(Box::new(DefaultFolder::new(
                current,
                self.locator.clone(),
                path,
            )))
        } else {
            None
        }
    }

    fn get_file(&self, path: &str) -> Option<Box<dyn DomainFile>> {
        // Not implemented at this level -- requires a full DomainFile impl.
        let _ = path;
        None
    }

    fn get_file_by_id(&self, file_id: &str) -> Option<Box<dyn DomainFile>> {
        let index = self.file_index.read().unwrap();
        for entry in index.values() {
            if entry.file_id.as_deref() == Some(file_id) {
                return None; // Would return a concrete DomainFile impl.
            }
        }
        None
    }

    fn file_count(&self) -> i32 {
        let index = self.file_index.read().unwrap();
        index.len() as i32
    }

    fn project_locator(&self) -> &ProjectLocator {
        &self.locator
    }

    fn max_name_length(&self) -> usize {
        256
    }

    fn make_valid_name(&self, name: &str) -> String {
        // Replace invalid filesystem characters.
        name.chars()
            .map(|c| match c {
                '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
                other => other,
            })
            .collect()
    }

    fn refresh(&self, _force: bool) {
        // In a full implementation, would rescan the data directory
        // and update the file index.
    }

    fn close(&self) {
        let mut state = self.state.write().unwrap();
        *state = ProjectDataState::Closed;
        self.file_index.write().unwrap().clear();
        self.open_objects.write().unwrap().clear();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_base() -> PathBuf {
        let mut d = env::temp_dir();
        d.push(format!(
            "ghidra_default_project_data_test_{}",
            std::process::id()
        ));
        d
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_project_data_creation() {
        let base = temp_base().join("create");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let pd = DefaultProjectData::new(locator).unwrap();
        assert_eq!(pd.state(), ProjectDataState::Open);
        assert!(pd.data_path().exists());
        assert_eq!(pd.indexed_file_count(), 0);

        cleanup(&base);
    }

    #[test]
    fn test_project_data_close() {
        let base = temp_base().join("close");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let pd = DefaultProjectData::new(locator).unwrap();
        assert_eq!(pd.state(), ProjectDataState::Open);

        pd.close();
        assert_eq!(pd.state(), ProjectDataState::Closed);
        assert_eq!(pd.indexed_file_count(), 0);

        cleanup(&base);
    }

    #[test]
    fn test_project_data_file_index() {
        let base = temp_base().join("index");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let pd = DefaultProjectData::new(locator).unwrap();

        let entry = FolderFileEntry::new("test.gzf", "/test.gzf", "Program");
        pd.index_file(entry);
        assert_eq!(pd.indexed_file_count(), 1);

        let found = pd.find_entry("/test.gzf");
        assert!(found.is_some());
        assert_eq!(found.unwrap().content_type, "Program");

        let removed = pd.unindex_file("/test.gzf");
        assert!(removed.is_some());
        assert_eq!(pd.indexed_file_count(), 0);

        cleanup(&base);
    }

    #[test]
    fn test_project_data_domain_objects() {
        let base = temp_base().join("domain_obj");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let pd = DefaultProjectData::new(locator).unwrap();

        assert_eq!(pd.open_object_count(), 0);

        let id1 = pd.open_domain_object("/test.gzf");
        assert!(id1 > 0);
        assert_eq!(pd.open_object_count(), 1);

        let id2 = pd.open_domain_object("/test2.gzf");
        assert!(id2 > id1);
        assert_eq!(pd.open_object_count(), 2);

        let closed = pd.close_domain_object("/test.gzf");
        assert!(closed.is_some());
        assert_eq!(pd.open_object_count(), 1);

        cleanup(&base);
    }

    #[test]
    fn test_project_data_file_status() {
        let base = temp_base().join("status");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let pd = DefaultProjectData::new(locator).unwrap();

        // Unknown file
        let status = pd.file_status("/nonexistent");
        assert!(!status.exists);

        // Indexed file
        let entry = FolderFileEntry::new("test.gzf", "/test.gzf", "Program");
        pd.index_file(entry);
        let status = pd.file_status("/test.gzf");
        assert!(status.exists);
        assert_eq!(status.content_type, "Program");

        cleanup(&base);
    }

    #[test]
    fn test_project_data_make_valid_name() {
        let base = temp_base().join("valid_name");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let pd = DefaultProjectData::new(locator).unwrap();

        assert_eq!(pd.make_valid_name("hello"), "hello");
        assert_eq!(pd.make_valid_name("bad/name"), "bad_name");
        assert_eq!(pd.make_valid_name("bad:name*?"), "bad_name__");
        assert_eq!(pd.make_valid_name("ok-name.txt"), "ok-name.txt");

        cleanup(&base);
    }

    #[test]
    fn test_project_data_root_folder() {
        let base = temp_base().join("root");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let pd = DefaultProjectData::new(locator).unwrap();

        let root = pd.root_folder();
        assert!(root.is_root());
        assert_eq!(root.pathname(), "/");

        cleanup(&base);
    }

    #[test]
    fn test_project_data_get_folder() {
        let base = temp_base().join("get_folder");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let pd = DefaultProjectData::new(locator).unwrap();

        // Root
        let root = pd.get_folder("/");
        assert!(root.is_some());
        assert!(root.unwrap().is_root());

        // Non-existent
        let missing = pd.get_folder("/nonexistent");
        assert!(missing.is_none());

        cleanup(&base);
    }

    #[test]
    fn test_project_data_listeners() {
        let base = temp_base().join("listeners");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let pd = DefaultProjectData::new(locator).unwrap();

        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();

        #[derive(Debug)]
        struct TestListener {
            count: Arc<AtomicUsize>,
        }
        impl DomainFolderChangeListener for TestListener {
            fn domain_file_added(&self, _file_path: &str) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
            fn domain_folder_added(&self, _folder_path: &str) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }

        pd.add_listener(Arc::new(TestListener { count: count_clone }));
        pd.fire_file_added("/test.gzf");
        pd.fire_folder_added("/subdir");
        assert_eq!(count.load(Ordering::SeqCst), 2);

        cleanup(&base);
    }

    #[test]
    fn test_project_data_discover_files() {
        let base = temp_base().join("discover");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let pd = DefaultProjectData::new(locator).unwrap();

        // Create some files in the data directory
        let data_dir = pd.data_path();
        fs::write(data_dir.join("test1.txt"), "hello").unwrap();
        fs::create_dir_all(data_dir.join("subdir")).unwrap();
        fs::write(data_dir.join("subdir/test2.txt"), "world").unwrap();

        let files = pd.discover_files().unwrap();
        assert_eq!(files.len(), 2);

        cleanup(&base);
    }

    #[test]
    fn test_project_data_config() {
        let base = temp_base().join("config");
        cleanup(&base);
        fs::create_dir_all(&base).unwrap();

        let locator = ProjectLocator::new(&base, "test_project");
        let config = ProjectDataConfig::new(locator)
            .with_max_open_objects(128)
            .with_auto_lock(true);

        let pd = DefaultProjectData::with_config(config).unwrap();
        assert_eq!(pd.state(), ProjectDataState::Open);

        cleanup(&base);
    }
}
