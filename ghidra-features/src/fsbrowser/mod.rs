//! File System Browser plugin and batch import framework.
//!
//! Ported from Ghidra's `ghidra.plugins.fsbrowser` and
//! `ghidra.plugins.importer.batch` Java packages.
//!
//! Provides a tree-based file system browser for navigating container files
//! (zips, tars, filesystem images) and a batch import framework for importing
//! multiple binary files at once, segregating them by loader and architecture.
//!
//! # Key Types
//!
//! - [`FsBrowserPlugin`] -- Plugin managing filesystem browser windows
//! - [`FsBrowserComponentProvider`] -- A single browser window instance
//! - [`FsBrowserNode`] -- Base class for tree nodes in the browser
//! - [`FsFileNode`] -- Node representing a file in a filesystem
//! - [`FsDirNode`] -- Node representing a directory in a filesystem
//! - [`FsRootNode`] -- Root node representing a mounted filesystem
//! - [`FsFileHandler`] -- Extension point for adding actions to files
//! - [`BatchInfo`] -- State for a batch import operation
//! - [`BatchGroup`] -- A group of files sharing the same loader and architecture
//! - [`BatchGroupLoadSpec`] -- Load spec for a batch group
//! - [`BatchSegregatingCriteria`] -- Criteria for grouping files during batch import
//! - [`BatchImportTableModel`] -- Table model for displaying batch import state

pub mod batch;
pub mod handlers;
pub mod node;
pub mod plugin;
pub mod provider;

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

// ---------------------------------------------------------------------------
// FSRL -- File System Resource Locator
// ---------------------------------------------------------------------------

/// A unique identifier for a file within a (possibly nested) filesystem.
///
/// Ported from `ghidra.formats.gfilesystem.FSRL`.  This lightweight
/// representation uses a string-based scheme so it works without pulling in
/// the full GFileSystem stack.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fsrl {
    /// The full URI string (e.g. `file:///tmp/archive.zip|zipfs:/inner.bin`).
    pub uri: String,
    /// The human-readable name (last path component).
    pub name: String,
}

impl Fsrl {
    /// Create a new FSRL from a URI and name.
    pub fn new(uri: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            name: name.into(),
        }
    }

    /// Get the file extension (lowercase, without dot).
    pub fn extension(&self) -> &str {
        self.name
            .rfind('.')
            .map(|i| &self.name[i + 1..])
            .unwrap_or("")
    }
}

impl fmt::Display for Fsrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.uri)
    }
}

// ---------------------------------------------------------------------------
// GFile -- lightweight file representation inside a GFileSystem
// ---------------------------------------------------------------------------

/// Represents a file entry inside a mounted [`GFileSystem`].
///
/// Ported from `ghidra.formats.gfilesystem.GFile`.
#[derive(Debug, Clone)]
pub struct GFile {
    /// The filesystem-relative name.
    pub name: String,
    /// The FSRL of this file.
    pub fsrl: Fsrl,
    /// Whether this entry is a directory.
    pub is_directory: bool,
    /// Size in bytes (0 for directories or unknown).
    pub size: u64,
    /// Child entries (populated lazily for directories).
    pub children: Vec<GFile>,
}

impl GFile {
    /// Create a new file entry.
    pub fn new(name: impl Into<String>, fsrl: Fsrl, is_directory: bool, size: u64) -> Self {
        Self {
            name: name.into(),
            fsrl,
            is_directory,
            size,
            children: Vec::new(),
        }
    }

    /// Create a directory entry.
    pub fn directory(name: impl Into<String>, fsrl: Fsrl) -> Self {
        Self::new(name, fsrl, true, 0)
    }

    /// Create a file entry.
    pub fn file(name: impl Into<String>, fsrl: Fsrl, size: u64) -> Self {
        Self::new(name, fsrl, false, size)
    }
}

// ---------------------------------------------------------------------------
// GFileSystem -- mounted filesystem
// ---------------------------------------------------------------------------

/// A mounted file system that can be browsed.
///
/// Ported from `ghidra.formats.gfilesystem.GFileSystem`.
#[derive(Debug, Clone)]
pub struct GFileSystem {
    /// The FSRL root for this filesystem.
    pub fsrl_root: Fsrl,
    /// Human-readable filesystem type name (e.g. "ZIP", "TAR", "SquashFS").
    pub fs_type: String,
    /// The root directory of this filesystem.
    pub root: GFile,
    /// Whether the filesystem has been fully enumerated.
    pub populated: bool,
}

impl GFileSystem {
    /// Create a new filesystem.
    pub fn new(fsrl_root: Fsrl, fs_type: impl Into<String>, root: GFile) -> Self {
        Self {
            fsrl_root,
            fs_type: fs_type.into(),
            root,
            populated: false,
        }
    }

    /// Get the filesystem type name.
    pub fn fs_type(&self) -> &str {
        &self.fs_type
    }

    /// Get the root directory.
    pub fn root(&self) -> &GFile {
        &self.root
    }
}

// ---------------------------------------------------------------------------
// FileSystemRef -- reference-counted filesystem handle
// ---------------------------------------------------------------------------

/// A reference-counted handle to a [`GFileSystem`].
///
/// Ported from `ghidra.formats.gfilesystem.FileSystemRef`.
#[derive(Debug, Clone)]
pub struct FileSystemRef {
    /// The filesystem.
    pub filesystem: Arc<RwLock<GFileSystem>>,
    /// Reference count.
    ref_count: Arc<Mutex<u32>>,
}

impl FileSystemRef {
    /// Create a new reference.
    pub fn new(fs: GFileSystem) -> Self {
        Self {
            filesystem: Arc::new(RwLock::new(fs)),
            ref_count: Arc::new(Mutex::new(1)),
        }
    }

    /// Increment the reference count.
    pub fn acquire(&self) {
        let mut count = self.ref_count.lock().unwrap();
        *count += 1;
    }

    /// Decrement the reference count.
    pub fn release(&self) -> u32 {
        let mut count = self.ref_count.lock().unwrap();
        *count = count.saturating_sub(1);
        *count
    }

    /// Get the current reference count.
    pub fn ref_count(&self) -> u32 {
        *self.ref_count.lock().unwrap()
    }
}

// ---------------------------------------------------------------------------
// RefdFile -- file + filesystem reference pair
// ---------------------------------------------------------------------------

/// A file entry together with its owning filesystem reference.
///
/// Ported from `ghidra.formats.gfilesystem.RefdFile`.
#[derive(Debug, Clone)]
pub struct RefdFile {
    /// The file.
    pub file: GFile,
    /// Reference to the filesystem containing this file.
    pub fs_ref: FileSystemRef,
}

impl RefdFile {
    /// Create a new refd file.
    pub fn new(file: GFile, fs_ref: FileSystemRef) -> Self {
        Self { file, fs_ref }
    }
}

// ---------------------------------------------------------------------------
// FileSystemService -- manages filesystem mounts and caching
// ---------------------------------------------------------------------------

/// Central service for mounting and managing file systems.
///
/// Ported from `ghidra.formats.gfilesystem.FileSystemService`.
#[derive(Debug)]
pub struct FileSystemService {
    /// Currently mounted filesystems, keyed by FSRL root URI.
    mounted: RwLock<HashMap<String, FileSystemRef>>,
}

impl FileSystemService {
    /// Create a new service.
    pub fn new() -> Self {
        Self {
            mounted: RwLock::new(HashMap::new()),
        }
    }

    /// Mount a filesystem and return a reference.
    pub fn mount(&self, fs: GFileSystem) -> FileSystemRef {
        let key = fs.fsrl_root.uri.clone();
        let fs_ref = FileSystemRef::new(fs);
        self.mounted
            .write()
            .unwrap()
            .insert(key, fs_ref.clone());
        fs_ref
    }

    /// Look up a mounted filesystem by its FSRL root URI.
    pub fn get_ref(&self, fsrl_root_uri: &str) -> Option<FileSystemRef> {
        self.mounted.read().unwrap().get(fsrl_root_uri).cloned()
    }

    /// Unmount a filesystem.
    pub fn unmount(&self, fsrl_root_uri: &str) -> Option<FileSystemRef> {
        self.mounted.write().unwrap().remove(fsrl_root_uri)
    }

    /// List all currently mounted filesystem URIs.
    pub fn mounted_list(&self) -> Vec<String> {
        self.mounted.read().unwrap().keys().cloned().collect()
    }
}

impl Default for FileSystemService {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// OpenFsOptions -- options when opening a filesystem for browsing
// ---------------------------------------------------------------------------

/// Options for opening a filesystem browser.
#[derive(Debug, Clone, Default)]
pub struct OpenFsOptions {
    /// Whether to recursively scan container files found inside.
    pub recursive: bool,
    /// Maximum recursion depth (0 = unlimited).
    pub max_depth: u32,
    /// Optional base directory for resolving relative paths.
    pub base_dir: Option<PathBuf>,
}

impl OpenFsOptions {
    /// Create with defaults (non-recursive).
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable recursive scanning with the given depth limit.
    pub fn with_recursive(mut self, max_depth: u32) -> Self {
        self.recursive = true;
        self.max_depth = max_depth;
        self
    }

    /// Set the base directory.
    pub fn with_base_dir(mut self, dir: PathBuf) -> Self {
        self.base_dir = Some(dir);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fsrl_new_and_display() {
        let fsrl = Fsrl::new("file:///tmp/test.zip", "test.zip");
        assert_eq!(fsrl.name, "test.zip");
        assert_eq!(fsrl.uri, "file:///tmp/test.zip");
        assert_eq!(format!("{fsrl}"), "file:///tmp/test.zip");
    }

    #[test]
    fn test_fsrl_extension() {
        assert_eq!(Fsrl::new("u", "test.bin").extension(), "bin");
        assert_eq!(Fsrl::new("u", "noext").extension(), "");
        assert_eq!(Fsrl::new("u", ".hidden").extension(), "hidden");
        assert_eq!(Fsrl::new("u", "multi.dotted.ext").extension(), "ext");
    }

    #[test]
    fn test_gfile_file() {
        let fsrl = Fsrl::new("zipfs:/inner.bin", "inner.bin");
        let f = GFile::file("inner.bin", fsrl.clone(), 1024);
        assert!(!f.is_directory);
        assert_eq!(f.size, 1024);
        assert_eq!(f.name, "inner.bin");
    }

    #[test]
    fn test_gfile_directory() {
        let fsrl = Fsrl::new("zipfs:/subdir", "subdir");
        let d = GFile::directory("subdir", fsrl);
        assert!(d.is_directory);
        assert_eq!(d.size, 0);
    }

    #[test]
    fn test_gfilesystem() {
        let root = GFile::directory(
            "/",
            Fsrl::new("zipfs:/", "/"),
        );
        let fs = GFileSystem::new(
            Fsrl::new("zipfs:", "archive.zip"),
            "ZIP",
            root,
        );
        assert_eq!(fs.fs_type(), "ZIP");
        assert!(fs.root().is_directory);
        assert!(!fs.populated);
    }

    #[test]
    fn test_filesystem_ref_refcounting() {
        let root = GFile::directory("/", Fsrl::new("zipfs:/", "/"));
        let fs = GFileSystem::new(Fsrl::new("zipfs:", "archive.zip"), "ZIP", root);
        let fs_ref = FileSystemRef::new(fs);
        assert_eq!(fs_ref.ref_count(), 1);

        fs_ref.acquire();
        assert_eq!(fs_ref.ref_count(), 2);

        let remaining = fs_ref.release();
        assert_eq!(remaining, 1);
        assert_eq!(fs_ref.ref_count(), 1);

        let remaining = fs_ref.release();
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_refd_file() {
        let root = GFile::directory("/", Fsrl::new("zipfs:/", "/"));
        let fs = GFileSystem::new(Fsrl::new("zipfs:", "archive.zip"), "ZIP", root);
        let fs_ref = FileSystemRef::new(fs);
        let file = GFile::file("data.bin", Fsrl::new("zipfs:/data.bin", "data.bin"), 512);
        let refd = RefdFile::new(file, fs_ref);
        assert_eq!(refd.file.name, "data.bin");
        assert_eq!(refd.fs_ref.ref_count(), 1);
    }

    #[test]
    fn test_filesystem_service_mount_and_lookup() {
        let svc = FileSystemService::new();
        let root = GFile::directory("/", Fsrl::new("zipfs:/", "/"));
        let fs = GFileSystem::new(Fsrl::new("zipfs:", "archive.zip"), "ZIP", root);
        svc.mount(fs);

        let mounted = svc.mounted_list();
        assert_eq!(mounted.len(), 1);
        assert!(svc.get_ref("zipfs:").is_some());
        assert!(svc.get_ref("nonexistent").is_none());
    }

    #[test]
    fn test_filesystem_service_unmount() {
        let svc = FileSystemService::new();
        let root = GFile::directory("/", Fsrl::new("tarfs:/", "/"));
        let fs = GFileSystem::new(Fsrl::new("tarfs:", "data.tar"), "TAR", root);
        svc.mount(fs);
        assert_eq!(svc.mounted_list().len(), 1);

        let removed = svc.unmount("tarfs:");
        assert!(removed.is_some());
        assert_eq!(svc.mounted_list().len(), 0);
    }

    #[test]
    fn test_open_fs_options() {
        let opts = OpenFsOptions::new();
        assert!(!opts.recursive);
        assert_eq!(opts.max_depth, 0);

        let opts = OpenFsOptions::new()
            .with_recursive(3)
            .with_base_dir(PathBuf::from("/tmp"));
        assert!(opts.recursive);
        assert_eq!(opts.max_depth, 3);
        assert_eq!(opts.base_dir, Some(PathBuf::from("/tmp")));
    }
}
