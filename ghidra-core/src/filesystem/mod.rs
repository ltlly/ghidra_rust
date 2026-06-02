//! Virtual filesystem abstraction.
//!
//! Provides the [`FileSystem`] trait for representing a hierarchical set of
//! files (the `GFileSystem` interface from Ghidra), a [`FileSystemManager`] for
//! discovering and mounting filesystems (the `FileSystemService`), and
//! supporting types: [`FSRL`]/[`FSRLRoot`] resource locators, [`GFile`] file
//! references, reference-count management via [`FileSystemRefManager`], and
//! miscellaneous utilities (`FSUtilities`).

use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Re-exports from the crate's error module.
use crate::error::GhidraError;
/// Re-exports from the generic task module.
use crate::generic::task::TaskMonitor;

// ============================================================================
// Result alias
// ============================================================================

/// Result type alias used throughout the filesystem module.
pub type FsResult<T> = Result<T, GhidraError>;

// ============================================================================
// FSRL – File System Resource Locator
// ============================================================================

/// An `FSRL` (File System Resource Locator) uniquely identifies a file either
/// on the local filesystem or nested inside a filesystem container.
///
/// An FSRL is composed of:
/// - An optional parent container (`FSRL` – what this file lives inside of)
/// - A path string (the location within that container)
/// - An optional MD5 hex digest
///
/// Corresponds to `ghidra.formats.gfilesystem.FSRL`.
#[derive(Debug, Clone)]
pub struct FSRL {
    /// Parent container, or `None` for top-level files.
    pub parent: Option<Arc<FSRL>>,
    /// Path portion of this FSRL.
    pub path: String,
    /// MD5 hex digest of the resource, or `None` if unknown.
    pub md5: Option<String>,
}

impl FSRL {
    // ------------------------------------------------------------------
    // Constructors
    // ------------------------------------------------------------------

    /// Create a new FSRL.
    pub fn new(parent: Option<Arc<FSRL>>, path: impl Into<String>, md5: Option<String>) -> Self {
        Self {
            parent,
            path: path.into(),
            md5,
        }
    }

    /// Create a root-level FSRL with only a path and optional MD5.
    pub fn root(path: impl Into<String>, md5: Option<String>) -> Self {
        Self {
            parent: None,
            path: path.into(),
            md5,
        }
    }

    /// Return a new FSRL with this FSRL as parent and the given path/md5 appended.
    pub fn with_path(&self, path: impl Into<String>) -> Self {
        FSRL {
            parent: Some(Arc::new(self.clone())),
            path: path.into(),
            md5: None,
        }
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// The owning filesystem root (`FSRLRoot`) of this FSRL.
    pub fn get_fs(&self) -> Option<FSRLRoot> {
        let mut cur: Option<&FSRL> = Some(self);
        while let Some(node) = cur {
            if let Some(fsrl_root) = node.as_fsrl_root() {
                return Some(fsrl_root.clone());
            }
            cur = node.parent.as_ref().map(|p| p.as_ref());
        }
        None
    }

    fn as_fsrl_root(&self) -> Option<FSRLRoot> {
        None // subclasses override; FSRLRoot overrides
    }

    /// The leaf name extracted from the path (text after the last '/').
    pub fn name(&self) -> String {
        match self.path.rfind('/') {
            Some(idx) => self.path[idx + 1..].to_string(),
            None => self.path.clone(),
        }
    }

    /// The full path string including all parents' path segments,
    /// joined by `|` to represent nested containers.
    pub fn full_path(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        self.collect_parts(&mut parts);
        parts.join("|")
    }

    fn collect_parts(&self, parts: &mut Vec<String>) {
        if let Some(ref parent) = self.parent {
            parent.collect_parts(parts);
        }
        if !self.path.is_empty() {
            parts.push(self.path.clone());
        }
    }

    /// Returns `true` if the MD5 matches the provided digest.
    pub fn is_md5_equal(&self, other_md5: Option<&str>) -> bool {
        match (&self.md5, other_md5) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
            _ => false,
        }
    }

    /// Clone this FSRL with the MD5 replaced.
    pub fn with_md5(&self, md5: impl Into<String>) -> Self {
        let mut c = self.clone();
        c.md5 = Some(md5.into());
        c
    }

    /// Returns `true` when this FSRL has an MD5.
    pub fn is_fully_qualified(&self) -> bool {
        self.md5.is_some()
    }
}

impl fmt::Display for FSRL {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fp = self.full_path();
        match &self.md5 {
            Some(md5) => write!(f, "{} [{}]", fp, md5),
            None => write!(f, "{}", fp),
        }
    }
}

impl PartialEq for FSRL {
    fn eq(&self, other: &Self) -> bool {
        self.parent == other.parent && self.path == other.path && self.md5 == other.md5
    }
}

impl Eq for FSRL {}

impl std::hash::Hash for FSRL {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.parent.hash(state);
        self.path.hash(state);
        self.md5.hash(state);
    }
}

// ============================================================================
// FSRLRoot
// ============================================================================

/// An `FSRLRoot` identifies a specific filesystem's root.
/// Its "path" is actually the filesystem protocol/type string
/// (e.g., `"file"`, `"zip"`, `"iso9660"`).
///
/// Corresponds to `ghidra.formats.gfilesystem.FSRLRoot`.
#[derive(Debug, Clone)]
pub struct FSRLRoot {
    /// The underlying FSRL — path holds the protocol string.
    pub fsrl: FSRL,
    /// Cached hash code.
    hash_code: u64,
}

impl FSRLRoot {
    /// Create a root FSRLRoot with no parent container (top-level filesystem).
    pub fn make_root(protocol: impl Into<String>) -> Self {
        let fsrl = FSRL::new(None, protocol.into(), None);
        let hash_code = Self::compute_hash(&fsrl);
        Self { fsrl, hash_code }
    }

    /// Create a nested FSRLRoot as a child of a container FSRL.
    pub fn nested_fs(container_file: &FSRL, fstype: impl Into<String>) -> Self {
        let fsrl = FSRL::new(
            Some(Arc::new(container_file.clone())),
            fstype.into(),
            None,
        );
        let hash_code = Self::compute_hash(&fsrl);
        Self { fsrl, hash_code }
    }

    /// Create a nested FSRLRoot by re-parenting an existing FSRLRoot.
    pub fn nested_fs_from_root(container_file: &FSRL, copy_fsrl: &FSRLRoot) -> Self {
        Self::nested_fs(container_file, copy_fsrl.protocol())
    }

    fn compute_hash(fsrl: &FSRL) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        fsrl.hash(&mut hasher);
        hasher.finish()
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Returns `self` (always - subsumes FSRL's `get_fs()`).
    pub fn get_fs(&self) -> &FSRLRoot {
        self
    }

    /// The protocol/type string for this filesystem (e.g., `"file"`, `"zip"`).
    pub fn protocol(&self) -> &str {
        &self.fsrl.path
    }

    /// The parent container FSRL, or `None` if this is a top-level filesystem.
    pub fn container(&self) -> Option<&FSRL> {
        self.fsrl.parent.as_ref().map(|p| p.as_ref())
    }

    /// Returns `true` when this root has a parent container.
    pub fn has_container(&self) -> bool {
        self.fsrl.parent.is_some()
    }

    /// Create a child FSRL within this filesystem.
    pub fn with_path(&self, path: impl Into<String>) -> FSRL {
        FSRL::new(
            Some(Arc::new(self.fsrl.clone())),
            path.into(),
            None,
        )
    }

    /// Create a child FSRL within this filesystem with an MD5.
    pub fn with_path_md5(&self, path: impl Into<String>, md5: impl Into<String>) -> FSRL {
        FSRL::new(
            Some(Arc::new(self.fsrl.clone())),
            path.into(),
            Some(md5.into()),
        )
    }
}

impl fmt::Display for FSRLRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(parent) = &self.fsrl.parent {
            write!(f, "{}|{}://", parent, self.fsrl.path)
        } else {
            write!(f, "{}://", self.fsrl.path)
        }
    }
}

impl PartialEq for FSRLRoot {
    fn eq(&self, other: &Self) -> bool {
        self.fsrl == other.fsrl
    }
}

impl Eq for FSRLRoot {}

impl std::hash::Hash for FSRLRoot {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash_code);
    }
}

// ============================================================================
// FileType
// ============================================================================

/// The type of a file within a filesystem.
///
/// Corresponds to `ghidra.formats.gfilesystem.fileinfo.FileType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    /// A regular file with data.
    File,
    /// A directory (container for other files).
    Directory,
    /// A symbolic link to another file.
    SymbolicLink,
    /// Unknown or unsupported file type.
    Unknown,
}

impl Default for FileType {
    fn default() -> Self {
        FileType::File
    }
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileType::File => write!(f, "file"),
            FileType::Directory => write!(f, "dir"),
            FileType::SymbolicLink => write!(f, "symlink"),
            FileType::Unknown => write!(f, "unknown"),
        }
    }
}

// ============================================================================
// GFile trait and default implementation
// ============================================================================

/// Represents a file (or directory) in a [`FileSystem`].
///
/// Valid only while the owning filesystem is still open.
///
/// Corresponds to `ghidra.formats.gfilesystem.GFile`.
pub trait GFile: Send + Sync {
    /// The filesystem that owns this file.
    fn filesystem(&self) -> Option<Arc<dyn FileSystem>>;

    /// The FSRL of this file.
    fn fsrl(&self) -> &FSRL;

    /// The parent directory, or `None` for root.
    fn parent_file(&self) -> Option<Arc<dyn GFile>>;

    /// The path and filename relative to the owning filesystem.
    fn path(&self) -> String;

    /// The name (filename portion) of this file.
    fn name(&self) -> String;

    /// Returns `true` when this file is a directory.
    fn is_directory(&self) -> bool;

    /// The byte length of this file, or `-1` if unknown.
    fn length(&self) -> i64;

    /// List children of this directory.
    fn listing(&self) -> FsResult<Vec<Arc<dyn GFile>>>;

    /// Return self as `&dyn Any` for downcast.
    fn as_any(&self) -> &dyn std::any::Any;
}

// ============================================================================
// GFileImpl – basic GFile implementation
// ============================================================================

/// A basic implementation of [`GFile`].
///
/// Corresponds to `ghidra.formats.gfilesystem.GFileImpl`.
pub struct GFileImpl {
    /// Weak reference to the owning filesystem.
    pub filesystem: Weak<dyn FileSystem>,
    /// The FSRL for this file.
    pub fsrl: FSRL,
    /// Parent directory, if any.
    pub parent: Option<Arc<dyn GFile>>,
    /// Whether this file is a directory.
    pub is_dir: bool,
    /// Length in bytes, or -1 if unknown.
    pub len: i64,
}

impl GFileImpl {
    /// Create a new root GFileImpl.
    pub fn new_root(fs: Arc<dyn FileSystem>, fsrl: FSRL) -> Arc<Self> {
        Arc::new(Self {
            filesystem: Arc::downgrade(&fs),
            fsrl,
            parent: None,
            is_dir: true,
            len: 0,
        })
    }

    /// Create a new child GFileImpl.
    pub fn new(
        fs: Arc<dyn FileSystem>,
        parent: Option<Arc<dyn GFile>>,
        is_dir: bool,
        len: i64,
        fsrl: FSRL,
    ) -> Arc<Self> {
        Arc::new(Self {
            filesystem: Arc::downgrade(&fs),
            fsrl,
            parent,
            is_dir,
            len,
        })
    }
}

impl GFile for GFileImpl {
    fn filesystem(&self) -> Option<Arc<dyn FileSystem>> {
        self.filesystem.upgrade()
    }

    fn fsrl(&self) -> &FSRL {
        &self.fsrl
    }

    fn parent_file(&self) -> Option<Arc<dyn GFile>> {
        self.parent.clone()
    }

    fn path(&self) -> String {
        self.fsrl.path.clone()
    }

    fn name(&self) -> String {
        self.fsrl.name()
    }

    fn is_directory(&self) -> bool {
        self.is_dir
    }

    fn length(&self) -> i64 {
        self.len
    }

    fn listing(&self) -> FsResult<Vec<Arc<dyn GFile>>> {
        match self.filesystem() {
            Some(fs) => fs.get_listing(self),
            None => Err(GhidraError::NotFound(
                "No filesystem available for listing".into(),
            )),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl fmt::Debug for GFileImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GFileImpl")
            .field("path", &self.fsrl.path)
            .field("is_dir", &self.is_dir)
            .field("len", &self.len)
            .finish()
    }
}

// ============================================================================
// FileSystem trait
// ============================================================================

/// The main filesystem abstraction: a hierarchical collection of files.
///
/// Operations accept a [`TaskMonitor`] so they can be cooperatively cancelled.
///
/// Corresponds to `ghidra.formats.gfilesystem.GFileSystem`.
pub trait FileSystem: Send + Sync + std::any::Any {
    /// The volume / container name.
    fn name(&self) -> &str;

    /// The filesystem type (e.g., `"zip"`, `"iso9660"`, `"file"`).
    fn fs_type(&self) -> &str;

    /// A human-readable description of the filesystem.
    fn description(&self) -> &str;

    /// The `FSRLRoot` of this filesystem.
    fn fsrl(&self) -> &FSRLRoot;

    /// Returns `true` when the filesystem has been closed.
    fn is_closed(&self) -> bool;

    /// Returns `true` when the filesystem is a static snapshot.
    /// Returns `false` when content is dynamic.
    fn is_static(&self) -> bool {
        true
    }

    /// Return the reference manager that controls [`FileSystemRef`] handles
    /// for this filesystem.
    fn ref_manager(&self) -> &FileSystemRefManager;

    /// Number of files in this filesystem, or `-1` if unknown.
    fn file_count(&self) -> i64 {
        -1
    }

    /// Look up a [`GFile`] by its path string.
    /// Pass `None` or `"/"` to get the root directory.
    fn lookup(&self, path: Option<&str>, monitor: &TaskMonitor) -> FsResult<Option<Arc<dyn GFile>>>;

    /// Return the root directory.
    fn root_dir(&self, monitor: &TaskMonitor) -> FsResult<Option<Arc<dyn GFile>>> {
        self.lookup(None, monitor)
    }

    /// Get directory listing of children of `directory`.
    /// A `None` directory means the root.
    fn get_listing(&self, directory: &dyn GFile) -> FsResult<Vec<Arc<dyn GFile>>>;

    /// Get an input stream that reads the contents of `file`.
    fn get_input_stream(
        &self,
        file: &dyn GFile,
        monitor: &TaskMonitor,
    ) -> FsResult<Box<dyn Read + Send>>;

    /// Get a [`ByteProvider`] for the given file.
    fn get_byte_provider(
        &self,
        file: &dyn GFile,
        monitor: &TaskMonitor,
    ) -> FsResult<Box<dyn ByteProvider>>;

    /// Close the filesystem, releasing all resources.
    fn close(&mut self) -> FsResult<()>;

    /// Return self as `&dyn Any` for downcast support.
    fn as_any(&self) -> &dyn std::any::Any;
}

// ============================================================================
// ByteProvider trait
// ============================================================================

/// Provides bytes for a resource, identified by an `FSRL`.
///
/// Corresponds to `ghidra.app.util.bin.ByteProvider`.
pub trait ByteProvider: Read + Send + Sync {
    /// The FSRL of this byte provider.
    fn fsrl(&self) -> &FSRL;

    /// Total length of the underlying resource.
    fn length(&self) -> u64;

    /// Open an input stream starting at `offset`.
    fn input_stream_at(&self, offset: u64) -> FsResult<Box<dyn Read + Send>>;

    /// Name of the resource (derived from the FSRL).
    fn name(&self) -> String {
        self.fsrl().name()
    }

    /// The underlying `File`, if available locally.
    fn file(&self) -> Option<&Path>;

    /// Close this provider.
    fn close(&mut self) -> FsResult<()>;
}

// ============================================================================
// FileSystemRef – handle that pins a filesystem in memory
// ============================================================================

/// An RAII handle that pins a [`FileSystem`] in memory.
///
/// Created by a [`FileSystemRefManager`]; when dropped, releases the reference.
///
/// Corresponds to `ghidra.formats.gfilesystem.FileSystemRef`.
pub struct FileSystemRef {
    /// The filesystem being referenced.
    fs: Arc<dyn FileSystem>,
    /// Weak reference back to the manager for release on drop.
    manager: Weak<Mutex<FileSystemRefManagerInner>>,
    /// Whether this ref has been released.
    closed: bool,
}

impl FileSystemRef {
    fn new(fs: Arc<dyn FileSystem>, manager: Weak<Mutex<FileSystemRefManagerInner>>) -> Self {
        Self {
            fs,
            manager,
            closed: false,
        }
    }

    /// The filesystem.
    pub fn filesystem(&self) -> &Arc<dyn FileSystem> {
        &self.fs
    }

    /// Returns `true` when this ref has been released.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Duplicate this ref (increment the reference count).
    pub fn dup_ref(&self) -> Option<Self> {
        if self.closed {
            return None;
        }
        let mgr = self.manager.upgrade()?;
        let mut inner = mgr.lock().ok()?;
        if inner.fs.is_none() {
            return None;
        }
        inner.refs.push(self.fs.clone());
        inner.touch();
        Some(Self {
            fs: self.fs.clone(),
            manager: self.manager.clone(),
            closed: false,
        })
    }

    /// Release this reference early (normally happens on drop).
    pub fn close(mut self) {
        self.closed = true;
        self.release_from_manager();
    }

    fn release_from_manager(&self) {
        if let Some(mgr) = self.manager.upgrade() {
            if let Ok(mut inner) = mgr.lock() {
                inner.remove_ref(&*self.fs);
            }
        }
    }
}

impl Drop for FileSystemRef {
    fn drop(&mut self) {
        if !self.closed {
            self.release_from_manager();
        }
    }
}

impl fmt::Debug for FileSystemRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSystemRef")
            .field("fs_name", &self.fs.name())
            .field("closed", &self.closed)
            .finish()
    }
}

// ============================================================================
// FileSystemRefManager – threadsafe ref-counting for a filesystem
// ============================================================================

/// The synchronized inner data for a [`FileSystemRefManager`].
pub(crate) struct FileSystemRefManagerInner {
    /// The filesystem being managed; set to `None` after close.
    fs: Option<Arc<dyn FileSystem>>,
    /// Active references (we track the Arc pointers for identity comparison).
    refs: Vec<Arc<dyn FileSystem>>,
    /// Last-used timestamp in milliseconds.
    last_used_ts: u64,
}

impl FileSystemRefManagerInner {
    fn new(fs: Arc<dyn FileSystem>) -> Self {
        Self {
            fs: Some(fs),
            refs: Vec::new(),
            last_used_ts: current_time_millis(),
        }
    }

    /// Create an empty inner (used by Default).
    fn empty() -> Self {
        Self {
            fs: None,
            refs: Vec::new(),
            last_used_ts: current_time_millis(),
        }
    }

    fn touch(&mut self) {
        self.last_used_ts = current_time_millis();
    }

    fn remove_ref(&mut self, target: &dyn FileSystem) {
        // Walk backward: most recently added is most likely to be removed.
        let target_ptr = target as *const dyn FileSystem as *const ();
        for i in (0..self.refs.len()).rev() {
            let ptr = Arc::as_ptr(&self.refs[i]) as *const dyn FileSystem as *const ();
            if ptr == target_ptr {
                self.refs.remove(i);
                self.touch();
                return;
            }
        }
    }
}

impl fmt::Debug for FileSystemRefManagerInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fs_name = self.fs.as_ref().map(|fs| fs.name().to_string());
        f.debug_struct("FileSystemRefManagerInner")
            .field("fs", &fs_name)
            .field("ref_count", &self.refs.len())
            .field("last_used_ts", &self.last_used_ts)
            .finish()
    }
}

/// Manages reference counting and listener dispatch for a single filesystem.
///
/// Only the outer manager is `Send + Sync` via its `Arc<Mutex<...>>` interior.
///
/// Corresponds to `ghidra.formats.gfilesystem.FileSystemRefManager`.
#[derive(Debug)]
pub struct FileSystemRefManager {
    inner: Arc<Mutex<FileSystemRefManagerInner>>,
}

impl Default for FileSystemRefManager {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(FileSystemRefManagerInner::empty())),
        }
    }
}

impl FileSystemRefManager {
    /// Create a new manager for the given filesystem.
    pub fn new(fs: Arc<dyn FileSystem>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FileSystemRefManagerInner::new(fs))),
        }
    }

    /// Create a new [`FileSystemRef`] for the managed filesystem.
    pub fn create_ref(&self) -> FsResult<FileSystemRef> {
        // First, check if the filesystem is closed (under the lock).
        {
            let inner = self.inner.lock().unwrap();
            if let Some(ref fs) = inner.fs {
                if fs.is_closed() {
                    return Err(GhidraError::InvalidData(format!(
                        "File system already closed: {}",
                        fs.name()
                    )));
                }
            }
        }

        // Clone the Arc out of the inner so we can push it back in the next step.
        let mut inner = self.inner.lock().unwrap();
        let fs_arc = match &inner.fs {
            Some(fs) => Some(fs.clone()),
            None => return Err(GhidraError::InvalidData("Manager already closed".into())),
        };
        if let Some(fs) = fs_arc {
            inner.refs.push(fs.clone());
            inner.touch();
            let mgr_weak = Arc::downgrade(&self.inner);
            Ok(FileSystemRef::new(fs, mgr_weak))
        } else {
            Err(GhidraError::InvalidData("Manager already closed".into()))
        }
    }

    /// Returns `true` when the given ref is the only reference holding
    /// the filesystem open.
    pub fn can_close(&self, callers_ref: &FileSystemRef) -> bool {
        let inner = self.inner.lock().unwrap();
        if inner.refs.is_empty() {
            return false;
        }
        let target =
            Arc::as_ptr(callers_ref.filesystem()) as *const dyn FileSystem as *const ();
        let only = Arc::as_ptr(&inner.refs[0]) as *const dyn FileSystem as *const ();
        inner.refs.len() == 1 && only == target
    }

    /// Called when the filesystem is closing. Clears internal state.
    pub fn on_close(&self) -> FsResult<()> {
        let mut inner = self.inner.lock().unwrap();
        let _fs = inner.fs.take().ok_or_else(|| {
            GhidraError::InvalidData("FileSystemRefManager already closed".into())
        })?;
        let ref_count = inner.refs.len();
        inner.refs.clear();

        if ref_count > 0 {
            log::warn!(
                "Closing filesystem even though {} active handles exist",
                ref_count
            );
        }
        Ok(())
    }

    /// Returns the last-used timestamp in milliseconds since epoch.
    pub fn last_used_timestamp(&self) -> u64 {
        self.inner.lock().unwrap().last_used_ts
    }
}

// ============================================================================
// FileSystemBase – partial default implementation of FileSystem
// ============================================================================

/// A base struct that implements common behaviour for [`FileSystem`].
///
/// Concrete filesystem types can embed this and override methods as needed.
///
/// Corresponds to `ghidra.formats.gfilesystem.GFileSystemBase`.
pub struct FileSystemBase {
    /// The volume / container name.
    pub file_system_name: String,
    /// The FSRLRoot of this filesystem.
    pub fs_fsrl: FSRLRoot,
    /// Root GFile.
    pub root: Option<Arc<dyn GFile>>,
    /// Reference manager.
    pub ref_manager: FileSystemRefManager,
    /// Whether this filesystem has been closed.
    pub closed: bool,
}

impl FileSystemBase {
    /// Create a new base with the given name and FSRLRoot.
    pub fn new(file_system_name: impl Into<String>, fs_fsrl: FSRLRoot) -> Self {
        Self {
            file_system_name: file_system_name.into(),
            fs_fsrl,
            root: None,
            ref_manager: FileSystemRefManager::default(),
            closed: false,
        }
    }

    /// Initialize the root after construction.
    pub fn init_root(fs: Arc<dyn FileSystem>, root_path: impl Into<String>) -> Arc<dyn GFile> {
        let root_path = root_path.into();
        let root_fsrl = FSRL::new(None, root_path, None);
        GFileImpl::new_root(fs, root_fsrl)
    }

    /// Close this filesystem.
    pub fn close_inner(&mut self) -> FsResult<()> {
        self.closed = true;
        Ok(())
    }
}

// ============================================================================
// FileSystemIterator – depth-first traversal over a filesystem
// ============================================================================

/// Iterates over every file in a [`FileSystem`] in depth-first order.
///
/// Corresponds to `ghidra.formats.gfilesystem.GFileSystemIterator`.
pub struct FileSystemIterator {
    /// Deque of file entries still to be yielded.
    file_deque: VecDeque<Arc<dyn GFile>>,
    /// Deque of directory entries still to be expanded.
    dir_deque: VecDeque<Arc<dyn GFile>>,
    /// Optional filter applied to non-directory files.
    predicate: Option<Box<dyn Fn(&dyn GFile) -> bool + Send + Sync>>,
}

impl FileSystemIterator {
    /// Create an iterator over the entire filesystem, starting at the root.
    pub fn new(fs: &dyn FileSystem, monitor: &TaskMonitor) -> FsResult<Self> {
        let root = fs
            .root_dir(monitor)?
            .ok_or_else(|| GhidraError::NotFound("No root directory".into()))?;
        Ok(Self::from_dir(root, None))
    }

    /// Create an iterator starting at the given directory.
    pub fn from_dir(
        dir: Arc<dyn GFile>,
        predicate: Option<Box<dyn Fn(&dyn GFile) -> bool + Send + Sync>>,
    ) -> Self {
        if !dir.is_directory() {
            log::warn!(
                "FileSystemIterator given non-directory start: {}",
                dir.name()
            );
            return Self {
                file_deque: VecDeque::new(),
                dir_deque: VecDeque::new(),
                predicate: None,
            };
        }
        let mut iter = Self {
            file_deque: VecDeque::new(),
            dir_deque: VecDeque::new(),
            predicate,
        };
        iter.dir_deque.push_back(dir);
        iter
    }

    /// Push the next batch of files from pending directories into the file deque.
    fn queue_next_files(&mut self) {
        while self.file_deque.is_empty() && !self.dir_deque.is_empty() {
            let dir = match self.dir_deque.pop_back() {
                Some(d) => d,
                None => break,
            };
            let list_result = match dir.filesystem() {
                Some(fs) => fs.get_listing(&*dir),
                None => Err(GhidraError::NotFound(
                    "No filesystem available for listing".into(),
                )),
            };
            match list_result {
                Ok(listing) => {
                    // Sort by name (reversed so that the front of the deque
                    // yields alphabetically-first when we pop_back).
                    let mut dirs: Vec<&Arc<dyn GFile>> =
                        listing.iter().filter(|g| g.is_directory()).collect();
                    dirs.sort_by(|a, b| b.name().cmp(&a.name()));
                    let mut files: Vec<&Arc<dyn GFile>> =
                        listing.iter().filter(|g| !g.is_directory()).collect();
                    files.sort_by(|a, b| b.name().cmp(&a.name()));

                    for d in dirs {
                        self.dir_deque.push_back(d.clone());
                    }
                    for f in files {
                        let pass = self
                            .predicate
                            .as_ref()
                            .map(|pred| pred(f.as_ref()))
                            .unwrap_or(true);
                        if pass {
                            self.file_deque.push_back(f.clone());
                        }
                    }
                }
                Err(e) => {
                    log::error!("Error listing directory {}: {}", dir.name(), e);
                    self.dir_deque.clear();
                    break;
                }
            }
        }
    }
}

impl Iterator for FileSystemIterator {
    type Item = Arc<dyn GFile>;

    fn next(&mut self) -> Option<Self::Item> {
        self.queue_next_files();
        self.file_deque.pop_back()
    }
}

// ============================================================================
// FileSystemManager – the central filesystem service
// ============================================================================

/// The central manager for discovering, mounting, and caching filesystems.
///
/// Maintains a registry of mounted filesystems, provides methods to probe
/// containers and resolve `FSRL` paths.
///
/// Corresponds to `ghidra.formats.gfilesystem.FileSystemService`.
#[derive(Default)]
pub struct FileSystemManager {
    /// Mounted filesystems keyed by their `FSRLRoot`.
    mounted: HashMap<FSRLRoot, Arc<dyn FileSystem>>,
    /// File cache entries (MD5 to cached file path).
    file_cache: HashMap<String, PathBuf>,
    /// Name index for derived files: (container_md5, derived_name) -> derived_md5.
    name_index: HashMap<(String, String), String>,
    /// Temporary directory for cached files.
    cache_dir: PathBuf,
}

impl FileSystemManager {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Create a new FileSystemManager with the default cache directory.
    pub fn new() -> FsResult<Self> {
        let cache_dir = std::env::temp_dir().join("ghidra_fscache2");
        std::fs::create_dir_all(&cache_dir)?;
        Ok(Self {
            mounted: HashMap::new(),
            file_cache: HashMap::new(),
            name_index: HashMap::new(),
            cache_dir,
        })
    }

    /// Create a FileSystemManager with a specific cache directory.
    pub fn with_cache_dir(cache_dir: PathBuf) -> FsResult<Self> {
        std::fs::create_dir_all(&cache_dir)?;
        Ok(Self {
            mounted: HashMap::new(),
            file_cache: HashMap::new(),
            name_index: HashMap::new(),
            cache_dir,
        })
    }

    // ------------------------------------------------------------------
    // Filesystem lifecycle
    // ------------------------------------------------------------------

    /// Mount a filesystem, returning a [`FileSystemRef`].
    pub fn mount(&mut self, fs: Arc<dyn FileSystem>) -> FsResult<FileSystemRef> {
        let fsrl = fs.fsrl().clone();
        if self.mounted.contains_key(&fsrl) {
            return Err(GhidraError::InvalidData(format!(
                "Filesystem already mounted: {}",
                fsrl
            )));
        }
        let fs_clone = fs.clone();
        self.mounted.insert(fsrl, fs_clone);
        fs.ref_manager().create_ref()
    }

    /// Unmount a filesystem by its root.
    pub fn unmount(&mut self, fsrl: &FSRLRoot) -> FsResult<()> {
        if let Some(fs) = self.mounted.remove(fsrl) {
            if !fs.is_closed() {
                log::warn!(
                    "Unmounting filesystem {} without closing it first",
                    fs.name()
                );
            }
        }
        Ok(())
    }

    /// Returns `true` if a filesystem is mounted at the given `FSRLRoot`.
    pub fn is_mounted_at(&self, fsrl: &FSRLRoot) -> bool {
        self.mounted.contains_key(fsrl)
    }

    /// Get a reference to a mounted filesystem by its root.
    pub fn get_mounted(&self, fsrl: &FSRLRoot) -> FsResult<FileSystemRef> {
        let fs = self
            .mounted
            .get(fsrl)
            .cloned()
            .ok_or_else(|| GhidraError::NotFound(format!("Filesystem not mounted: {}", fsrl)))?;
        fs.ref_manager().create_ref()
    }

    /// List all mounted filesystem roots.
    pub fn mounted_filesystems(&self) -> Vec<FSRLRoot> {
        self.mounted.keys().cloned().collect()
    }

    /// Close and unmount all filesystems.
    pub fn clear(&mut self) {
        self.mounted.clear();
        self.file_cache.clear();
        self.name_index.clear();
    }

    // ------------------------------------------------------------------
    // Cache management
    // ------------------------------------------------------------------

    /// Create a temporary file in the cache directory, returning its path.
    pub fn create_temp_file(&self, prefix: &str) -> FsResult<PathBuf> {
        let timestamp = current_time_millis();
        let filename = format!("{}_{}", prefix, timestamp);
        let path = self.cache_dir.join(filename);
        Ok(path)
    }

    /// Check whether a derived file exists in the name index.
    pub fn has_derived_file(&self, container_md5: &str, derived_name: &str) -> bool {
        let key = (container_md5.to_string(), derived_name.to_string());
        self.name_index.contains_key(&key)
    }

    /// Register a derived file in the name index.
    pub fn register_derived_file(
        &mut self,
        container_md5: String,
        derived_name: String,
        derived_md5: String,
    ) {
        self.name_index
            .insert((container_md5, derived_name), derived_md5);
    }

    /// Look up a cached file path by MD5.
    pub fn get_cached_file(&self, md5: &str) -> Option<&PathBuf> {
        self.file_cache.get(md5)
    }

    /// Store a cached file path keyed by MD5.
    pub fn cache_file(&mut self, md5: String, path: PathBuf) {
        self.file_cache.insert(md5, path);
    }

    /// Release a cached file by MD5.
    pub fn release_cache(&mut self, md5: &str) {
        self.file_cache.remove(md5);
    }
}

impl fmt::Debug for FileSystemManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSystemManager")
            .field("mounted_count", &self.mounted.len())
            .field("cache_dir", &self.cache_dir)
            .finish()
    }
}

// ============================================================================
// Utility functions (FSUtilities port)
// ============================================================================

/// Filesystem utility functions.
///
/// Corresponds to `ghidra.formats.gfilesystem.FSUtilities`.
pub struct FsUtils;

impl FsUtils {
    /// Path separator character.
    pub const SEPARATOR: &'static str = "/";
    /// Characters that separate path components.
    pub const SEPARATOR_CHARS: &'static str = "/\\:";

    // ------------------------------------------------------------------
    // Path helpers
    // ------------------------------------------------------------------

    /// Concatenate path segments with `/`, handling existing separators.
    ///
    /// Empty or `None` segments are skipped. Handles forward and back slashes
    /// in the input, but only inserts forward slashes.
    pub fn append_path(paths: &[&str]) -> Option<String> {
        if paths.iter().all(|p| p.is_empty()) {
            return None;
        }
        let mut buf = String::new();
        for path in paths {
            if path.is_empty() {
                continue;
            }
            let empty = buf.is_empty();
            let ends_slash = !empty && "/\\".contains(buf.chars().last().unwrap());
            let starts_slash = "/\\".contains(path.chars().next().unwrap());

            if !ends_slash && !starts_slash && !empty {
                buf.push('/');
            }
            let part: &str = if starts_slash && ends_slash {
                &path[1..]
            } else {
                path
            };
            buf.push_str(part);
        }
        Some(buf)
    }

    /// Normalize a native path to use forward slashes and have a leading `/`.
    pub fn normalize_native_path(path: &str) -> String {
        let unix_path = path.replace('\\', "/");
        Self::append_path(&["/", &unix_path]).unwrap_or_else(|| "/".into())
    }

    /// Split a path into its individual directory and filename components.
    /// `"/dir/dir/file"` becomes `["", "dir", "dir", "file"]`.
    pub fn split_path(path: &str) -> Vec<String> {
        let p: &str = if path.is_empty() { "" } else { path };
        p.replace('\\', "/")
            .split('/')
            .map(|s| s.to_string())
            .collect()
    }

    /// Sanitize an untrusted filename for safe writing to the local filesystem.
    pub fn safe_filename(untrusted: &str) -> String {
        let s = untrusted
            .replace('/', "_")
            .replace('\\', "_")
            .replace(':', "_")
            .replace('|', "_")
            .trim()
            .to_string();
        match s.as_str() {
            "" => "empty_filename".into(),
            "." => "dot".into(),
            ".." => "dotdot".into(),
            other => Self::escape_encode(other),
        }
    }

    /// Escape non-printable and special characters using `%NN` hex sequences.
    pub fn escape_encode(s: &str) -> String {
        let escape_chars = "%?|";
        let mut result = String::new();
        for c in s.chars() {
            if (c as u32) < 32 || (c as u32) > 126 || escape_chars.contains(c) {
                let bytes = c.to_string().into_bytes();
                for b in bytes {
                    result.push_str(&format!("%{:02X}", b));
                }
            } else {
                result.push(c);
            }
        }
        result
    }

    /// Decode `%NN` escape sequences back to original characters (UTF-8).
    pub fn escape_decode(s: &str) -> FsResult<String> {
        let mut result = String::new();
        let chars: Vec<char> = s.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '%' {
                let mut bytes = Vec::new();
                while i + 2 < chars.len() && chars[i] == '%' {
                    let hex_str: String = chars[i + 1..i + 3].iter().collect();
                    let v = u8::from_str_radix(&hex_str, 16).map_err(|_| {
                        GhidraError::InvalidData(format!(
                            "Bad hex chars in escape pattern: {}",
                            s
                        ))
                    })?;
                    bytes.push(v);
                    i += 3;
                }
                if i < chars.len() && chars[i] == '%' {
                    return Err(GhidraError::InvalidData(format!(
                        "Bad escape pattern in {}",
                        s
                    )));
                }
                result.push_str(&String::from_utf8_lossy(&bytes));
            } else {
                result.push(chars[i]);
                i += 1;
            }
        }
        Ok(result)
    }

    /// Get the extension of a filename at the given level.
    ///
    /// Level 1 returns ".ext2" from "path/file.ext1.ext2".
    /// Level 2 returns ".ext1.ext2".
    pub fn extension(path: &str, ext_level: usize) -> Option<String> {
        if ext_level < 1 {
            return None;
        }
        let mut remaining = ext_level;
        for (i, c) in path.char_indices().rev() {
            if Self::SEPARATOR_CHARS.contains(c) {
                return None;
            }
            if c == '.' {
                remaining -= 1;
                if remaining == 0 {
                    return Some(path[i..].to_string());
                }
            }
        }
        None
    }

    /// Convert the given path to a valid mirrored project path.
    /// From a Windows path like `/C:/foo` drops the colon.
    pub fn mirrored_project_path(path: &str) -> String {
        let path = Self::normalize_native_path(path);
        if path.len() >= 3
            && path.starts_with('/')
            && path.chars().nth(1).map_or(false, |c| c.is_ascii_alphabetic())
            && path.chars().nth(2) == Some(':')
        {
            return format!("/{}{}", path.chars().nth(1).unwrap(), &path[3..]);
        }
        path
    }

    // ------------------------------------------------------------------
    // Comparison / sorting
    // ------------------------------------------------------------------

    /// Compare two GFiles: directories first, then case-insensitive by name.
    pub fn gfile_name_type_compare(a: &dyn GFile, b: &dyn GFile) -> Ordering {
        match (a.is_directory(), b.is_directory()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => {
                let an = a.name().to_lowercase();
                let bn = b.name().to_lowercase();
                an.cmp(&bn)
            }
        }
    }

    /// Returns true if all the FSRLs in the list belong to the same filesystem.
    pub fn is_same_fs(fsrls: &[FSRL]) -> bool {
        if fsrls.is_empty() {
            return true;
        }
        let fs_root = fsrls[0].get_fs();
        fsrls.iter().all(|f| f.get_fs() == fs_root)
    }

    // ------------------------------------------------------------------
    // I/O helpers
    // ------------------------------------------------------------------

    /// Copy all bytes from a reader to a file, updating a `TaskMonitor`.
    pub fn copy_to_file<R: Read>(
        reader: &mut R,
        dest: &Path,
        monitor: &TaskMonitor,
    ) -> FsResult<u64> {
        let mut file = File::create(dest)?;
        Self::stream_copy(reader, &mut file, monitor)
    }

    /// Copy all bytes from `reader` to `writer`, updating a `TaskMonitor`.
    pub fn stream_copy<R: Read, W: Write>(
        reader: &mut R,
        writer: &mut W,
        monitor: &TaskMonitor,
    ) -> FsResult<u64> {
        let mut buf = [0u8; 8192];
        let mut total: u64 = 0;
        loop {
            monitor.check_cancelled().map_err(|e| {
                GhidraError::Other(anyhow::anyhow!("Cancelled: {}", e))
            })?;
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n])?;
            total += n as u64;
            monitor.set_progress(total as i64);
        }
        writer.flush()?;
        Ok(total)
    }

    /// Compute the MD5 hash of a file.
    pub fn file_md5(path: &Path, monitor: &TaskMonitor) -> FsResult<String> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len();
        Self::md5_from_reader(&mut file, &path.to_string_lossy(), len as i64, monitor)
    }

    /// Compute the MD5 hash from a reader.
    pub fn md5_from_reader<R: Read>(
        reader: &mut R,
        name: &str,
        expected_len: i64,
        monitor: &TaskMonitor,
    ) -> FsResult<String> {
        use md5::{Digest, Md5};

        monitor.initialize(expected_len);
        monitor.set_message(&format!("Hashing {}", name));

        let mut hasher = Md5::new();
        let buf_size: usize = 1024usize.max(
            expected_len
                .try_into()
                .unwrap_or(1024 * 1024)
                .min(1024 * 1024),
        );
        let mut buf = vec![0u8; buf_size];
        let mut total: u64 = 0;

        loop {
            monitor.check_cancelled().map_err(|e| {
                GhidraError::Other(anyhow::anyhow!("Cancelled: {}", e))
            })?;
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total += n as u64;
            monitor.set_progress(total as i64);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Read all text lines from a reader.
    pub fn read_lines<R: Read>(reader: R) -> FsResult<Vec<String>> {
        let br = BufReader::new(reader);
        br.lines()
            .collect::<io::Result<Vec<_>>>()
            .map_err(|e| GhidraError::IoError(e))
    }

    /// Close an object, logging any error. (`uncheckedClose` in Java)
    pub fn unchecked_close<C: FnOnce() -> FsResult<()>>(closer: C, msg: Option<&str>) {
        if let Err(e) = closer() {
            log::warn!(
                "{}: {}",
                msg.unwrap_or("Problem closing object"),
                e
            );
        }
    }

    /// Convert a `HashMap<String, String>` to a multi-line `"key: value\n"` string.
    pub fn info_map_to_string(info: &HashMap<String, String>) -> String {
        let mut s = String::new();
        for (k, v) in info {
            s.push_str(&format!("{}: {}\n", k, v));
        }
        s
    }

    // ------------------------------------------------------------------
    // Timestamp formatting
    // ------------------------------------------------------------------

    /// Format a `SystemTime` or `None` into a standard date+time string.
    pub fn format_timestamp(ts: Option<SystemTime>) -> String {
        match ts {
            None => "NA".into(),
            Some(t) => {
                let dt: chrono::DateTime<chrono::Utc> = t.into();
                dt.format("%d %b %Y %H:%M:%S %Z").to_string()
            }
        }
    }

    /// Pretty-print a byte count.
    pub fn format_size(len: Option<i64>) -> String {
        match len {
            None => "NA".into(),
            Some(l) if l < 0 => "NA".into(),
            Some(l) => {
                let ul = l as u64;
                if ul < 1024 {
                    format!("{} B", ul)
                } else if ul < 1024 * 1024 {
                    format!("{:.1} KB", ul as f64 / 1024.0)
                } else if ul < 1024 * 1024 * 1024 {
                    format!("{:.1} MB", ul as f64 / (1024.0 * 1024.0))
                } else {
                    format!("{:.1} GB", ul as f64 / (1024.0 * 1024.0 * 1024.0))
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // File type detection
    // ------------------------------------------------------------------

    /// Detect the file type from a path.
    pub fn detect_file_type(path: &Path) -> FileType {
        match path.symlink_metadata() {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    FileType::SymbolicLink
                } else if meta.is_dir() {
                    FileType::Directory
                } else if meta.is_file() {
                    FileType::File
                } else {
                    FileType::Unknown
                }
            }
            Err(_) => FileType::Unknown,
        }
    }

    /// Read the target of a symlink. Returns `None` if not a symlink or on error.
    pub fn read_symlink(path: &Path) -> Option<PathBuf> {
        std::fs::read_link(path).ok()
    }

    /// Returns `true` when `path` is a symbolic link.
    pub fn is_symlink(path: &Path) -> bool {
        path.symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Current time in milliseconds since the Unix epoch.
fn current_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // FSRL tests
    // ------------------------------------------------------------------

    #[test]
    fn test_fsrl_root_simple() {
        let fsrl = FSRL::root("/test/file.txt", None);
        assert_eq!(fsrl.path, "/test/file.txt");
        assert_eq!(fsrl.name(), "file.txt");
        assert!(fsrl.md5.is_none());
        assert!(fsrl.parent.is_none());
    }

    #[test]
    fn test_fsrl_with_md5() {
        let fsrl = FSRL::root("/test/file.txt", Some("abc123".into()));
        assert!(fsrl.is_fully_qualified());
        assert!(fsrl.is_md5_equal(Some("ABC123")));
    }

    #[test]
    fn test_fsrl_nested() {
        let parent_fsrl = FSRL::root("/container.zip", Some("md5parent".into()));
        let child = parent_fsrl.with_path("/inside/file.txt");
        assert!(child.parent.is_some());
        assert_eq!(child.path, "/inside/file.txt");
        assert_eq!(child.name(), "file.txt");
    }

    #[test]
    fn test_fsrl_full_path() {
        let root = FSRL::root("/a.zip", None);
        let child = root.with_path("/b.txt");
        assert_eq!(child.full_path(), "/a.zip|/b.txt");
    }

    // ------------------------------------------------------------------
    // FSRLRoot tests
    // ------------------------------------------------------------------

    #[test]
    fn test_fsrl_root_make() {
        let root = FSRLRoot::make_root("file");
        assert_eq!(root.protocol(), "file");
        assert!(!root.has_container());
        assert_eq!(format!("{}", root), "file://");
    }

    #[test]
    fn test_fsrl_root_nested() {
        let container = FSRL::root("/archive.tar", Some("abc".into()));
        let nested = FSRLRoot::nested_fs(&container, "zip");
        assert_eq!(nested.protocol(), "zip");
        assert!(nested.has_container());
    }

    #[test]
    fn test_fsrl_root_with_path_md5() {
        let root = FSRLRoot::make_root("file");
        let child = root.with_path_md5("/dir/f.txt", "deadbeef");
        assert_eq!(child.path, "/dir/f.txt");
        assert_eq!(child.md5, Some("deadbeef".into()));
        assert_eq!(child.name(), "f.txt");
    }

    // ------------------------------------------------------------------
    // GFileImpl tests
    // ------------------------------------------------------------------

    /// A minimal, concrete filesystem for testing.
    struct DummyFs {
        name: String,
        fsrl_root: FSRLRoot,
        ref_mgr: FileSystemRefManager,
        closed: bool,
    }

    impl FileSystem for DummyFs {
        fn name(&self) -> &str {
            &self.name
        }
        fn fs_type(&self) -> &str {
            "dummy"
        }
        fn description(&self) -> &str {
            "test-dummy"
        }
        fn fsrl(&self) -> &FSRLRoot {
            &self.fsrl_root
        }
        fn is_closed(&self) -> bool {
            self.closed
        }
        fn ref_manager(&self) -> &FileSystemRefManager {
            &self.ref_mgr
        }
        fn lookup(
            &self,
            _path: Option<&str>,
            _monitor: &TaskMonitor,
        ) -> FsResult<Option<Arc<dyn GFile>>> {
            Ok(None)
        }
        fn get_listing(&self, _dir: &dyn GFile) -> FsResult<Vec<Arc<dyn GFile>>> {
            Ok(Vec::new())
        }
        fn get_input_stream(
            &self,
            _file: &dyn GFile,
            _monitor: &TaskMonitor,
        ) -> FsResult<Box<dyn Read + Send>> {
            Err(GhidraError::NotSupported("dummy".into()))
        }
        fn get_byte_provider(
            &self,
            _file: &dyn GFile,
            _monitor: &TaskMonitor,
        ) -> FsResult<Box<dyn ByteProvider>> {
            Err(GhidraError::NotSupported("dummy".into()))
        }
        fn close(&mut self) -> FsResult<()> {
            self.closed = true;
            Ok(())
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn make_dummy_fs() -> Arc<DummyFs> {
        Arc::new(DummyFs {
            name: "dummy".into(),
            fsrl_root: FSRLRoot::make_root("dummyfs"),
            ref_mgr: FileSystemRefManager::default(),
            closed: false,
        })
    }

    #[test]
    fn test_gfile_impl() {
        let dummy = make_dummy_fs();
        let gfile_fsrl = FSRL::root("/readme.txt", None);
        let gfile = GFileImpl::new(dummy, None, false, 42, gfile_fsrl);
        assert!(!gfile.is_directory());
        assert_eq!(gfile.length(), 42);
        assert_eq!(gfile.name(), "readme.txt");
        assert!(gfile.parent_file().is_none());
        assert!(gfile.filesystem().is_some());
    }

    // ------------------------------------------------------------------
    // FileSystemManager tests
    // ------------------------------------------------------------------

    #[test]
    fn test_manager_mount_unmount() {
        let mut mgr = FileSystemManager::new().unwrap();
        let dummy = make_dummy_fs();
        let fsrl_root = dummy.fsrl_root.clone();

        let reff = mgr.mount(dummy).unwrap();
        assert!(!reff.is_closed());
        assert!(mgr.is_mounted_at(&fsrl_root));

        drop(reff);
        mgr.unmount(&fsrl_root).unwrap();
        assert!(!mgr.is_mounted_at(&fsrl_root));
    }

    #[test]
    fn test_manager_mounted_filesystems() {
        let mut mgr = FileSystemManager::new().unwrap();
        let dummy = make_dummy_fs();

        let reff = mgr.mount(dummy).unwrap();
        let mounted = mgr.mounted_filesystems();
        assert_eq!(mounted.len(), 1);

        drop(reff);
        mgr.clear();
        assert_eq!(mgr.mounted_filesystems().len(), 0);
    }

    // ------------------------------------------------------------------
    // FsUtils tests
    // ------------------------------------------------------------------

    #[test]
    fn test_append_path() {
        assert_eq!(FsUtils::append_path(&["/a", "b"]).unwrap(), "/a/b");
        assert_eq!(FsUtils::append_path(&["/a/", "/b"]).unwrap(), "/a/b");
        assert_eq!(FsUtils::append_path(&["/a", "", "c"]).unwrap(), "/a/c");
    }

    #[test]
    fn test_append_path_all_empty() {
        assert_eq!(FsUtils::append_path(&["", "", ""]), None);
    }

    #[test]
    fn test_normalize_native_path() {
        let p = FsUtils::normalize_native_path(r"a\b\c");
        assert_eq!(p, "/a/b/c");
    }

    #[test]
    fn test_split_path() {
        let parts = FsUtils::split_path("/dir/dir/file");
        assert_eq!(parts, vec!["", "dir", "dir", "file"]);
    }

    #[test]
    fn test_safe_filename() {
        assert_eq!(FsUtils::safe_filename("hello.txt"), "hello.txt");
        assert_eq!(FsUtils::safe_filename("bad:name"), "bad_name");
        assert_eq!(FsUtils::safe_filename("."), "dot");
        assert_eq!(FsUtils::safe_filename(".."), "dotdot");
        assert_eq!(FsUtils::safe_filename(""), "empty_filename");
    }

    #[test]
    fn test_escape_encode_decode_roundtrip() {
        let original = "hello world % test";
        let encoded = FsUtils::escape_encode(original);
        assert!(encoded.contains("%25"));
        let decoded = FsUtils::escape_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_extension() {
        assert_eq!(
            FsUtils::extension("path/file.ext1.ext2", 1),
            Some(".ext2".into())
        );
        assert_eq!(
            FsUtils::extension("path/file.ext1.ext2", 2),
            Some(".ext1.ext2".into())
        );
        assert_eq!(FsUtils::extension("path/file_noext", 1), None);
    }

    #[test]
    fn test_format_size() {
        assert_eq!(FsUtils::format_size(None), "NA");
        assert_eq!(FsUtils::format_size(Some(-1)), "NA");
        assert_eq!(FsUtils::format_size(Some(500)), "500 B");
        assert_eq!(FsUtils::format_size(Some(2048)), "2.0 KB");
    }

    #[test]
    fn test_gfile_name_type_compare() {
        struct TestGFile {
            name: String,
            is_dir: bool,
            fsrl: FSRL,
        }
        impl GFile for TestGFile {
            fn filesystem(&self) -> Option<Arc<dyn FileSystem>> {
                None
            }
            fn fsrl(&self) -> &FSRL {
                &self.fsrl
            }
            fn parent_file(&self) -> Option<Arc<dyn GFile>> {
                None
            }
            fn path(&self) -> String {
                self.fsrl.path.clone()
            }
            fn name(&self) -> String {
                self.name.clone()
            }
            fn is_directory(&self) -> bool {
                self.is_dir
            }
            fn length(&self) -> i64 {
                0
            }
            fn listing(&self) -> FsResult<Vec<Arc<dyn GFile>>> {
                Ok(Vec::new())
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let dir = TestGFile {
            name: "alpha".into(),
            is_dir: true,
            fsrl: FSRL::root("/a", None),
        };
        let file = TestGFile {
            name: "alpha".into(),
            is_dir: false,
            fsrl: FSRL::root("/b", None),
        };

        assert_eq!(
            FsUtils::gfile_name_type_compare(&dir, &file),
            Ordering::Less
        );
        assert_eq!(
            FsUtils::gfile_name_type_compare(&file, &dir),
            Ordering::Greater
        );
    }

    #[test]
    fn test_is_same_fs() {
        let root1 = FSRLRoot::make_root("a");
        let root2 = FSRLRoot::make_root("b");
        let f1 = root1.with_path("/1");
        let f2 = root1.with_path("/2");
        let f3 = root2.with_path("/3");

        assert!(FsUtils::is_same_fs(&[f1.clone(), f2]));
        assert!(!FsUtils::is_same_fs(&[f1, f3]));
        assert!(FsUtils::is_same_fs(&[]));
    }

    #[test]
    fn test_stream_copy() {
        let data = b"hello world!";
        let mut reader: &[u8] = data;
        let mut writer = Vec::new();
        let monitor = TaskMonitor::new();
        let copied =
            FsUtils::stream_copy(&mut reader, &mut writer, &monitor).unwrap();
        assert_eq!(copied, data.len() as u64);
        assert_eq!(writer, data);
    }

    #[test]
    fn test_mirrored_project_path() {
        assert_eq!(
            FsUtils::mirrored_project_path("/C:/Users/test"),
            "/C/Users/test"
        );
        assert_eq!(FsUtils::mirrored_project_path("/data"), "/data");
    }
}
