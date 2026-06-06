//! Ghidra virtual file system (GFileSystem) framework.
//!
//! Ported from `ghidra.formats.gfilesystem`.
//!
//! Provides a virtual filesystem abstraction for browsing archive contents
//! (ZIP, TAR, GZ, etc.) with nested container support, reference counting,
//! caching, and an FSRL (File System Resource Locator) addressing scheme.
//!
//! # Architecture
//!
//! - [`Fsrl`] -- immutable, hierarchical resource locator (like a URI).
//! - [`FsrlRoot`] -- the filesystem-root portion of an FSRL.
//! - [`GFile`] -- a file entry in a virtual filesystem.
//! - [`GFileSystem`] -- trait for filesystem implementations.
//! - [`FileSystemRef`] -- RAII reference-counted handle to an open filesystem.
//! - [`FileSystemIndexHelper`] -- index of files by path.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, Weak};

// ---------------------------------------------------------------------------
// FSRL -- File System Resource Locator
// ---------------------------------------------------------------------------

/// A File System Resource Locator.
///
/// Immutable, hierarchical addressing scheme for files inside nested
/// virtual filesystems. Format: `fstype://path?MD5=hash|childfs://childpath?MD5=hash|...`
///
/// Examples:
/// - `file://dir/subdir`
/// - `file://dir/example.zip|zip://readme.txt`
/// - `file://dir/example.zip|zip://nested.tar|tar://file.txt?MD5=abcdef`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fsrl {
    /// Parent FSRL (the container that holds this file).
    parent: Option<Box<Fsrl>>,
    /// The FSRL root (filesystem type and container).
    fs: FsrlRoot,
    /// Path within the filesystem.
    path: Option<String>,
    /// Optional MD5 hash.
    md5: Option<String>,
}

impl Fsrl {
    /// Create a new FSRL with the given root, path, and optional MD5.
    pub fn new(fs: FsrlRoot, path: Option<String>, md5: Option<String>) -> Self {
        Self {
            parent: None,
            fs,
            path,
            md5,
        }
    }

    /// Create a nested FSRL with a parent container.
    pub fn nested(parent: Fsrl, fs: FsrlRoot, path: Option<String>, md5: Option<String>) -> Self {
        Self {
            parent: Some(Box::new(parent)),
            fs,
            path,
            md5,
        }
    }

    /// Parse an FSRL from its string representation.
    ///
    /// Format: `fstype://path[?MD5=hash][|childfstype://childpath[?MD5=hash]]...`
    pub fn from_string(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split('|').collect();
        let mut current: Option<Fsrl> = None;

        for part in parts {
            let part = part.trim();
            let colon_pos = part
                .find("://")
                .ok_or_else(|| format!("Missing '://' in FSRL part: {part}"))?;

            let proto = &part[..colon_pos];
            let mut path_and_params = &part[colon_pos + 3..];

            let mut md5 = None;
            if let Some(qpos) = path_and_params.find('?') {
                let params = &path_and_params[qpos + 1..];
                path_and_params = &path_and_params[..qpos];
                for param in params.split('&') {
                    if let Some(eq) = param.find('=') {
                        let key = &param[..eq];
                        let val = &param[eq + 1..];
                        if key == "MD5" {
                            md5 = Some(val.to_string());
                        }
                    }
                }
            }

            let path = if path_and_params.is_empty() {
                None
            } else {
                Some(path_and_params.to_string())
            };

            let fs = FsrlRoot::new(proto.to_string());
            let fsrl = match current {
                Some(parent) => Fsrl::nested(parent, fs, path, md5),
                None => Fsrl::new(fs, path, md5),
            };
            current = Some(fsrl);
        }

        current.ok_or_else(|| "Empty FSRL string".to_string())
    }

    /// The filesystem root.
    pub fn fs(&self) -> &FsrlRoot {
        &self.fs
    }

    /// The parent FSRL (container file), if any.
    pub fn parent(&self) -> Option<&Fsrl> {
        self.parent.as_deref()
    }

    /// The path within the filesystem (None for a root FSRL).
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// The file name (last component of the path).
    pub fn name(&self) -> Option<&str> {
        self.path.as_deref().and_then(|p| {
            // Handle trailing slashes
            let trimmed = p.trim_end_matches('/');
            trimmed.rsplit('/').next()
        })
    }

    /// The MD5 hash, if present.
    pub fn md5(&self) -> Option<&str> {
        self.md5.as_deref()
    }

    /// Create a new FSRL with the same root and path but a different MD5.
    pub fn with_md5(&self, md5: Option<String>) -> Self {
        Self {
            parent: self.parent.clone(),
            fs: self.fs.clone(),
            path: self.path.clone(),
            md5,
        }
    }

    /// Create a new FSRL with the same root but a different path.
    pub fn with_path(&self, path: Option<String>) -> Self {
        Self {
            parent: self.parent.clone(),
            fs: self.fs.clone(),
            path,
            md5: None,
        }
    }

    /// Append a relative path component.
    pub fn append_path(&self, rel_path: &str) -> Self {
        let new_path = match &self.path {
            Some(base) => {
                if base.ends_with('/') {
                    format!("{base}{rel_path}")
                } else {
                    format!("{base}/{rel_path}")
                }
            }
            None => format!("/{rel_path}"),
        };
        self.with_path(Some(new_path))
    }

    /// Create a nested FSRL for a child filesystem type.
    pub fn make_nested(&self, fs_type: &str) -> Fsrl {
        Fsrl::nested(
            self.clone(),
            FsrlRoot::new(fs_type.to_string()),
            None,
            None,
        )
    }

    /// Number of nesting levels (1 for a simple FSRL, 2+ for nested).
    pub fn nesting_depth(&self) -> usize {
        let mut depth = 1;
        let mut current = self.parent.as_deref();
        while let Some(p) = current {
            depth += 1;
            current = p.parent.as_deref();
        }
        depth
    }

    /// Split into a list of FSRLs, one per nesting level.
    pub fn split(&self) -> Vec<&Fsrl> {
        let mut result = Vec::new();
        let mut current = Some(self);
        while let Some(fsrl) = current {
            result.push(fsrl);
            current = fsrl.parent.as_deref();
        }
        result.reverse();
        result
    }

    /// Test if this FSRL is equivalent to the other (ignoring MD5).
    pub fn is_equivalent(&self, other: &Fsrl) -> bool {
        self.fs == other.fs && self.path == other.path && self.parent_equivalent(other)
    }

    fn parent_equivalent(&self, other: &Fsrl) -> bool {
        match (&self.parent, &other.parent) {
            (None, None) => true,
            (Some(a), Some(b)) => a.is_equivalent(b),
            _ => false,
        }
    }
}

impl fmt::Display for Fsrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(parent) = &self.parent {
            write!(f, "{parent}|")?;
        }
        write!(f, "{}://", self.fs.fs_type)?;
        if let Some(path) = &self.path {
            write!(f, "{path}")?;
        }
        if let Some(md5) = &self.md5 {
            write!(f, "?MD5={md5}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FSRLRoot
// ---------------------------------------------------------------------------

/// The filesystem-root portion of an FSRL.
///
/// Identifies the filesystem type (e.g., "file", "zip", "tar") and
/// optionally references the container file that holds this filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FsrlRoot {
    /// The filesystem type identifier (e.g., "file", "zip", "tar", "cpio").
    fs_type: String,
}

impl FsrlRoot {
    /// Create a new filesystem root with the given type.
    pub fn new(fs_type: String) -> Self {
        Self { fs_type }
    }

    /// The filesystem type string.
    pub fn fs_type(&self) -> &str {
        &self.fs_type
    }

    /// Create the local filesystem root.
    pub fn local() -> Self {
        Self::new("file".to_string())
    }
}

impl fmt::Display for FsrlRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://", self.fs_type)
    }
}

// ---------------------------------------------------------------------------
// GFile
// ---------------------------------------------------------------------------

/// A file entry in a [`GFileSystem`].
///
/// Each file has a name, path, optional length, and a flag indicating whether
/// it is a directory.
#[derive(Debug, Clone)]
pub struct GFile {
    /// The owning filesystem's FSRL root.
    fs_root: FsrlRoot,
    /// The FSRL of this file.
    fsrl: Fsrl,
    /// Path within the filesystem.
    path: String,
    /// File name.
    name: String,
    /// Whether this is a directory.
    is_directory: bool,
    /// File length in bytes (-1 if unknown).
    length: i64,
}

impl GFile {
    /// Create a new file entry.
    pub fn new(
        fs_root: FsrlRoot,
        path: String,
        name: String,
        is_directory: bool,
        length: i64,
    ) -> Self {
        let fsrl = Fsrl::new(fs_root.clone(), Some(path.clone()), None);
        Self {
            fs_root,
            fsrl,
            path,
            name,
            is_directory,
            length,
        }
    }

    /// The FSRL of this file.
    pub fn fsrl(&self) -> &Fsrl {
        &self.fsrl
    }

    /// Path within the filesystem.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// File name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether this is a directory.
    pub fn is_directory(&self) -> bool {
        self.is_directory
    }

    /// File length in bytes, or -1 if unknown.
    pub fn length(&self) -> i64 {
        self.length
    }
}

// ---------------------------------------------------------------------------
// GFileSystem trait
// ---------------------------------------------------------------------------

/// Trait for virtual filesystem implementations.
///
/// Filesystem implementations must provide `lookup`, `get_listing`, and
/// lifecycle methods (`close`, `is_closed`).
pub trait GFileSystem: Send + Sync {
    /// The human-readable filesystem name (typically the container filename).
    fn name(&self) -> &str;

    /// The filesystem type identifier (e.g., "zip", "tar", "cpio").
    fn fs_type(&self) -> &str;

    /// The filesystem's FSRL root.
    fn fsrl_root(&self) -> &FsrlRoot;

    /// Whether the filesystem has been closed.
    fn is_closed(&self) -> bool;

    /// Close the filesystem and release resources.
    fn close(&mut self);

    /// Number of files, or -1 if unknown.
    fn file_count(&self) -> i64 {
        -1
    }

    /// Look up a file by path. Returns `None` if not found.
    fn lookup(&self, path: &str) -> Option<GFile>;

    /// Get the listing of files in a directory. `None` means root.
    fn get_listing(&self, directory: Option<&GFile>) -> Vec<GFile>;

    /// Get the root directory.
    fn root_dir(&self) -> Option<GFile> {
        self.lookup("")
    }
}

// ---------------------------------------------------------------------------
// FileSystemRef -- RAII reference-counted handle
// ---------------------------------------------------------------------------

/// RAII reference-counted handle to a [`GFileSystem`].
///
/// The filesystem is kept alive as long as at least one reference exists.
#[derive(Clone)]
pub struct FileSystemRef {
    inner: Arc<Mutex<Box<dyn GFileSystem>>>,
    label: String,
}

impl std::fmt::Debug for FileSystemRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSystemRef")
            .field("label", &self.label)
            .field("strong_count", &Arc::strong_count(&self.inner))
            .finish()
    }
}

impl FileSystemRef {
    /// Create a new reference wrapping a filesystem.
    pub fn new(fs: Box<dyn GFileSystem>) -> Self {
        let label = fs.name().to_string();
        Self {
            inner: Arc::new(Mutex::new(fs)),
            label,
        }
    }

    /// The label (usually the filesystem name).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Get the number of strong references.
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    /// Execute a closure with read access to the filesystem.
    pub fn with_fs<R>(&self, f: impl FnOnce(&dyn GFileSystem) -> R) -> R {
        let fs = self.inner.lock().unwrap();
        f(fs.as_ref())
    }

    /// Execute a closure with mutable access to the filesystem.
    pub fn with_fs_mut<R>(&self, f: impl FnOnce(&mut dyn GFileSystem) -> R) -> R {
        let mut fs = self.inner.lock().unwrap();
        f(fs.as_mut())
    }
}

// ---------------------------------------------------------------------------
// FileSystemIndexHelper
// ---------------------------------------------------------------------------

/// Index of files in a filesystem, keyed by path.
#[derive(Debug)]
pub struct FileSystemIndexHelper {
    by_path: HashMap<String, GFile>,
    by_name: HashMap<String, Vec<GFile>>,
}

impl FileSystemIndexHelper {
    /// Create an empty index.
    pub fn new() -> Self {
        Self {
            by_path: HashMap::new(),
            by_name: HashMap::new(),
        }
    }

    /// Add a file to the index.
    pub fn add_file(&mut self, file: GFile) {
        self.by_path.insert(file.path().to_string(), file.clone());
        self.by_name
            .entry(file.name().to_string())
            .or_default()
            .push(file);
    }

    /// Look up a file by its full path.
    pub fn lookup_by_path(&self, path: &str) -> Option<&GFile> {
        self.by_path.get(path)
    }

    /// Look up files by name (may return multiple matches in different directories).
    pub fn lookup_by_name(&self, name: &str) -> Option<&Vec<GFile>> {
        self.by_name.get(name)
    }

    /// Total number of indexed files.
    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }

    /// Iterate over all indexed files.
    pub fn files(&self) -> impl Iterator<Item = &GFile> {
        self.by_path.values()
    }
}

impl Default for FileSystemIndexHelper {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FileSystemInstanceManager
// ---------------------------------------------------------------------------

/// Manages open filesystem instances with reference counting.
#[derive(Debug)]
pub struct FileSystemInstanceManager {
    /// Open filesystems keyed by FSRL root.
    instances: HashMap<FsrlRoot, FileSystemRef>,
}

impl FileSystemInstanceManager {
    /// Create a new instance manager.
    pub fn new() -> Self {
        Self {
            instances: HashMap::new(),
        }
    }

    /// Add a filesystem to the manager.
    pub fn add(&mut self, fs_ref: FileSystemRef) {
        let key = fs_ref.with_fs(|fs| fs.fsrl_root().clone());
        self.instances.insert(key, fs_ref);
    }

    /// Get a reference to a filesystem by its FSRL root.
    pub fn get(&self, root: &FsrlRoot) -> Option<&FileSystemRef> {
        self.instances.get(root)
    }

    /// Remove a filesystem from the manager.
    pub fn remove(&mut self, root: &FsrlRoot) -> Option<FileSystemRef> {
        self.instances.remove(root)
    }

    /// Close all filesystems with only one reference (the manager's own).
    pub fn close_all_unused(&mut self) {
        self.instances.retain(|_, fs_ref| {
            if fs_ref.strong_count() <= 1 {
                fs_ref.with_fs_mut(|fs| fs.close());
                false
            } else {
                true
            }
        });
    }

    /// Number of open filesystems.
    pub fn len(&self) -> usize {
        self.instances.len()
    }

    /// Whether there are no open filesystems.
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }

    /// Close and remove all filesystems.
    pub fn clear(&mut self) {
        for (_, fs_ref) in self.instances.drain() {
            fs_ref.with_fs_mut(|fs| fs.close());
        }
    }
}

impl Default for FileSystemInstanceManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CryptoProvider -- password provider for encrypted archives
// ---------------------------------------------------------------------------

/// Trait for providing passwords when opening encrypted filesystems.
pub trait PasswordProvider: Send + Sync {
    /// Get a password for the given FSRL. Returns `None` if the user cancelled.
    fn get_password(&self, fsrl: &Fsrl) -> Option<String>;
}

// ---------------------------------------------------------------------------
// FileAttribute / FileAttributes
// ---------------------------------------------------------------------------

/// A single file attribute (name/value pair with a type group).
#[derive(Debug, Clone)]
pub struct FileAttribute {
    /// Attribute name.
    pub name: String,
    /// Attribute value as string.
    pub value: String,
    /// Attribute type group for categorization.
    pub group: FileAttributeGroup,
}

/// Groups for file attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileAttributeGroup {
    /// Basic file info (name, size, timestamps).
    Basic,
    /// Security/permission info.
    Security,
    /// Format-specific metadata.
    Metadata,
    /// Other/custom attributes.
    Other,
}

/// A collection of file attributes.
#[derive(Debug, Clone, Default)]
pub struct FileAttributes {
    attrs: Vec<FileAttribute>,
}

impl FileAttributes {
    /// An empty attribute set.
    pub const EMPTY: Self = Self { attrs: Vec::new() };

    /// Create a new empty attribute set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an attribute.
    pub fn push(&mut self, attr: FileAttribute) {
        self.attrs.push(attr);
    }

    /// Get all attributes.
    pub fn attributes(&self) -> &[FileAttribute] {
        &self.attrs
    }

    /// Find an attribute by name.
    pub fn get(&self, name: &str) -> Option<&FileAttribute> {
        self.attrs.iter().find(|a| a.name == name)
    }

    /// Number of attributes.
    pub fn len(&self) -> usize {
        self.attrs.len()
    }

    /// Whether there are no attributes.
    pub fn is_empty(&self) -> bool {
        self.attrs.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fsrl_parse_simple() {
        let fsrl = Fsrl::from_string("file://dir/subdir").unwrap();
        assert_eq!(fsrl.fs().fs_type(), "file");
        assert_eq!(fsrl.path(), Some("dir/subdir"));
        assert!(fsrl.parent().is_none());
        assert!(fsrl.md5().is_none());
    }

    #[test]
    fn test_fsrl_parse_nested() {
        let fsrl = Fsrl::from_string("file://dir/example.zip|zip://readme.txt").unwrap();
        assert_eq!(fsrl.fs().fs_type(), "zip");
        assert_eq!(fsrl.path(), Some("readme.txt"));
        assert!(fsrl.parent().is_some());
        assert_eq!(fsrl.parent().unwrap().fs().fs_type(), "file");
    }

    #[test]
    fn test_fsrl_parse_with_md5() {
        let fsrl = Fsrl::from_string("file://dir/f.txt?MD5=abcdef123456").unwrap();
        assert_eq!(fsrl.md5(), Some("abcdef123456"));
    }

    #[test]
    fn test_fsrl_parse_deeply_nested() {
        let fsrl = Fsrl::from_string(
            "file://dir/example.zip|zip://nested.tar|tar://file.txt?MD5=abc",
        )
        .unwrap();
        assert_eq!(fsrl.fs().fs_type(), "tar");
        assert_eq!(fsrl.path(), Some("file.txt"));
        assert_eq!(fsrl.nesting_depth(), 3);
    }

    #[test]
    fn test_fsrl_display_roundtrip() {
        let input = "file://dir/example.zip|zip://readme.txt";
        let fsrl = Fsrl::from_string(input).unwrap();
        assert_eq!(fsrl.to_string(), input);
    }

    #[test]
    fn test_fsrl_display_with_md5() {
        let input = "file://dir/f.txt?MD5=abc123";
        let fsrl = Fsrl::from_string(input).unwrap();
        assert_eq!(fsrl.to_string(), input);
    }

    #[test]
    fn test_fsrl_name() {
        let fsrl = Fsrl::from_string("file://dir/subdir/filename.txt").unwrap();
        assert_eq!(fsrl.name(), Some("filename.txt"));
    }

    #[test]
    fn test_fsrl_append_path() {
        let fsrl = Fsrl::from_string("file://dir").unwrap();
        let child = fsrl.append_path("child.txt");
        assert_eq!(child.path(), Some("dir/child.txt"));
    }

    #[test]
    fn test_fsrl_with_md5() {
        let fsrl = Fsrl::from_string("file://dir/f.txt").unwrap();
        let with_hash = fsrl.with_md5(Some("hash123".into()));
        assert_eq!(with_hash.md5(), Some("hash123"));
    }

    #[test]
    fn test_fsrl_equivalence() {
        let a = Fsrl::from_string("file://dir/f.txt?MD5=abc").unwrap();
        let b = Fsrl::from_string("file://dir/f.txt?MD5=xyz").unwrap();
        assert!(a.is_equivalent(&b)); // same except MD5
    }

    #[test]
    fn test_fsrl_split() {
        let fsrl =
            Fsrl::from_string("file://dir/example.zip|zip://readme.txt").unwrap();
        let parts = fsrl.split();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].fs().fs_type(), "file");
        assert_eq!(parts[1].fs().fs_type(), "zip");
    }

    #[test]
    fn test_fsrl_make_nested() {
        let fsrl = Fsrl::from_string("file://dir/archive.zip").unwrap();
        let nested = fsrl.make_nested("zip");
        assert_eq!(nested.fs().fs_type(), "zip");
        assert!(nested.parent().is_some());
    }

    #[test]
    fn test_fsrl_parse_error() {
        assert!(Fsrl::from_string("bad format").is_err());
        assert!(Fsrl::from_string("").is_err());
    }

    #[test]
    fn test_fsrl_root_local() {
        let root = FsrlRoot::local();
        assert_eq!(root.fs_type(), "file");
    }

    #[test]
    fn test_gfile_creation() {
        let root = FsrlRoot::new("zip".into());
        let file = GFile::new(root, "/readme.txt".into(), "readme.txt".into(), false, 1234);
        assert_eq!(file.name(), "readme.txt");
        assert_eq!(file.path(), "/readme.txt");
        assert!(!file.is_directory());
        assert_eq!(file.length(), 1234);
    }

    #[test]
    fn test_gfile_directory() {
        let root = FsrlRoot::new("zip".into());
        let dir = GFile::new(root, "/subdir".into(), "subdir".into(), true, -1);
        assert!(dir.is_directory());
    }

    #[test]
    fn test_filesystem_index_helper() {
        let mut index = FileSystemIndexHelper::new();
        let root = FsrlRoot::new("zip".into());
        let f1 = GFile::new(root.clone(), "/a.txt".into(), "a.txt".into(), false, 100);
        let f2 = GFile::new(root, "/b.txt".into(), "b.txt".into(), false, 200);
        index.add_file(f1);
        index.add_file(f2);
        assert_eq!(index.len(), 2);
        assert!(index.lookup_by_path("/a.txt").is_some());
        assert!(index.lookup_by_name("b.txt").is_some());
        assert!(index.lookup_by_path("/missing.txt").is_none());
    }

    #[test]
    fn test_filesystem_instance_manager() {
        let mut mgr = FileSystemInstanceManager::new();
        assert!(mgr.is_empty());
        // Manager lifecycle test (no real FS, just structure)
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn test_file_attributes() {
        let mut attrs = FileAttributes::new();
        attrs.push(FileAttribute {
            name: "size".into(),
            value: "1024".into(),
            group: FileAttributeGroup::Basic,
        });
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs.get("size").unwrap().value, "1024");
        assert!(attrs.get("missing").is_none());
    }
}
