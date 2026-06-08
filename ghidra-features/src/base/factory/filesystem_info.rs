//! Filesystem metadata records and factory dependency exceptions.
//!
//! Ported from `ghidra.formats.gfilesystem.factory.FileSystemInfoRec`
//! and `ghidra.formats.gfilesystem.factory.FileSystemFactoryDependencyException`.
//!
//! [`FileSystemInfoRec`] holds the metadata that in Java is attached via
//! the `@FileSystemInfo` annotation on filesystem classes -- type string,
//! description, priority, and a factory reference.  The factory manager
//! uses these records to probe and create filesystems in priority order.
//!
//! [`FileSystemFactoryDependencyException`] is raised when a filesystem
//! factory cannot operate because the runtime environment is missing a
//! required dependency (e.g. a native library or external tool).

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::io;

use super::gfilesystem_factory::GFileSystemFactory;

// ---------------------------------------------------------------------------
// FileSystemFactoryDependencyException
// ---------------------------------------------------------------------------

/// An I/O error indicating that a filesystem factory cannot proceed
/// because a required dependency is missing from the user's environment.
///
/// Ported from `ghidra.formats.gfilesystem.factory.FileSystemFactoryDependencyException`.
#[derive(Debug)]
pub struct FileSystemFactoryDependencyException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl FileSystemFactoryDependencyException {
    /// Creates a new dependency exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Creates a new dependency exception wrapping a source error.
    pub fn with_source(
        message: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(source.into()),
        }
    }

    /// The error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for FileSystemFactoryDependencyException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Filesystem factory dependency error: {}", self.message)
    }
}

impl std::error::Error for FileSystemFactoryDependencyException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as _)
    }
}

// Allow conversion from/to io::Error for use in io::Result chains.
impl From<FileSystemFactoryDependencyException> for io::Error {
    fn from(e: FileSystemFactoryDependencyException) -> Self {
        io::Error::new(io::ErrorKind::NotFound, e)
    }
}

// ---------------------------------------------------------------------------
// FileSystemInfoRec
// ---------------------------------------------------------------------------

/// Holds metadata about a filesystem implementation, corresponding to the
/// `@FileSystemInfo` annotation in Java.
///
/// Each record carries a type string (e.g. "zip", "tar"), a human-readable
/// description, a priority for probe ordering, and a factory that can
/// create instances of the filesystem.
///
/// Ported from `ghidra.formats.gfilesystem.factory.FileSystemInfoRec`.
#[derive(Debug)]
pub struct FileSystemInfoRec {
    /// Filesystem type identifier (lowercase alphanumeric, e.g. "zip", "tar", "cpio").
    fs_type: String,
    /// Human-readable description (e.g. "ZIP Archive Format").
    description: String,
    /// Relative priority -- higher values are probed first.
    priority: i32,
    /// The factory that creates filesystem instances of this type.
    factory: Box<dyn GFileSystemFactory>,
}

impl FileSystemInfoRec {
    /// Regex pattern for valid filesystem type strings: `[a-z0-9]+`.
    const VALID_TYPE_PATTERN: &'static str = r"^[a-z0-9]+$";

    /// Creates a new filesystem info record.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `fs_type` contains characters outside `[a-z0-9]`.
    pub fn new(
        fs_type: impl Into<String>,
        description: impl Into<String>,
        priority: i32,
        factory: Box<dyn GFileSystemFactory>,
    ) -> Result<Self, String> {
        let fs_type = fs_type.into();
        if !Self::is_valid_type(&fs_type) {
            return Err(format!(
                "Bad GFileSystem type specified: '{}', must match [a-z0-9]+",
                fs_type
            ));
        }
        Ok(Self {
            fs_type,
            description: description.into(),
            priority,
            factory,
        })
    }

    /// Creates a new record without type validation (for internal use).
    pub(crate) fn new_unchecked(
        fs_type: String,
        description: String,
        priority: i32,
        factory: Box<dyn GFileSystemFactory>,
    ) -> Self {
        Self {
            fs_type,
            description,
            priority,
            factory,
        }
    }

    /// Returns `true` if the type string matches `[a-z0-9]+`.
    pub fn is_valid_type(fs_type: &str) -> bool {
        !fs_type.is_empty() && fs_type.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    }

    /// The filesystem type identifier.
    pub fn fs_type(&self) -> &str {
        &self.fs_type
    }

    /// The human-readable description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// The relative priority (higher = probed first).
    pub fn priority(&self) -> i32 {
        self.priority
    }

    /// A reference to the factory.
    pub fn factory(&self) -> &dyn GFileSystemFactory {
        self.factory.as_ref()
    }

    /// Compares two records by priority (descending -- higher priority first).
    pub fn compare_by_priority(a: &FileSystemInfoRec, b: &FileSystemInfoRec) -> Ordering {
        b.priority.cmp(&a.priority)
    }
}

impl fmt::Display for FileSystemInfoRec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FileSystemInfo(type={}, desc={}, priority={})",
            self.fs_type, self.description, self.priority
        )
    }
}

// ---------------------------------------------------------------------------
// FileSystemInfoRegistry
// ---------------------------------------------------------------------------

/// A registry of [`FileSystemInfoRec`] entries, indexed by type.
///
/// This corresponds to the management logic in `FileSystemFactoryMgr`
/// that collects `@FileSystemInfo` annotations from filesystem classes
/// and uses them for probe ordering.
///
/// Ported from the collection side of `FileSystemFactoryMgr`.
#[derive(Debug)]
pub struct FileSystemInfoRegistry {
    records: Vec<FileSystemInfoRec>,
    by_type: HashMap<String, usize>,
}

impl FileSystemInfoRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            by_type: HashMap::new(),
        }
    }

    /// Registers a filesystem info record.
    ///
    /// If a record with the same type already exists, it is replaced.
    pub fn register(&mut self, record: FileSystemInfoRec) {
        let fs_type = record.fs_type().to_string();
        if let Some(&idx) = self.by_type.get(&fs_type) {
            self.records[idx] = record;
        } else {
            let idx = self.records.len();
            self.by_type.insert(fs_type, idx);
            self.records.push(record);
        }
    }

    /// Returns the number of registered records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Looks up a record by filesystem type.
    pub fn get(&self, fs_type: &str) -> Option<&FileSystemInfoRec> {
        self.by_type.get(fs_type).map(|&idx| &self.records[idx])
    }

    /// Returns whether a type is registered.
    pub fn contains_type(&self, fs_type: &str) -> bool {
        self.by_type.contains_key(fs_type)
    }

    /// Returns all records sorted by descending priority.
    pub fn sorted_by_priority(&self) -> Vec<&FileSystemInfoRec> {
        let mut refs: Vec<&FileSystemInfoRec> = self.records.iter().collect();
        refs.sort_by(|a, b| FileSystemInfoRec::compare_by_priority(a, b));
        refs
    }

    /// Returns all registered filesystem type strings.
    pub fn all_types(&self) -> Vec<&str> {
        self.records.iter().map(|r| r.fs_type()).collect()
    }

    /// Returns all registered descriptions.
    pub fn all_descriptions(&self) -> Vec<&str> {
        self.records.iter().map(|r| r.description()).collect()
    }

    /// Removes a record by filesystem type. Returns `true` if removed.
    pub fn remove(&mut self, fs_type: &str) -> bool {
        if let Some(idx) = self.by_type.remove(fs_type) {
            self.records.swap_remove(idx);
            // Fix up the index that was moved by swap_remove
            if idx < self.records.len() {
                let moved_type = self.records[idx].fs_type().to_string();
                self.by_type.insert(moved_type, idx);
            }
            true
        } else {
            false
        }
    }

    /// Clears all records.
    pub fn clear(&mut self) {
        self.records.clear();
        self.by_type.clear();
    }
}

impl Default for FileSystemInfoRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::factory::gfilesystem_factory::GFileSystemFactoryIgnore;

    // --- FileSystemFactoryDependencyException ---

    #[test]
    fn test_dependency_exception_display() {
        let e = FileSystemFactoryDependencyException::new("libz not found");
        assert!(format!("{}", e).contains("libz not found"));
    }

    #[test]
    fn test_dependency_exception_message() {
        let e = FileSystemFactoryDependencyException::new("missing native lib");
        assert_eq!(e.message(), "missing native lib");
    }

    #[test]
    fn test_dependency_exception_with_source() {
        let inner = io::Error::new(io::ErrorKind::NotFound, "file missing");
        let e = FileSystemFactoryDependencyException::with_source("cannot load plugin", inner);
        let err: &dyn std::error::Error = &e;
        assert!(err.source().is_some());
    }

    #[test]
    fn test_dependency_exception_is_std_error() {
        let e: Box<dyn std::error::Error> =
            Box::new(FileSystemFactoryDependencyException::new("test err"));
        assert!(e.to_string().contains("test err"));
    }

    #[test]
    fn test_dependency_exception_to_io_error() {
        let e = FileSystemFactoryDependencyException::new("missing dep");
        let io_err: io::Error = e.into();
        assert_eq!(io_err.kind(), io::ErrorKind::NotFound);
    }

    // --- FileSystemInfoRec ---

    #[test]
    fn test_info_rec_valid_type() {
        let factory = Box::new(GFileSystemFactoryIgnore::new("zip"));
        let rec = FileSystemInfoRec::new("zip", "ZIP Archive", 10, factory);
        assert!(rec.is_ok());
        let rec = rec.unwrap();
        assert_eq!(rec.fs_type(), "zip");
        assert_eq!(rec.description(), "ZIP Archive");
        assert_eq!(rec.priority(), 10);
    }

    #[test]
    fn test_info_rec_invalid_type_uppercase() {
        let factory = Box::new(GFileSystemFactoryIgnore::new("Zip"));
        let rec = FileSystemInfoRec::new("Zip", "ZIP Archive", 10, factory);
        assert!(rec.is_err());
        assert!(rec.unwrap_err().contains("Bad GFileSystem type"));
    }

    #[test]
    fn test_info_rec_invalid_type_special_char() {
        let factory = Box::new(GFileSystemFactoryIgnore::new("my-fs"));
        let rec = FileSystemInfoRec::new("my-fs", "Custom FS", 5, factory);
        assert!(rec.is_err());
    }

    #[test]
    fn test_info_rec_invalid_type_empty() {
        let factory = Box::new(GFileSystemFactoryIgnore::new(""));
        let rec = FileSystemInfoRec::new("", "Empty", 0, factory);
        assert!(rec.is_err());
    }

    #[test]
    fn test_info_rec_valid_type_alphanumeric() {
        let factory = Box::new(GFileSystemFactoryIgnore::new("cpio"));
        let rec = FileSystemInfoRec::new("cpio123", "CPIO archive", 5, factory);
        assert!(rec.is_ok());
    }

    #[test]
    fn test_info_rec_display() {
        let factory = Box::new(GFileSystemFactoryIgnore::new("tar"));
        let rec = FileSystemInfoRec::new("tar", "TAR Archive", 8, factory).unwrap();
        let s = format!("{}", rec);
        assert!(s.contains("tar"));
        assert!(s.contains("TAR Archive"));
        assert!(s.contains("8"));
    }

    #[test]
    fn test_info_rec_compare_by_priority() {
        let f1 = Box::new(GFileSystemFactoryIgnore::new("a"));
        let f2 = Box::new(GFileSystemFactoryIgnore::new("b"));
        let r1 = FileSystemInfoRec::new("a", "A", 5, f1).unwrap();
        let r2 = FileSystemInfoRec::new("b", "B", 10, f2).unwrap();

        // r2 has higher priority, so compare_by_priority returns Greater for r1 vs r2
        // (higher priority sorts first: b.cmp(a) pattern)
        assert_eq!(
            FileSystemInfoRec::compare_by_priority(&r1, &r2),
            Ordering::Greater
        );
        assert_eq!(
            FileSystemInfoRec::compare_by_priority(&r2, &r1),
            Ordering::Less
        );
    }

    #[test]
    fn test_is_valid_type() {
        assert!(FileSystemInfoRec::is_valid_type("zip"));
        assert!(FileSystemInfoRec::is_valid_type("tar"));
        assert!(FileSystemInfoRec::is_valid_type("cpio"));
        assert!(FileSystemInfoRec::is_valid_type("7z"));
        assert!(FileSystemInfoRec::is_valid_type("fs2"));
        assert!(!FileSystemInfoRec::is_valid_type(""));
        assert!(!FileSystemInfoRec::is_valid_type("ZIP"));
        assert!(!FileSystemInfoRec::is_valid_type("my-fs"));
        assert!(!FileSystemInfoRec::is_valid_type("my_fs"));
        assert!(!FileSystemInfoRec::is_valid_type(" "));
    }

    // --- FileSystemInfoRegistry ---

    #[test]
    fn test_registry_empty() {
        let reg = FileSystemInfoRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn test_registry_register_and_lookup() {
        let mut reg = FileSystemInfoRegistry::new();
        let f = Box::new(GFileSystemFactoryIgnore::new("zip"));
        reg.register(FileSystemInfoRec::new("zip", "ZIP", 10, f).unwrap());

        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
        assert!(reg.contains_type("zip"));
        assert!(!reg.contains_type("tar"));

        let rec = reg.get("zip").unwrap();
        assert_eq!(rec.fs_type(), "zip");
        assert_eq!(rec.priority(), 10);
    }

    #[test]
    fn test_registry_sorted_by_priority() {
        let mut reg = FileSystemInfoRegistry::new();

        let f1 = Box::new(GFileSystemFactoryIgnore::new("a"));
        let f2 = Box::new(GFileSystemFactoryIgnore::new("b"));
        let f3 = Box::new(GFileSystemFactoryIgnore::new("c"));

        reg.register(FileSystemInfoRec::new("a", "A", 5, f1).unwrap());
        reg.register(FileSystemInfoRec::new("b", "B", 20, f2).unwrap());
        reg.register(FileSystemInfoRec::new("c", "C", 10, f3).unwrap());

        let sorted = reg.sorted_by_priority();
        assert_eq!(sorted[0].fs_type(), "b"); // priority 20
        assert_eq!(sorted[1].fs_type(), "c"); // priority 10
        assert_eq!(sorted[2].fs_type(), "a"); // priority 5
    }

    #[test]
    fn test_registry_all_types() {
        let mut reg = FileSystemInfoRegistry::new();
        let f1 = Box::new(GFileSystemFactoryIgnore::new("x"));
        let f2 = Box::new(GFileSystemFactoryIgnore::new("y"));
        reg.register(FileSystemInfoRec::new("x", "X", 1, f1).unwrap());
        reg.register(FileSystemInfoRec::new("y", "Y", 2, f2).unwrap());

        let types = reg.all_types();
        assert_eq!(types.len(), 2);
        assert!(types.contains(&"x"));
        assert!(types.contains(&"y"));
    }

    #[test]
    fn test_registry_replace_existing() {
        let mut reg = FileSystemInfoRegistry::new();

        let f1 = Box::new(GFileSystemFactoryIgnore::new("zip"));
        reg.register(FileSystemInfoRec::new("zip", "ZIP v1", 10, f1).unwrap());

        let f2 = Box::new(GFileSystemFactoryIgnore::new("zip"));
        reg.register(FileSystemInfoRec::new("zip", "ZIP v2", 20, f2).unwrap());

        assert_eq!(reg.len(), 1);
        let rec = reg.get("zip").unwrap();
        assert_eq!(rec.description(), "ZIP v2");
        assert_eq!(rec.priority(), 20);
    }

    #[test]
    fn test_registry_remove() {
        let mut reg = FileSystemInfoRegistry::new();
        let f = Box::new(GFileSystemFactoryIgnore::new("tar"));
        reg.register(FileSystemInfoRec::new("tar", "TAR", 5, f).unwrap());

        assert!(reg.remove("tar"));
        assert!(!reg.contains_type("tar"));
        assert!(reg.is_empty());
    }

    #[test]
    fn test_registry_remove_nonexistent() {
        let mut reg = FileSystemInfoRegistry::new();
        assert!(!reg.remove("nope"));
    }

    #[test]
    fn test_registry_clear() {
        let mut reg = FileSystemInfoRegistry::new();
        let f1 = Box::new(GFileSystemFactoryIgnore::new("a"));
        let f2 = Box::new(GFileSystemFactoryIgnore::new("b"));
        reg.register(FileSystemInfoRec::new("a", "A", 1, f1).unwrap());
        reg.register(FileSystemInfoRec::new("b", "B", 2, f2).unwrap());

        reg.clear();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn test_registry_all_descriptions() {
        let mut reg = FileSystemInfoRegistry::new();
        let f1 = Box::new(GFileSystemFactoryIgnore::new("a"));
        let f2 = Box::new(GFileSystemFactoryIgnore::new("b"));
        reg.register(FileSystemInfoRec::new("a", "Alpha", 1, f1).unwrap());
        reg.register(FileSystemInfoRec::new("b", "Beta", 2, f2).unwrap());

        let descs = reg.all_descriptions();
        assert_eq!(descs.len(), 2);
        assert!(descs.contains(&"Alpha"));
        assert!(descs.contains(&"Beta"));
    }
}
