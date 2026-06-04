//! Database subpackage for the filesystem store.
//!
//! Provides types for managing database files within the store:
//! [`PrivateDatabase`], [`VersionedDatabase`], [`PackedDatabase`], and
//! [`PackedDatabaseCache`].
//!
//! These are structural stubs that define the API surface. The actual
//! buffer-file I/O (which in Ghidra relies on `db.buffers.*`) will be
//! implemented when that subsystem is ported.
//!
//! Corresponds to `ghidra.framework.store.db.*`.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::GhidraError;
use super::StoreResult;

// ============================================================================
// VersionedDBListener trait
// ============================================================================

/// Listener for versioned database events.
///
/// Corresponds to `ghidra.framework.store.db.VersionedDBListener`.
pub trait VersionedDBListener: Send + Sync {
    /// Called when a new version is created.
    ///
    /// Returns `true` if the version was accepted.
    fn version_created(
        &self,
        version: i32,
        time: i64,
        comment: &str,
        checkin_id: i64,
    ) -> bool;

    /// Called when the database is about to be disposed.
    fn disposing(&self);
}

// ============================================================================
// PrivateDatabase
// ============================================================================

/// A private (non-versioned) database stored locally.
///
/// Corresponds to `ghidra.framework.store.db.PrivateDatabase`.
pub struct PrivateDatabase {
    /// Data directory containing the database files.
    data_dir: PathBuf,
    /// Current version number.
    current_version: i32,
    /// Whether the database is open.
    is_open: bool,
}

impl PrivateDatabase {
    /// Create a new private database in the given directory.
    pub fn new(data_dir: PathBuf) -> StoreResult<Self> {
        if !data_dir.exists() {
            fs::create_dir_all(&data_dir)?;
        }
        Ok(Self {
            data_dir,
            current_version: 0,
            is_open: true,
        })
    }

    /// Get the data directory.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Get the current version number.
    pub fn current_version(&self) -> i32 {
        self.current_version
    }

    /// Check if the database is open.
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    /// Close this database.
    pub fn close(&mut self) {
        self.is_open = false;
    }

    /// Create a new empty private database.
    pub fn create(data_dir: &Path, _buffer_size: i32, content_type: &str) -> StoreResult<Self> {
        fs::create_dir_all(data_dir)?;
        let mut db = Self::new(data_dir.to_path_buf())?;
        // Write a metadata file
        let meta_path = data_dir.join("db.meta");
        fs::write(&meta_path, format!("content_type={}\nversion=0\n", content_type))?;
        Ok(db)
    }

    /// Delete this database and all its files.
    pub fn delete(&mut self) -> StoreResult<()> {
        if self.data_dir.exists() {
            fs::remove_dir_all(&self.data_dir)?;
        }
        self.is_open = false;
        Ok(())
    }

    /// Create a new version (for non-versioned DBs, this increments the version counter).
    pub fn create_version(&mut self, _comment: &str) -> StoreResult<i32> {
        self.current_version += 1;
        Ok(self.current_version)
    }

    /// Clean up old pre-save files.
    pub fn cleanup_old_presave_files(dir: &Path) {
        if !dir.exists() {
            return;
        }
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(".db") {
                        Self::cleanup_presave_in_dir(&path);
                    } else {
                        Self::cleanup_old_presave_files(&path);
                    }
                }
            }
        }
    }

    fn cleanup_presave_in_dir(dir: &Path) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("preSave") || name.starts_with("tmpSave") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}

impl fmt::Debug for PrivateDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateDatabase")
            .field("data_dir", &self.data_dir)
            .field("current_version", &self.current_version)
            .field("is_open", &self.is_open)
            .finish()
    }
}

// ============================================================================
// VersionedDatabase
// ============================================================================

/// A versioned database with history tracking.
///
/// Corresponds to `ghidra.framework.store.db.VersionedDatabase`.
pub struct VersionedDatabase {
    /// Data directory.
    data_dir: PathBuf,
    /// Current version number.
    current_version: i32,
    /// Minimum available version.
    min_version: i32,
    /// Whether the database is open.
    is_open: bool,
    /// Synchronization object for thread safety.
    sync_object: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

impl VersionedDatabase {
    /// Create a new versioned database.
    pub fn new(data_dir: PathBuf) -> StoreResult<Self> {
        if !data_dir.exists() {
            fs::create_dir_all(&data_dir)?;
        }
        Ok(Self {
            data_dir,
            current_version: 0,
            min_version: 0,
            is_open: true,
            sync_object: None,
        })
    }

    /// Get the data directory.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Get the current version.
    pub fn current_version(&self) -> i32 {
        self.current_version
    }

    /// Get the minimum version.
    pub fn minimum_version(&self) -> i32 {
        self.min_version
    }

    /// Check if the database is open.
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    /// Set the synchronization object.
    pub fn set_synchronization_object(&mut self, obj: Arc<dyn std::any::Any + Send + Sync>) {
        self.sync_object = Some(obj);
    }

    /// Close this database.
    pub fn close(&mut self) {
        self.is_open = false;
        self.sync_object = None;
    }

    /// Create a new version.
    pub fn create_version(
        &mut self,
        comment: &str,
        checkin_id: i64,
    ) -> StoreResult<i32> {
        self.current_version += 1;
        // In a full implementation, this would write version data
        log::info!(
            "Created version {} (checkin={}, comment={})",
            self.current_version,
            checkin_id,
            comment
        );
        Ok(self.current_version)
    }

    /// Delete a specific version.
    pub fn delete_version(&mut self, version: i32) -> StoreResult<()> {
        if version < self.min_version || version > self.current_version {
            return Err(GhidraError::InvalidData(format!(
                "Invalid version: {} (range: {}-{})",
                version, self.min_version, self.current_version
            )));
        }
        // Update min_version if the deleted version was the minimum or below current min
        if version >= self.min_version {
            self.min_version = version + 1;
        }
        if version == self.current_version {
            self.current_version -= 1;
        }
        Ok(())
    }

    /// Delete the entire database.
    pub fn delete(&mut self) -> StoreResult<()> {
        if self.data_dir.exists() {
            fs::remove_dir_all(&self.data_dir)?;
        }
        self.is_open = false;
        Ok(())
    }
}

impl fmt::Debug for VersionedDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VersionedDatabase")
            .field("data_dir", &self.data_dir)
            .field("current_version", &self.current_version)
            .field("min_version", &self.min_version)
            .field("is_open", &self.is_open)
            .finish()
    }
}

// ============================================================================
// PackedDatabase
// ============================================================================

/// A packed (serialized) database that can be transferred between file systems.
///
/// Corresponds to `ghidra.framework.store.db.PackedDatabase`.
pub struct PackedDatabase {
    /// Path to the packed database file.
    file_path: PathBuf,
    /// Content type.
    content_type: String,
    /// Database ID.
    database_id: Option<String>,
}

impl PackedDatabase {
    /// File extension for packed databases.
    pub const PACKED_DB_EXT: &'static str = ".gpd";

    /// Create a new packed database from a file path.
    pub fn new(file_path: PathBuf) -> StoreResult<Self> {
        if !file_path.exists() {
            return Err(GhidraError::NotFound(format!(
                "Packed database not found: {}",
                file_path.display()
            )));
        }
        Ok(Self {
            file_path,
            content_type: String::new(),
            database_id: None,
        })
    }

    /// Create a packed database from data.
    pub fn create(
        file_path: PathBuf,
        content_type: &str,
        data: &[u8],
    ) -> StoreResult<Self> {
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&file_path, data)?;
        Ok(Self {
            file_path,
            content_type: content_type.to_string(),
            database_id: None,
        })
    }

    /// Get the file path.
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Get the content type.
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// Get the database ID.
    pub fn database_id(&self) -> Option<&str> {
        self.database_id.as_deref()
    }

    /// Get the file size.
    pub fn file_size(&self) -> io::Result<u64> {
        Ok(fs::metadata(&self.file_path)?.len())
    }

    /// Close and clean up.
    pub fn close(&self) {
        // No-op for now
    }

    /// Clean up old temporary packed databases.
    pub fn cleanup_old_temp_databases() {
        let temp_dir = std::env::temp_dir();
        if let Ok(entries) = fs::read_dir(temp_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("ghidra_packed_") && name.ends_with(Self::PACKED_DB_EXT) {
                    // Check age - remove if older than 1 day
                    if let Ok(meta) = entry.metadata() {
                        if let Ok(modified) = meta.modified() {
                            if let Ok(elapsed) = modified.elapsed() {
                                if elapsed.as_secs() > 86400 {
                                    let _ = fs::remove_file(entry.path());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Drop for PackedDatabase {
    fn drop(&mut self) {
        self.close();
    }
}

impl fmt::Debug for PackedDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackedDatabase")
            .field("file_path", &self.file_path)
            .field("content_type", &self.content_type)
            .finish()
    }
}

// ============================================================================
// PackedDatabaseCache
// ============================================================================

/// Cache for packed databases to avoid repeated extraction.
///
/// Corresponds to `ghidra.framework.store.db.PackedDatabaseCache`.
pub struct PackedDatabaseCache {
    /// Cache directory.
    cache_dir: PathBuf,
    /// Cache entries: (key) -> path.
    entries: HashMap<String, PathBuf>,
    /// Maximum cache size in bytes.
    max_size: u64,
    /// Current cache size in bytes.
    current_size: u64,
}

impl PackedDatabaseCache {
    /// Default maximum cache size (100 MB).
    pub const DEFAULT_MAX_SIZE: u64 = 100 * 1024 * 1024;

    /// Create a new cache.
    pub fn new(cache_dir: PathBuf) -> StoreResult<Self> {
        fs::create_dir_all(&cache_dir)?;
        Ok(Self {
            cache_dir,
            entries: HashMap::new(),
            max_size: Self::DEFAULT_MAX_SIZE,
            current_size: 0,
        })
    }

    /// Get the cache directory.
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Check if a key is cached.
    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Get the path for a cached entry.
    pub fn get(&self, key: &str) -> Option<&PathBuf> {
        self.entries.get(key)
    }

    /// Put an entry into the cache.
    pub fn put(&mut self, key: String, path: PathBuf) {
        if let Ok(meta) = fs::metadata(&path) {
            let size = meta.len();
            // Evict if necessary
            while self.current_size + size > self.max_size && !self.entries.is_empty() {
                self.evict_oldest();
            }
            self.current_size += size;
            self.entries.insert(key, path);
        }
    }

    /// Remove an entry from the cache.
    pub fn remove(&mut self, key: &str) -> Option<PathBuf> {
        let path = self.entries.remove(key)?;
        if let Ok(meta) = fs::metadata(&path) {
            self.current_size = self.current_size.saturating_sub(meta.len());
        }
        Some(path)
    }

    /// Clear all cache entries.
    pub fn clear(&mut self) {
        for path in self.entries.values() {
            let _ = fs::remove_file(path);
        }
        self.entries.clear();
        self.current_size = 0;
    }

    /// Number of cached entries.
    pub fn size(&self) -> usize {
        self.entries.len()
    }

    fn evict_oldest(&mut self) {
        if let Some(key) = self.entries.keys().next().cloned() {
            self.remove(&key);
        }
    }
}

impl Drop for PackedDatabaseCache {
    fn drop(&mut self) {
        // Don't clean up on drop - cache persists across sessions
    }
}

impl fmt::Debug for PackedDatabaseCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackedDatabaseCache")
            .field("cache_dir", &self.cache_dir)
            .field("entries", &self.entries.len())
            .field("current_size", &self.current_size)
            .field("max_size", &self.max_size)
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_database_create() {
        let dir = std::env::temp_dir().join("ghidra_test_privatedb");
        let _ = fs::remove_dir_all(&dir);

        let db = PrivateDatabase::create(&dir, 1024, "Program").unwrap();
        assert!(db.is_open());
        assert_eq!(db.current_version(), 0);
        assert!(dir.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_private_database_version() {
        let dir = std::env::temp_dir().join("ghidra_test_privatedb_ver");
        let _ = fs::remove_dir_all(&dir);

        let mut db = PrivateDatabase::create(&dir, 1024, "Program").unwrap();
        let v1 = db.create_version("first save").unwrap();
        assert_eq!(v1, 1);
        let v2 = db.create_version("second save").unwrap();
        assert_eq!(v2, 2);
        assert_eq!(db.current_version(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_versioned_database() {
        let dir = std::env::temp_dir().join("ghidra_test_versioneddb");
        let _ = fs::remove_dir_all(&dir);

        let mut db = VersionedDatabase::new(dir.clone()).unwrap();
        assert_eq!(db.current_version(), 0);

        db.create_version("v1", 1).unwrap();
        assert_eq!(db.current_version(), 1);

        db.create_version("v2", 2).unwrap();
        assert_eq!(db.current_version(), 2);

        db.delete_version(1).unwrap();
        assert_eq!(db.minimum_version(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_packed_database() {
        let dir = std::env::temp_dir().join("ghidra_test_packeddb");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("test.gpd");
        let pdb = PackedDatabase::create(path.clone(), "Program", b"fake data").unwrap();
        assert_eq!(pdb.file_size().unwrap(), 9);
        assert_eq!(pdb.content_type(), "Program");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_packed_database_cache() {
        let dir = std::env::temp_dir().join("ghidra_test_packedcache");
        let _ = fs::remove_dir_all(&dir);

        let mut cache = PackedDatabaseCache::new(dir.clone()).unwrap();
        assert_eq!(cache.size(), 0);

        // Create a temp file to cache
        let tmp = dir.join("test_data.bin");
        fs::write(&tmp, b"cached content").unwrap();

        cache.put("key1".to_string(), tmp.clone());
        assert!(cache.contains("key1"));
        assert_eq!(cache.size(), 1);

        cache.remove("key1");
        assert!(!cache.contains("key1"));
        assert_eq!(cache.size(), 0);

        cache.clear();
        let _ = fs::remove_dir_all(&dir);
    }
}
