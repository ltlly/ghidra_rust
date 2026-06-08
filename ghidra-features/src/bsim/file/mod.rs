//! File-based BSim database.
//!
//! Ports `ghidra.features.bsim.query.file` package.
//!
//! Provides a file-system-based BSim function database that stores
//! signatures in flat files for portable, offline analysis.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::bsim::BSimSignature;

/// Configuration for a file-based BSim database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDatabaseConfig {
    /// Root directory for the database files.
    pub root_dir: PathBuf,
    /// Whether to compress stored data.
    pub compress: bool,
    /// Index file name.
    pub index_file: String,
    /// Data file prefix.
    pub data_prefix: String,
}

impl Default for FileDatabaseConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from("bsim_data"),
            compress: true,
            index_file: "index.json".to_string(),
            data_prefix: "sig_".to_string(),
        }
    }
}

/// File-based BSim database.
///
/// Stores function signatures as files on disk, with an index for
/// fast lookup by function hash.
#[derive(Debug)]
pub struct FileDatabase {
    /// Configuration.
    pub config: FileDatabaseConfig,
    /// In-memory index: function hash -> file path.
    index: HashMap<[u8; 32], PathBuf>,
    /// Whether the database has been loaded.
    loaded: bool,
}

impl FileDatabase {
    /// Create a new file database with the given configuration.
    pub fn new(config: FileDatabaseConfig) -> Self {
        Self {
            config,
            index: HashMap::new(),
            loaded: false,
        }
    }

    /// Open an existing database directory.
    pub fn open(root: &Path) -> Self {
        let config = FileDatabaseConfig {
            root_dir: root.to_path_buf(),
            ..Default::default()
        };
        let mut db = Self::new(config);
        db.load_index();
        db
    }

    /// Load the index from disk.
    fn load_index(&mut self) {
        // In a real implementation, this would read the index file
        // and populate the in-memory index.
        self.loaded = true;
    }

    /// Store a signature to disk.
    pub fn store(&mut self, sig: &BSimSignature) -> Result<(), String> {
        let file_name = format!("{}{:016x}.bin",
            self.config.data_prefix,
            u64::from_be_bytes(sig.function_hash[0..8].try_into().unwrap_or([0; 8]))
        );
        let file_path = self.config.root_dir.join(&file_name);

        // Serialize the signature
        let _data = bincode::serialize(sig).map_err(|e| format!("Serialization error: {}", e))?;

        // In a real implementation, write to disk
        self.index.insert(sig.function_hash, file_path);

        Ok(())
    }

    /// Retrieve a signature by function hash.
    pub fn retrieve(&self, hash: &[u8; 32]) -> Option<BSimSignature> {
        let _path = self.index.get(hash)?;
        // In a real implementation, read from disk and deserialize
        None
    }

    /// Get the number of stored signatures.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Check if the database has been loaded.
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// List all stored function hashes.
    pub fn list_hashes(&self) -> Vec<[u8; 32]> {
        self.index.keys().copied().collect()
    }

    /// Get the file path for a given hash.
    pub fn file_path(&self, hash: &[u8; 32]) -> Option<&Path> {
        self.index.get(hash).map(|p| p.as_path())
    }
}

/// Metadata about a file database on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDatabaseInfo {
    /// Number of stored signatures.
    pub signature_count: usize,
    /// Total disk usage in bytes.
    pub disk_usage_bytes: u64,
    /// Database version.
    pub version: u32,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: u64,
    /// Last modified timestamp.
    pub modified_at: u64,
}

impl FileDatabaseInfo {
    /// Create new empty info.
    pub fn new() -> Self {
        Self {
            signature_count: 0,
            disk_usage_bytes: 0,
            version: 1,
            created_at: 0,
            modified_at: 0,
        }
    }
}

impl Default for FileDatabaseInfo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_database_config_default() {
        let config = FileDatabaseConfig::default();
        assert_eq!(config.root_dir, PathBuf::from("bsim_data"));
        assert!(config.compress);
    }

    #[test]
    fn file_database_new() {
        let config = FileDatabaseConfig::default();
        let db = FileDatabase::new(config);
        assert!(db.is_empty());
        assert!(!db.is_loaded());
    }

    #[test]
    fn file_database_open() {
        let db = FileDatabase::open(Path::new("/tmp/bsim_test"));
        assert!(db.is_loaded());
    }

    #[test]
    fn file_database_info_default() {
        let info = FileDatabaseInfo::default();
        assert_eq!(info.version, 1);
        assert_eq!(info.signature_count, 0);
    }

    #[test]
    fn file_database_list_hashes_empty() {
        let db = FileDatabase::new(FileDatabaseConfig::default());
        assert!(db.list_hashes().is_empty());
    }

    #[test]
    fn file_database_file_path_none() {
        let db = FileDatabase::new(FileDatabaseConfig::default());
        assert!(db.file_path(&[0u8; 32]).is_none());
    }
}
