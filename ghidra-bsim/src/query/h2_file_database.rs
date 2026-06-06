//! H2 file-based BSim database.
//!
//! Port of Ghidra's `ghidra.features.bsim.query.file` package:
//! - `H2FileFunctionDatabase`: file-based function database using H2/SQLite
//! - `BSimH2FileDBConnectionManager`: connection management
//! - `BSimVectorStoreManager`: vector store management
//! - `H2VectorTable`: vector storage table
//! - `VectorStore`: vector store abstraction
//! - `VectorStoreEntry`: single vector entry

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

/// A vector store entry (single function signature vector).
///
/// Port of `ghidra.features.bsim.query.file.VectorStoreEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorStoreEntry {
    /// Row key.
    pub row_key: i64,
    /// Function hash.
    pub function_hash: String,
    /// The signature vector.
    pub vector: Vec<f32>,
}

impl VectorStoreEntry {
    /// Create a new vector store entry.
    pub fn new(row_key: i64, function_hash: impl Into<String>, vector: Vec<f32>) -> Self {
        Self { row_key, function_hash: function_hash.into(), vector }
    }

    /// Get the vector dimension.
    pub fn dimension(&self) -> usize {
        self.vector.len()
    }
}

/// A vector store for BSim function signatures.
///
/// Port of `ghidra.features.bsim.query.file.VectorStore`.
#[derive(Debug, Default)]
pub struct VectorStore {
    /// The entries keyed by row_key.
    entries: HashMap<i64, VectorStoreEntry>,
    /// Vector dimension.
    pub dimension: usize,
}

impl VectorStore {
    /// Create a new empty vector store.
    pub fn new(dimension: usize) -> Self {
        Self { entries: HashMap::new(), dimension }
    }

    /// Insert an entry.
    pub fn insert(&mut self, entry: VectorStoreEntry) {
        self.dimension = self.dimension.max(entry.vector.len());
        self.entries.insert(entry.row_key, entry);
    }

    /// Get an entry by row_key.
    pub fn get(&self, row_key: i64) -> Option<&VectorStoreEntry> {
        self.entries.get(&row_key)
    }

    /// Remove an entry by row_key.
    pub fn remove(&mut self, row_key: i64) -> Option<VectorStoreEntry> {
        self.entries.remove(&row_key)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &VectorStoreEntry> {
        self.entries.values()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// H2 vector table abstraction.
///
/// Port of `ghidra.features.bsim.query.file.H2VectorTable`.
#[derive(Debug)]
pub struct H2VectorTable {
    /// Table name.
    pub table_name: String,
    /// Vector dimension.
    pub dimension: usize,
    /// Layout version.
    pub layout_version: u32,
}

impl H2VectorTable {
    /// Create a new H2 vector table descriptor.
    pub fn new(table_name: impl Into<String>, dimension: usize) -> Self {
        Self { table_name: table_name.into(), dimension, layout_version: 1 }
    }

    /// Get the SQL for creating the table.
    pub fn create_table_sql(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {} (row_key BIGINT PRIMARY KEY, vector BLOB)",
            self.table_name
        )
    }
}

/// Connection manager for H2 file-based BSim databases.
///
/// Port of `ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager`.
#[derive(Debug)]
pub struct BSimH2FileDbConnectionManager {
    /// Database file path.
    pub db_path: PathBuf,
    /// Whether connected.
    connected: bool,
    /// Connection map (connection id -> description).
    connections: HashMap<String, String>,
}

impl BSimH2FileDbConnectionManager {
    /// Create a new connection manager.
    pub fn new(db_path: impl AsRef<Path>) -> Self {
        Self {
            db_path: db_path.as_ref().to_path_buf(),
            connected: false,
            connections: HashMap::new(),
        }
    }

    /// Connect to the database.
    pub fn connect(&mut self) -> Result<(), String> {
        self.connected = true;
        Ok(())
    }

    /// Disconnect.
    pub fn disconnect(&mut self) {
        self.connected = false;
        self.connections.clear();
    }

    /// Whether connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Register a connection.
    pub fn register_connection(&mut self, id: impl Into<String>, desc: impl Into<String>) {
        self.connections.insert(id.into(), desc.into());
    }
}

/// Manager for BSim vector stores in a file database.
///
/// Port of `ghidra.features.bsim.query.file.BSimVectorStoreManager`.
#[derive(Debug, Default)]
pub struct BSimVectorStoreManager {
    /// Stores by name.
    stores: HashMap<String, VectorStore>,
}

impl BSimVectorStoreManager {
    /// Create a new vector store manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create or get a named store.
    pub fn get_or_create(&mut self, name: &str, dimension: usize) -> &mut VectorStore {
        self.stores
            .entry(name.to_string())
            .or_insert_with(|| VectorStore::new(dimension))
    }

    /// Remove a store.
    pub fn remove_store(&mut self, name: &str) -> Option<VectorStore> {
        self.stores.remove(name)
    }

    /// Number of stores.
    pub fn store_count(&self) -> usize {
        self.stores.len()
    }
}

/// File-based function database using H2/SQLite.
///
/// Port of `ghidra.features.bsim.query.file.H2FileFunctionDatabase`.
#[derive(Debug)]
pub struct H2FileFunctionDatabase {
    /// Database file path.
    pub db_path: PathBuf,
    /// Connection manager.
    pub connection_manager: BSimH2FileDbConnectionManager,
    /// Vector store manager.
    pub vector_stores: BSimVectorStoreManager,
    /// Whether connected.
    connected: bool,
}

impl H2FileFunctionDatabase {
    /// Create a new file-based function database.
    pub fn new(db_path: impl AsRef<Path>) -> Self {
        let path = db_path.as_ref().to_path_buf();
        Self {
            db_path: path.clone(),
            connection_manager: BSimH2FileDbConnectionManager::new(path),
            vector_stores: BSimVectorStoreManager::new(),
            connected: false,
        }
    }

    /// Connect to the database.
    pub fn connect(&mut self) -> Result<(), String> {
        self.connection_manager.connect()?;
        self.connected = true;
        Ok(())
    }

    /// Disconnect.
    pub fn disconnect(&mut self) {
        self.connection_manager.disconnect();
        self.connected = false;
    }

    /// Whether connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_store_entry() {
        let entry = VectorStoreEntry::new(1, "abc123", vec![0.1, 0.2, 0.3]);
        assert_eq!(entry.dimension(), 3);
        assert_eq!(entry.row_key, 1);
    }

    #[test]
    fn test_vector_store() {
        let mut store = VectorStore::new(3);
        assert!(store.is_empty());

        store.insert(VectorStoreEntry::new(1, "h1", vec![1.0, 2.0, 3.0]));
        store.insert(VectorStoreEntry::new(2, "h2", vec![4.0, 5.0, 6.0]));
        assert_eq!(store.len(), 2);

        let e = store.get(1).unwrap();
        assert_eq!(e.function_hash, "h1");

        store.remove(1);
        assert_eq!(store.len(), 1);
        assert!(store.get(1).is_none());
    }

    #[test]
    fn test_h2_vector_table() {
        let table = H2VectorTable::new("signatures", 128);
        let sql = table.create_table_sql();
        assert!(sql.contains("signatures"));
        assert!(sql.contains("BIGINT PRIMARY KEY"));
    }

    #[test]
    fn test_vector_store_manager() {
        let mut mgr = BSimVectorStoreManager::new();
        assert_eq!(mgr.store_count(), 0);

        mgr.get_or_create("store_a", 64);
        assert_eq!(mgr.store_count(), 1);

        mgr.get_or_create("store_a", 64); // existing
        assert_eq!(mgr.store_count(), 1);
    }

    #[test]
    fn test_h2_file_function_database() {
        let mut db = H2FileFunctionDatabase::new("/tmp/test.bsim");
        assert!(!db.is_connected());
        db.connect().unwrap();
        assert!(db.is_connected());
        db.disconnect();
        assert!(!db.is_connected());
    }

    #[test]
    fn test_h2_connection_manager() {
        let mut mgr = BSimH2FileDbConnectionManager::new("/tmp/test.db");
        assert!(!mgr.is_connected());
        mgr.connect().unwrap();
        assert!(mgr.is_connected());
        mgr.register_connection("conn1", "primary connection");
        mgr.disconnect();
        assert!(!mgr.is_connected());
    }
}
