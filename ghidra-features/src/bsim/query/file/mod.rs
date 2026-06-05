//! H2/file-based local BSim database.
//!
//! Port of `ghidra.features.bsim.query.file`:
//! - [`H2FileFunctionDatabase`]: file-based function database
//! - [`VectorStore`]: local vector storage
//! - [`VectorStoreEntry`]: individual vector entries
//! - [`H2VectorTable`]: H2-specific vector table
//! - [`BSimH2FileDBConnectionManager`]: connection pool for H2 file databases
//! - [`BSimVectorStoreManager`]: manages multiple vector stores

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::client::AbstractSQLFunctionDatabase;
use super::super::description::{ExecutableRecord, FunctionDescription};

// ============================================================================
// VectorStoreEntry
// ============================================================================

/// An entry in a vector store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorStoreEntry {
    /// Function name.
    pub function_name: String,
    /// Executable index.
    pub exe_index: usize,
    /// Feature vector (hash -> weight pairs).
    pub vector: Vec<(u64, f64)>,
    /// Storage offset in the file.
    pub offset: u64,
}

impl VectorStoreEntry {
    /// Create a new vector store entry.
    pub fn new(function_name: impl Into<String>, exe_index: usize) -> Self {
        Self {
            function_name: function_name.into(),
            exe_index,
            vector: Vec::new(),
            offset: 0,
        }
    }

    /// Set the vector data.
    pub fn with_vector(mut self, vector: Vec<(u64, f64)>) -> Self {
        self.vector = vector;
        self
    }

    /// Set the storage offset.
    pub fn with_offset(mut self, offset: u64) -> Self {
        self.offset = offset;
        self
    }
}

// ============================================================================
// VectorStore
// ============================================================================

/// Local file-based vector storage.
#[derive(Debug, Clone)]
pub struct VectorStore {
    /// Path to the store directory.
    pub path: String,
    /// Entries in the store.
    entries: Vec<VectorStoreEntry>,
}

impl VectorStore {
    /// Create a new vector store at the given path.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            entries: Vec::new(),
        }
    }

    /// Add an entry to the store.
    pub fn add_entry(&mut self, entry: VectorStoreEntry) {
        self.entries.push(entry);
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entries.
    pub fn entries(&self) -> &[VectorStoreEntry] {
        &self.entries
    }

    /// Find an entry by function name and executable index.
    pub fn find(&self, function_name: &str, exe_index: usize) -> Option<&VectorStoreEntry> {
        self.entries
            .iter()
            .find(|e| e.function_name == function_name && e.exe_index == exe_index)
    }

    /// Remove an entry by function name and executable index.
    pub fn remove(&mut self, function_name: &str, exe_index: usize) -> bool {
        let len_before = self.entries.len();
        self.entries
            .retain(|e| !(e.function_name == function_name && e.exe_index == exe_index));
        self.entries.len() < len_before
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ============================================================================
// H2VectorTable
// ============================================================================

/// H2-specific vector table for storing feature vectors in the database.
///
/// This is a table-backed storage for feature vectors that uses
/// the H2 file database for persistence.
#[derive(Debug, Clone)]
pub struct H2VectorTable {
    /// Table name in the database.
    pub table_name: String,
    /// Vector entries indexed by (exe_index, function_name).
    entries: HashMap<(usize, String), Vec<f64>>,
}

impl H2VectorTable {
    /// Create a new H2 vector table.
    pub fn new(table_name: impl Into<String>) -> Self {
        Self {
            table_name: table_name.into(),
            entries: HashMap::new(),
        }
    }

    /// Insert a vector.
    pub fn insert(&mut self, exe_index: usize, function_name: &str, vector: Vec<f64>) {
        self.entries
            .insert((exe_index, function_name.to_string()), vector);
    }

    /// Get a vector.
    pub fn get(&self, exe_index: usize, function_name: &str) -> Option<&Vec<f64>> {
        self.entries.get(&(exe_index, function_name.to_string()))
    }

    /// Remove a vector.
    pub fn remove(&mut self, exe_index: usize, function_name: &str) -> bool {
        self.entries
            .remove(&(exe_index, function_name.to_string()))
            .is_some()
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ============================================================================
// BSimH2FileDBConnectionManager
// ============================================================================

/// Connection manager for H2 file-based BSim databases.
///
/// Manages a pool of connections to H2 database files, allowing
/// multiple concurrent database access.
#[derive(Debug)]
pub struct BSimH2FileDBConnectionManager {
    /// Active database connections by path.
    connections: HashMap<String, H2FileFunctionDatabase>,
    /// Maximum number of concurrent connections.
    pub max_connections: usize,
}

impl BSimH2FileDBConnectionManager {
    /// Create a new connection manager.
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: HashMap::new(),
            max_connections,
        }
    }

    /// Get or create a connection to a database file.
    pub fn get_connection(&mut self, db_path: &str) -> Option<&H2FileFunctionDatabase> {
        if !self.connections.contains_key(db_path) {
            if self.connections.len() >= self.max_connections {
                return None; // Pool exhausted.
            }
            let db = H2FileFunctionDatabase::new(db_path);
            self.connections.insert(db_path.to_string(), db);
        }
        self.connections.get(db_path)
    }

    /// Get a mutable reference to a connection.
    pub fn get_connection_mut(&mut self, db_path: &str) -> Option<&mut H2FileFunctionDatabase> {
        if !self.connections.contains_key(db_path) {
            if self.connections.len() >= self.max_connections {
                return None;
            }
            let db = H2FileFunctionDatabase::new(db_path);
            self.connections.insert(db_path.to_string(), db);
        }
        self.connections.get_mut(db_path)
    }

    /// Close a connection.
    pub fn close_connection(&mut self, db_path: &str) -> bool {
        self.connections.remove(db_path).is_some()
    }

    /// Get the number of active connections.
    pub fn active_connections(&self) -> usize {
        self.connections.len()
    }

    /// Close all connections.
    pub fn close_all(&mut self) {
        self.connections.clear();
    }
}

impl Default for BSimH2FileDBConnectionManager {
    fn default() -> Self {
        Self::new(10)
    }
}

// ============================================================================
// BSimVectorStoreManager
// ============================================================================

/// Manages multiple vector stores for BSim databases.
///
/// Each vector store is associated with a database path and provides
/// efficient storage and retrieval of feature vectors.
#[derive(Debug)]
pub struct BSimVectorStoreManager {
    /// Vector stores by database path.
    stores: HashMap<String, VectorStore>,
    /// Base directory for vector stores.
    pub base_dir: String,
}

impl BSimVectorStoreManager {
    /// Create a new vector store manager.
    pub fn new(base_dir: impl Into<String>) -> Self {
        Self {
            stores: HashMap::new(),
            base_dir: base_dir.into(),
        }
    }

    /// Get or create a vector store for a database.
    pub fn get_store(&mut self, db_path: &str) -> &VectorStore {
        if !self.stores.contains_key(db_path) {
            let store_path = format!("{}/{}.vectors", self.base_dir, db_path);
            let store = VectorStore::new(store_path);
            self.stores.insert(db_path.to_string(), store);
        }
        &self.stores[db_path]
    }

    /// Get a mutable reference to a vector store.
    pub fn get_store_mut(&mut self, db_path: &str) -> &mut VectorStore {
        if !self.stores.contains_key(db_path) {
            let store_path = format!("{}/{}.vectors", self.base_dir, db_path);
            let store = VectorStore::new(store_path);
            self.stores.insert(db_path.to_string(), store);
        }
        self.stores.get_mut(db_path).unwrap()
    }

    /// Remove a vector store.
    pub fn remove_store(&mut self, db_path: &str) -> bool {
        self.stores.remove(db_path).is_some()
    }

    /// Get the number of managed stores.
    pub fn store_count(&self) -> usize {
        self.stores.len()
    }

    /// Clear all stores.
    pub fn clear(&mut self) {
        self.stores.clear();
    }
}

// ============================================================================
// H2FileFunctionDatabase
// ============================================================================

/// H2 file-based BSim function database.
#[derive(Debug, Clone)]
pub struct H2FileFunctionDatabase {
    /// Path to the database file.
    pub db_path: String,
    /// Functions stored in the database.
    functions: Vec<FunctionDescription>,
    /// Executables stored in the database.
    executables: Vec<ExecutableRecord>,
    /// Vector store for feature vectors.
    pub vector_store: VectorStore,
    /// H2 vector table.
    pub vector_table: H2VectorTable,
}

impl H2FileFunctionDatabase {
    /// Create a new H2 file function database.
    pub fn new(db_path: impl Into<String>) -> Self {
        let path = db_path.into();
        Self {
            vector_store: VectorStore::new(format!("{}.vectors", path)),
            vector_table: H2VectorTable::new("vectors"),
            db_path: path,
            functions: Vec::new(),
            executables: Vec::new(),
        }
    }

    /// Get all functions.
    pub fn functions(&self) -> &[FunctionDescription] {
        &self.functions
    }

    /// Get all executables.
    pub fn executables(&self) -> &[ExecutableRecord] {
        &self.executables
    }

    /// Query all functions for a given executable.
    pub fn query_functions_by_exe(&self, exe_index: usize) -> Vec<&FunctionDescription> {
        self.functions
            .iter()
            .filter(|f| f.exe_index == exe_index)
            .collect()
    }
}

impl AbstractSQLFunctionDatabase for H2FileFunctionDatabase {
    fn query_by_name(&self, exe_index: usize, name: &str) -> Option<FunctionDescription> {
        self.functions
            .iter()
            .find(|f| f.exe_index == exe_index && f.function_name == name)
            .cloned()
    }

    fn query_by_executable(&self, exe_index: usize) -> Vec<FunctionDescription> {
        self.functions
            .iter()
            .filter(|f| f.exe_index == exe_index)
            .cloned()
            .collect()
    }

    fn insert_function(&mut self, func: &FunctionDescription) -> Result<(), String> {
        self.functions.push(func.clone());
        Ok(())
    }

    fn insert_executable(&mut self, exe: &ExecutableRecord) -> Result<(), String> {
        self.executables.push(exe.clone());
        Ok(())
    }

    fn delete_function(&mut self, exe_index: usize, name: &str) -> Result<(), String> {
        self.functions
            .retain(|f| !(f.exe_index == exe_index && f.function_name == name));
        Ok(())
    }

    fn function_count(&self) -> usize {
        self.functions.len()
    }

    fn executable_count(&self) -> usize {
        self.executables.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_store_entry() {
        let mut entry = VectorStoreEntry::new("main", 0);
        entry.vector.push((100, 0.5));
        assert_eq!(entry.function_name, "main");
        assert_eq!(entry.vector.len(), 1);
    }

    #[test]
    fn vector_store_entry_with_vector() {
        let entry = VectorStoreEntry::new("f1", 0)
            .with_vector(vec![(1, 0.5), (2, 0.3)])
            .with_offset(100);
        assert_eq!(entry.vector.len(), 2);
        assert_eq!(entry.offset, 100);
    }

    #[test]
    fn test_vector_store() {
        let mut store = VectorStore::new("/tmp/vectors");
        assert!(store.is_empty());
        store.add_entry(VectorStoreEntry::new("f1", 0));
        store.add_entry(VectorStoreEntry::new("f2", 1));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn vector_store_find() {
        let mut store = VectorStore::new("/tmp/vectors");
        store.add_entry(VectorStoreEntry::new("main", 0));
        store.add_entry(VectorStoreEntry::new("foo", 1));

        assert!(store.find("main", 0).is_some());
        assert!(store.find("main", 1).is_none());
        assert!(store.find("bar", 0).is_none());
    }

    #[test]
    fn vector_store_remove() {
        let mut store = VectorStore::new("/tmp/vectors");
        store.add_entry(VectorStoreEntry::new("f1", 0));
        assert_eq!(store.len(), 1);
        assert!(store.remove("f1", 0));
        assert_eq!(store.len(), 0);
        assert!(!store.remove("f1", 0));
    }

    #[test]
    fn vector_store_clear() {
        let mut store = VectorStore::new("/tmp/vectors");
        store.add_entry(VectorStoreEntry::new("f1", 0));
        store.add_entry(VectorStoreEntry::new("f2", 1));
        store.clear();
        assert!(store.is_empty());
    }

    #[test]
    fn h2_vector_table() {
        let mut table = H2VectorTable::new("test_vectors");
        assert!(table.is_empty());

        table.insert(0, "main", vec![1.0, 2.0, 3.0]);
        table.insert(1, "foo", vec![4.0, 5.0]);
        assert_eq!(table.len(), 2);

        let vec = table.get(0, "main").unwrap();
        assert_eq!(vec.len(), 3);
        assert!((vec[0] - 1.0).abs() < 1e-9);

        assert!(table.get(0, "nonexistent").is_none());
    }

    #[test]
    fn h2_vector_table_remove() {
        let mut table = H2VectorTable::new("test_vectors");
        table.insert(0, "main", vec![1.0]);
        assert!(table.remove(0, "main"));
        assert!(table.is_empty());
        assert!(!table.remove(0, "main"));
    }

    #[test]
    fn h2_vector_table_clear() {
        let mut table = H2VectorTable::new("test_vectors");
        table.insert(0, "a", vec![1.0]);
        table.insert(1, "b", vec![2.0]);
        table.clear();
        assert!(table.is_empty());
    }

    #[test]
    fn bsim_h2_connection_manager() {
        let mut mgr = BSimH2FileDBConnectionManager::new(5);
        assert_eq!(mgr.active_connections(), 0);

        let _db = mgr.get_connection("/tmp/test1.bsim");
        assert_eq!(mgr.active_connections(), 1);

        let _db2 = mgr.get_connection("/tmp/test2.bsim");
        assert_eq!(mgr.active_connections(), 2);

        assert!(mgr.close_connection("/tmp/test1.bsim"));
        assert_eq!(mgr.active_connections(), 1);
    }

    #[test]
    fn bsim_h2_connection_manager_pool_limit() {
        let mut mgr = BSimH2FileDBConnectionManager::new(2);
        mgr.get_connection("/tmp/1.bsim");
        mgr.get_connection("/tmp/2.bsim");
        assert!(mgr.get_connection("/tmp/3.bsim").is_none());
    }

    #[test]
    fn bsim_h2_connection_manager_default() {
        let mgr = BSimH2FileDBConnectionManager::default();
        assert_eq!(mgr.max_connections, 10);
    }

    #[test]
    fn bsim_h2_connection_manager_close_all() {
        let mut mgr = BSimH2FileDBConnectionManager::new(5);
        mgr.get_connection("/tmp/1.bsim");
        mgr.get_connection("/tmp/2.bsim");
        mgr.close_all();
        assert_eq!(mgr.active_connections(), 0);
    }

    #[test]
    fn bsim_vector_store_manager() {
        let mut mgr = BSimVectorStoreManager::new("/tmp/bsim");
        assert_eq!(mgr.store_count(), 0);

        let store = mgr.get_store("db1");
        assert!(store.is_empty());
        assert_eq!(mgr.store_count(), 1);

        let store_mut = mgr.get_store_mut("db1");
        store_mut.add_entry(VectorStoreEntry::new("f1", 0));
        assert_eq!(mgr.get_store("db1").len(), 1);
    }

    #[test]
    fn bsim_vector_store_manager_remove() {
        let mut mgr = BSimVectorStoreManager::new("/tmp/bsim");
        mgr.get_store("db1");
        assert_eq!(mgr.store_count(), 1);
        assert!(mgr.remove_store("db1"));
        assert_eq!(mgr.store_count(), 0);
        assert!(!mgr.remove_store("db1"));
    }

    #[test]
    fn bsim_vector_store_manager_clear() {
        let mut mgr = BSimVectorStoreManager::new("/tmp/bsim");
        mgr.get_store("db1");
        mgr.get_store("db2");
        mgr.clear();
        assert_eq!(mgr.store_count(), 0);
    }

    #[test]
    fn test_h2_database() {
        let mut db = H2FileFunctionDatabase::new("/tmp/test.bsim");
        assert_eq!(db.db_path, "/tmp/test.bsim");

        let func = FunctionDescription::new(0, "main", Some(0x1000));
        db.insert_function(&func).unwrap();
        assert_eq!(db.function_count(), 1);

        let found = db.query_by_name(0, "main");
        assert!(found.is_some());
    }

    #[test]
    fn test_h2_delete() {
        let mut db = H2FileFunctionDatabase::new("/tmp/test.bsim");
        db.insert_function(&FunctionDescription::new(0, "f1", None)).unwrap();
        db.delete_function(0, "f1").unwrap();
        assert_eq!(db.function_count(), 0);
    }

    #[test]
    fn h2_database_query_functions_by_exe() {
        let mut db = H2FileFunctionDatabase::new("/tmp/test.bsim");
        db.insert_function(&FunctionDescription::new(0, "f1", Some(0x1000)));
        db.insert_function(&FunctionDescription::new(0, "f2", Some(0x2000)));
        db.insert_function(&FunctionDescription::new(1, "f3", Some(0x3000)));

        let exe0_funcs = db.query_functions_by_exe(0);
        assert_eq!(exe0_funcs.len(), 2);

        let exe1_funcs = db.query_functions_by_exe(1);
        assert_eq!(exe1_funcs.len(), 1);
    }

    #[test]
    fn h2_database_functions_and_executables() {
        let mut db = H2FileFunctionDatabase::new("/tmp/test.bsim");
        db.insert_function(&FunctionDescription::new(0, "f1", Some(0x1000)));
        db.insert_executable(&ExecutableRecord::new("abc", "prog", "x86", "gcc"));

        assert_eq!(db.functions().len(), 1);
        assert_eq!(db.executables().len(), 1);
    }
}
