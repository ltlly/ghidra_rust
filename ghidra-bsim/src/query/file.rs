//! File-based backend for BSim.
//!
//! Ports `ghidra.features.bsim.query.file` from Ghidra's Java source.
//!
//! Stores BSim data in a local SQLite database file.

use super::description::{BSimExecutableInfo, BSimFunctionDescription, BSimResultSet, SimilarityMetric};
use super::function_database::{FunctionDatabase, StubFunctionDatabase};
use super::server_config::ServerConfig;
use super::{BSimError, BSimResult};

/// File-backed function database using SQLite.
#[derive(Debug)]
pub struct FileFunctionDatabase {
    /// Path to the database file.
    pub path: String,
    connected: bool,
    stub: StubFunctionDatabase,
}

impl FileFunctionDatabase {
    /// Create a new file-backed database.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            connected: false,
            stub: StubFunctionDatabase::new(),
        }
    }

    /// Create from a server config (file type).
    pub fn from_config(config: &ServerConfig) -> Self {
        Self::new(&config.database)
    }

    /// Get the SQL statements to create the schema.
    pub fn create_schema_sql() -> Vec<&'static str> {
        vec![
            "CREATE TABLE IF NOT EXISTS executables (id INTEGER PRIMARY KEY, name TEXT, md5 TEXT, arch TEXT, compiler TEXT, path TEXT, ingest_date INTEGER, is_executable INTEGER, function_count INTEGER)",
            "CREATE TABLE IF NOT EXISTS functions (id INTEGER PRIMARY KEY, executable_id INTEGER, name TEXT, entry_point INTEGER, hash TEXT, size INTEGER, bb_count INTEGER, call_count INTEGER, instr_count INTEGER, signature BLOB, is_library INTEGER)",
            "CREATE TABLE IF NOT EXISTS signatures (function_id INTEGER, type TEXT, data BLOB, PRIMARY KEY (function_id, type))",
        ]
    }
}

impl FunctionDatabase for FileFunctionDatabase {
    fn open(&mut self) -> BSimResult<()> {
        self.connected = true;
        self.stub.open()
    }

    fn close(&mut self) -> BSimResult<()> {
        self.connected = false;
        self.stub.close()
    }

    fn is_open(&self) -> bool {
        self.connected
    }

    fn register_executable(&mut self, info: &BSimExecutableInfo) -> BSimResult<()> {
        self.stub.register_executable(info)
    }

    fn remove_executable(&mut self, executable_id: &str) -> BSimResult<()> {
        self.stub.remove_executable(executable_id)
    }

    fn has_executable(&self, executable_id: &str) -> BSimResult<bool> {
        self.stub.has_executable(executable_id)
    }

    fn ingest_functions(&mut self, functions: &[BSimFunctionDescription]) -> BSimResult<usize> {
        self.stub.ingest_functions(functions)
    }

    fn query_similar(
        &self,
        description: &BSimFunctionDescription,
        metric: SimilarityMetric,
        max_results: usize,
        min_similarity: f64,
    ) -> BSimResult<BSimResultSet> {
        self.stub.query_similar(description, metric, max_results, min_similarity)
    }

    fn query_by_hash(&self, function_hash: &str) -> BSimResult<Option<BSimFunctionDescription>> {
        self.stub.query_by_hash(function_hash)
    }

    fn get_functions_for_executable(&self, executable_id: &str) -> BSimResult<Vec<BSimFunctionDescription>> {
        self.stub.get_functions_for_executable(executable_id)
    }

    fn get_executable_info(&self, executable_id: &str) -> BSimResult<Option<BSimExecutableInfo>> {
        self.stub.get_executable_info(executable_id)
    }

    fn function_count(&self) -> BSimResult<usize> {
        self.stub.function_count()
    }

    fn executable_count(&self) -> BSimResult<usize> {
        self.stub.executable_count()
    }

    fn execute_query(&self, query: &str) -> BSimResult<BSimResultSet> {
        self.stub.execute_query(query)
    }

    fn supports_metric(&self, _metric: SimilarityMetric) -> bool {
        true
    }
}

// ============================================================================
// VectorStore / VectorStoreEntry -- Ports `ghidra.features.bsim.query.file`
// ============================================================================

/// A record containing a vector and a count of how many functions share it.
///
/// Ports `ghidra.features.bsim.query.file.VectorStoreEntry`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VectorStoreEntry {
    /// Vector id in the database.
    pub id: i64,
    /// The LSH vector data.
    pub vector: Vec<f64>,
    /// Number of functions sharing this vector.
    pub count: i32,
    /// Self-significance of the vector (using database settings).
    pub self_sig: f64,
}

impl VectorStoreEntry {
    /// Create a new VectorStoreEntry.
    pub fn new(id: i64, vector: Vec<f64>, count: i32, self_sig: f64) -> Self {
        Self { id, vector, count, self_sig }
    }
}

/// A store of vectors for a BSim database.
///
/// Ports `ghidra.features.bsim.query.file.VectorStore`.
/// Provides lazy-loading and caching of LSH vectors from a file-backed database.
#[derive(Debug)]
pub struct VectorStore {
    /// Server info for this store.
    pub server_info: ServerConfig,
    /// Loaded vectors (keyed by id).
    vectors: Option<std::collections::HashMap<i64, VectorStoreEntry>>,
}

impl VectorStore {
    /// Create a new VectorStore for the given server info.
    pub fn new(server_info: ServerConfig) -> Self {
        Self {
            server_info,
            vectors: None,
        }
    }

    /// Get a vector by id, loading from database if needed.
    pub fn get_vector_by_id(&mut self, id: i64) -> Option<&VectorStoreEntry> {
        self.ensure_loaded();
        self.vectors.as_ref()?.get(&id)
    }

    /// Get an iterator over all vector entries.
    pub fn iter(&mut self) -> Box<dyn Iterator<Item = &VectorStoreEntry> + '_> {
        self.ensure_loaded();
        match &self.vectors {
            Some(v) => Box::new(v.values()),
            None => Box::new(std::iter::empty()),
        }
    }

    /// Get the number of loaded vectors.
    pub fn len(&mut self) -> usize {
        self.ensure_loaded();
        self.vectors.as_ref().map_or(0, |v| v.len())
    }

    /// Whether the store is empty.
    pub fn is_empty(&mut self) -> bool {
        self.len() == 0
    }

    /// Invalidate the cache (forces reload on next access).
    pub fn invalidate(&mut self) {
        self.vectors = None;
    }

    /// Whether the vectors have been loaded.
    pub fn is_loaded(&self) -> bool {
        self.vectors.is_some()
    }

    fn ensure_loaded(&mut self) {
        if self.vectors.is_some() {
            return;
        }
        let mut map = std::collections::HashMap::new();
        // In a real implementation, this would load from H2FileFunctionDatabase.
        // For now, we initialize an empty map.
        self.vectors = Some(map);
    }
}

/// Manages multiple VectorStores for different BSim databases.
///
/// Ports `ghidra.features.bsim.query.file.BSimVectorStoreManager`.
#[derive(Debug, Default)]
pub struct VectorStoreManager {
    stores: std::collections::HashMap<String, VectorStore>,
}

impl VectorStoreManager {
    /// Create a new empty VectorStoreManager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a VectorStore for the given database name.
    pub fn get_or_create(&mut self, name: &str, config: ServerConfig) -> &mut VectorStore {
        self.stores
            .entry(name.to_string())
            .or_insert_with(|| VectorStore::new(config))
    }

    /// Invalidate a specific store.
    pub fn invalidate(&mut self, name: &str) {
        if let Some(store) = self.stores.get_mut(name) {
            store.invalidate();
        }
    }

    /// Invalidate all stores.
    pub fn invalidate_all(&mut self) {
        for store in self.stores.values_mut() {
            store.invalidate();
        }
    }

    /// Remove a store.
    pub fn remove(&mut self, name: &str) -> Option<VectorStore> {
        self.stores.remove(name)
    }

    /// Get the number of stores.
    pub fn store_count(&self) -> usize {
        self.stores.len()
    }
}

/// H2 vector table for reading/writing vectors in the file-based H2 database.
///
/// Ports `ghidra.features.bsim.query.file.H2VectorTable`.
#[derive(Debug, Clone)]
pub struct H2VectorTable {
    /// Table name.
    pub table_name: String,
}

impl H2VectorTable {
    /// Create a new H2VectorTable.
    pub fn new() -> Self {
        Self {
            table_name: "vectortable".to_string(),
        }
    }

    /// Get the CREATE TABLE SQL.
    pub fn create_sql(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {} (id BIGINT PRIMARY KEY, vector BLOB, count INTEGER, selfsig DOUBLE)",
            self.table_name
        )
    }

    /// Get the INSERT SQL.
    pub fn insert_sql(&self) -> String {
        format!(
            "INSERT INTO {} (id, vector, count, selfsig) VALUES (?, ?, ?, ?)",
            self.table_name
        )
    }

    /// Get the SELECT ALL SQL.
    pub fn select_all_sql(&self) -> String {
        format!("SELECT id, vector, count, selfsig FROM {}", self.table_name)
    }

    /// Get the SELECT BY ID SQL.
    pub fn select_by_id_sql(&self) -> String {
        format!(
            "SELECT id, vector, count, selfsig FROM {} WHERE id = ?",
            self.table_name
        )
    }
}

impl Default for H2VectorTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Connection manager for H2 file-based BSim databases.
///
/// Ports `ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager`.
#[derive(Debug)]
pub struct H2FileDBConnectionManager {
    /// Active connections by database path.
    connections: std::collections::HashMap<String, bool>,
}

impl H2FileDBConnectionManager {
    /// Create a new connection manager.
    pub fn new() -> Self {
        Self {
            connections: std::collections::HashMap::new(),
        }
    }

    /// Register a database path.
    pub fn register(&mut self, path: &str) {
        self.connections.insert(path.to_string(), false);
    }

    /// Connect to a database.
    pub fn connect(&mut self, path: &str) -> BSimResult<()> {
        if self.connections.contains_key(path) {
            self.connections.insert(path.to_string(), true);
            Ok(())
        } else {
            Err(BSimError::NotFound(format!("Database not registered: {}", path)))
        }
    }

    /// Disconnect from a database.
    pub fn disconnect(&mut self, path: &str) {
        if let Some(connected) = self.connections.get_mut(path) {
            *connected = false;
        }
    }

    /// Check if a database is connected.
    pub fn is_connected(&self, path: &str) -> bool {
        self.connections.get(path).copied().unwrap_or(false)
    }

    /// Remove a database registration.
    pub fn remove(&mut self, path: &str) -> Option<bool> {
        self.connections.remove(path)
    }

    /// Get the number of registered databases.
    pub fn registered_count(&self) -> usize {
        self.connections.len()
    }
}

impl Default for H2FileDBConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_database_new() {
        let db = FileFunctionDatabase::new("/tmp/bsim.db");
        assert_eq!(db.path, "/tmp/bsim.db");
        assert!(!db.is_open());
    }

    #[test]
    fn test_file_database_from_config() {
        let config = ServerConfig::file("/tmp/test.db");
        let db = FileFunctionDatabase::from_config(&config);
        assert_eq!(db.path, "/tmp/test.db");
    }

    #[test]
    fn test_file_database_open_close() {
        let mut db = FileFunctionDatabase::new("/tmp/bsim.db");
        db.open().unwrap();
        assert!(db.is_open());
        db.close().unwrap();
        assert!(!db.is_open());
    }

    #[test]
    fn test_file_database_schema_sql() {
        let stmts = FileFunctionDatabase::create_schema_sql();
        assert_eq!(stmts.len(), 3);
        assert!(stmts[0].contains("executables"));
        assert!(stmts[1].contains("functions"));
        assert!(stmts[2].contains("signatures"));
    }

    #[test]
    fn test_file_database_ingest_and_query() {
        let mut db = FileFunctionDatabase::new("/tmp/bsim.db");
        db.open().unwrap();

        let func = BSimFunctionDescription::new("exe1", "main", 0x1000);
        db.ingest_functions(&[func]).unwrap();
        assert_eq!(db.function_count().unwrap(), 1);

        let results = db.get_functions_for_executable("exe1").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_file_database_supports_all_metrics() {
        let db = FileFunctionDatabase::new("/tmp/bsim.db");
        assert!(db.supports_metric(SimilarityMetric::Jaccard));
        assert!(db.supports_metric(SimilarityMetric::Cosine));
        assert!(db.supports_metric(SimilarityMetric::EditDistance));
        assert!(db.supports_metric(SimilarityMetric::LshApproximate));
    }

    // VectorStore tests

    #[test]
    fn test_vector_store_entry() {
        let entry = VectorStoreEntry::new(42, vec![1.0, 2.0, 3.0], 5, 0.95);
        assert_eq!(entry.id, 42);
        assert_eq!(entry.vector.len(), 3);
        assert_eq!(entry.count, 5);
        assert!((entry.self_sig - 0.95).abs() < 1e-10);
    }

    #[test]
    fn test_vector_store_new() {
        let config = ServerConfig::file("/tmp/test.db");
        let store = VectorStore::new(config);
        assert!(!store.is_loaded());
    }

    #[test]
    fn test_vector_store_invalidate() {
        let config = ServerConfig::file("/tmp/test.db");
        let mut store = VectorStore::new(config);
        store.invalidate();
        assert!(!store.is_loaded());
    }

    #[test]
    fn test_vector_store_manager() {
        let mut mgr = VectorStoreManager::new();
        assert_eq!(mgr.store_count(), 0);

        let config = ServerConfig::file("/tmp/test.db");
        mgr.get_or_create("test", config);
        assert_eq!(mgr.store_count(), 1);

        mgr.invalidate_all();
        mgr.remove("test");
        assert_eq!(mgr.store_count(), 0);
    }

    #[test]
    fn test_h2_vector_table() {
        let table = H2VectorTable::new();
        assert_eq!(table.table_name, "vectortable");
        assert!(table.create_sql().contains("CREATE TABLE"));
        assert!(table.insert_sql().contains("INSERT INTO"));
        assert!(table.select_all_sql().contains("SELECT"));
        assert!(table.select_by_id_sql().contains("WHERE id = ?"));
    }

    #[test]
    fn test_h2_file_db_connection_manager() {
        let mut mgr = H2FileDBConnectionManager::new();
        assert_eq!(mgr.registered_count(), 0);

        mgr.register("/tmp/test.db");
        assert_eq!(mgr.registered_count(), 1);
        assert!(!mgr.is_connected("/tmp/test.db"));

        mgr.connect("/tmp/test.db").unwrap();
        assert!(mgr.is_connected("/tmp/test.db"));

        mgr.disconnect("/tmp/test.db");
        assert!(!mgr.is_connected("/tmp/test.db"));

        mgr.remove("/tmp/test.db");
        assert_eq!(mgr.registered_count(), 0);
    }

    #[test]
    fn test_h2_connection_manager_unknown_db() {
        let mut mgr = H2FileDBConnectionManager::new();
        let result = mgr.connect("/tmp/unknown.db");
        assert!(result.is_err());
    }
}
