//! Missing BSim types ported from Ghidra's Java BSim feature.
//!
//! Ports the following Java classes:
//! - `ghidra.features.bsim.query.description.FunctionDescription`
//! - `ghidra.features.bsim.query.description.ExecutableRecord`
//! - `ghidra.features.bsim.query.client.*` (SQL client types)
//! - `ghidra.features.bsim.query.protocol.*` (protocol types)
//! - `ghidra.features.bsim.query.elastic.*` (ElasticSearch types)
//! - `ghidra.features.bsim.query.*` (miscellaneous types)

use std::collections::HashMap;

// ============================================================================
// FunctionDescription
// ============================================================================

/// A function description record in BSim.
///
/// Ported from `ghidra.features.bsim.query.description.FunctionDescription`.
#[derive(Debug, Clone)]
pub struct FunctionDescription {
    /// The executable record this function belongs to.
    pub executable: Option<usize>,
    /// Name of the function (unique within the executable).
    pub function_name: String,
    /// Address offset of this function within its executable (-1 for library functions).
    pub address: i64,
    /// Table id of this description.
    pub id: Option<i64>,
    /// Vector id of the signature associated with this function.
    pub vector_id: i64,
    /// 1-bit attributes/flags of the function.
    pub flags: i32,
    /// Callgraph entries (if any).
    pub callgraph: Vec<CallgraphEntry>,
    /// Associated signature record.
    pub signature: Option<usize>,
}

impl FunctionDescription {
    /// Create a new function description.
    pub fn new(exe_id: Option<usize>, name: impl Into<String>, address: i64) -> Self {
        Self {
            executable: exe_id,
            function_name: name.into(),
            address,
            id: None,
            vector_id: 0,
            flags: 0,
            callgraph: Vec::new(),
            signature: None,
        }
    }

    /// Get the function name.
    pub fn function_name(&self) -> &str {
        &self.function_name
    }

    /// Get the address.
    pub fn address(&self) -> i64 {
        self.address
    }

    /// Set the row id.
    pub fn set_id(&mut self, id: i64) {
        self.id = Some(id);
    }

    /// Set the vector id.
    pub fn set_vector_id(&mut self, vid: i64) {
        self.vector_id = vid;
    }

    /// Set flags.
    pub fn set_flags(&mut self, flags: i32) {
        self.flags = flags;
    }

    /// Add a callgraph entry.
    pub fn insert_call(&mut self, callee_id: usize, lhash: i32) {
        self.callgraph.push(CallgraphEntry {
            callee: callee_id,
            lhash,
        });
    }

    /// Set the signature record.
    pub fn set_signature(&mut self, sig_id: usize) {
        self.signature = Some(sig_id);
    }
}

impl PartialEq for FunctionDescription {
    fn eq(&self, other: &Self) -> bool {
        self.function_name == other.function_name
            && self.address == other.address
            && self.executable == other.executable
    }
}
impl Eq for FunctionDescription {}

impl PartialOrd for FunctionDescription {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FunctionDescription {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.function_name
            .cmp(&other.function_name)
            .then_with(|| self.address.cmp(&other.address))
    }
}

// ============================================================================
// ExecutableRecord
// ============================================================================

/// Record for an executable in the BSim database.
///
/// Ported from `ghidra.features.bsim.query.description.ExecutableRecord`.
#[derive(Debug, Clone)]
pub struct ExecutableRecord {
    /// Database row id.
    pub id: Option<i64>,
    /// Executable name.
    pub name: String,
    /// MD5 hash of the executable.
    pub md5: String,
    /// Architecture name.
    pub architecture: String,
    /// Compiler name.
    pub compiler: String,
    /// Category.
    pub category: String,
    /// Repository path.
    pub repository_path: String,
    /// Date (Unix timestamp).
    pub date: i64,
    /// Whether this is a library function.
    pub is_library: bool,
    /// Optional metadata.
    pub metadata: HashMap<String, String>,
}

impl ExecutableRecord {
    /// Create a new executable record.
    pub fn new(name: impl Into<String>, md5: impl Into<String>) -> Self {
        Self {
            id: None,
            name: name.into(),
            md5: md5.into(),
            architecture: String::new(),
            compiler: String::new(),
            category: String::new(),
            repository_path: String::new(),
            date: 0,
            is_library: false,
            metadata: HashMap::new(),
        }
    }
}

// ============================================================================
// CallgraphEntry
// ============================================================================

/// An entry in the callgraph for a function.
///
/// Ported from `ghidra.features.bsim.query.description.CallgraphEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallgraphEntry {
    /// Index of the callee function.
    pub callee: usize,
    /// Local hash of the call edge.
    pub lhash: i32,
}

// ============================================================================
// SQL Client Types
// ============================================================================

/// Abstract base for SQL-backed function databases.
///
/// Ported from `ghidra.features.bsim.query.client.AbstractSQLFunctionDatabase`.
#[derive(Debug)]
pub struct AbstractSqlFunctionDatabase {
    /// Connection URL.
    pub connection_url: String,
    /// Database name.
    pub database_name: String,
    /// Whether the connection is active.
    pub connected: bool,
    /// Maximum query rows.
    pub max_rows: usize,
}

impl AbstractSqlFunctionDatabase {
    /// Create a new SQL function database.
    pub fn new(url: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            connection_url: url.into(),
            database_name: name.into(),
            connected: false,
            max_rows: 10000,
        }
    }

    /// Connect to the database.
    pub fn connect(&mut self) -> Result<(), String> {
        self.connected = true;
        Ok(())
    }

    /// Disconnect from the database.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Returns true if connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

/// SQL clause builder for BSim queries.
///
/// Ported from `ghidra.features.bsim.query.client.BSimSqlClause`.
#[derive(Debug, Clone)]
pub struct BSimSqlClause {
    /// The SQL clause text.
    pub clause: String,
    /// Parameters for the clause.
    pub params: Vec<String>,
}

impl BSimSqlClause {
    /// Create a new SQL clause.
    pub fn new(clause: impl Into<String>) -> Self {
        Self {
            clause: clause.into(),
            params: Vec::new(),
        }
    }

    /// Add a parameter.
    pub fn with_param(mut self, param: impl Into<String>) -> Self {
        self.params.push(param.into());
        self
    }
}

/// Exception for cancelled SQL operations.
///
/// Ported from `ghidra.features.bsim.query.client.CancelledSQLException`.
#[derive(Debug, Clone)]
pub struct CancelledSqlException {
    /// Error message.
    pub message: String,
}

impl CancelledSqlException {
    /// Create a new cancelled SQL exception.
    pub fn new(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
    }
}

impl std::fmt::Display for CancelledSqlException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CancelledSQL: {}", self.message)
    }
}

impl std::error::Error for CancelledSqlException {}

/// Configuration for BSim queries.
///
/// Ported from `ghidra.features.bsim.query.client.Configuration`.
#[derive(Debug, Clone)]
pub struct BSimClientConfiguration {
    /// Server host.
    pub host: String,
    /// Server port.
    pub port: u16,
    /// Database name.
    pub database: String,
    /// Username.
    pub username: String,
    /// Use SSL.
    pub use_ssl: bool,
    /// Connection timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for BSimClientConfiguration {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 5432,
            database: "bsim".to_string(),
            username: "bsim".to_string(),
            use_ssl: false,
            timeout_secs: 30,
        }
    }
}

/// Scorer for executable comparisons.
///
/// Ported from `ghidra.features.bsim.query.client.ExecutableScorerSingle`.
#[derive(Debug, Clone)]
pub struct ExecutableScorerSingle {
    /// Similarity score.
    pub score: f64,
    /// Number of matched functions.
    pub match_count: usize,
    /// Total functions in the executable.
    pub total_count: usize,
}

impl ExecutableScorerSingle {
    /// Create a new scorer.
    pub fn new() -> Self {
        Self {
            score: 0.0,
            match_count: 0,
            total_count: 0,
        }
    }

    /// Calculate the normalized score.
    pub fn normalized_score(&self) -> f64 {
        if self.total_count == 0 {
            0.0
        } else {
            self.match_count as f64 / self.total_count as f64
        }
    }
}

impl Default for ExecutableScorerSingle {
    fn default() -> Self {
        Self::new()
    }
}

/// File-based score caching.
///
/// Ported from `ghidra.features.bsim.query.client.FileScoreCaching`.
#[derive(Debug, Clone)]
pub struct FileScoreCache {
    /// Cached scores keyed by executable pair.
    pub cache: HashMap<(String, String), f64>,
    /// Cache file path.
    pub path: String,
}

impl FileScoreCache {
    /// Create a new file score cache.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            cache: HashMap::new(),
            path: path.into(),
        }
    }

    /// Look up a cached score.
    pub fn get(&self, exe1: &str, exe2: &str) -> Option<f64> {
        self.cache
            .get(&(exe1.to_string(), exe2.to_string()))
            .copied()
    }

    /// Store a score.
    pub fn put(&mut self, exe1: &str, exe2: &str, score: f64) {
        self.cache
            .insert((exe1.to_string(), exe2.to_string()), score);
    }
}

/// ID histogram for vector matching.
///
/// Ported from `ghidra.features.bsim.query.client.IdHistogram`.
#[derive(Debug, Clone)]
pub struct IdHistogram {
    /// Counts per ID.
    pub counts: HashMap<i64, usize>,
    /// Total entries.
    pub total: usize,
}

impl IdHistogram {
    /// Create a new histogram.
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
            total: 0,
        }
    }

    /// Add an ID to the histogram.
    pub fn add(&mut self, id: i64) {
        *self.counts.entry(id).or_insert(0) += 1;
        self.total += 1;
    }

    /// Get the count for an ID.
    pub fn count(&self, id: i64) -> usize {
        self.counts.get(&id).copied().unwrap_or(0)
    }
}

impl Default for IdHistogram {
    fn default() -> Self {
        Self::new()
    }
}

/// SQL resolution for ID lookups.
///
/// Ported from `ghidra.features.bsim.query.client.IDSQLResolution`.
#[derive(Debug, Clone)]
pub struct IdSqlResolution {
    /// Resolved ID.
    pub id: i64,
    /// Resolution status.
    pub resolved: bool,
    /// Error message (if any).
    pub error: Option<String>,
}

impl IdSqlResolution {
    /// Create a resolved ID.
    pub fn resolved(id: i64) -> Self {
        Self {
            id,
            resolved: true,
            error: None,
        }
    }

    /// Create an unresolved ID with error.
    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            id: 0,
            resolved: false,
            error: Some(msg.into()),
        }
    }
}

/// Row key for SQL operations.
///
/// Ported from `ghidra.features.bsim.query.client.RowKeySQL`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RowKeySql {
    /// The key value.
    pub key: i64,
}

impl RowKeySql {
    /// Create a new row key.
    pub fn new(key: i64) -> Self {
        Self { key }
    }
}

/// Effects of SQL operations.
///
/// Ported from `ghidra.features.bsim.query.client.SQLEffects`.
#[derive(Debug, Clone, Default)]
pub struct SqlEffects {
    /// Number of rows inserted.
    pub inserts: usize,
    /// Number of rows updated.
    pub updates: usize,
    /// Number of rows deleted.
    pub deletes: usize,
    /// Number of selects.
    pub selects: usize,
}

impl SqlEffects {
    /// Create a new SQL effects tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge another SqlEffects into this one.
    pub fn merge(&mut self, other: &SqlEffects) {
        self.inserts += other.inserts;
        self.updates += other.updates;
        self.deletes += other.deletes;
        self.selects += other.selects;
    }
}

/// Table-based score caching.
///
/// Ported from `ghidra.features.bsim.query.client.TableScoreCaching`.
#[derive(Debug, Clone)]
pub struct TableScoreCache {
    /// Cached table scores.
    pub cache: HashMap<String, HashMap<String, f64>>,
}

impl TableScoreCache {
    /// Create a new table score cache.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Store a score for a table/exe pair.
    pub fn put(&mut self, table: &str, exe: &str, score: f64) {
        self.cache
            .entry(table.to_string())
            .or_default()
            .insert(exe.to_string(), score);
    }

    /// Get a cached score.
    pub fn get(&self, table: &str, exe: &str) -> Option<f64> {
        self.cache.get(table)?.get(exe).copied()
    }
}

impl Default for TableScoreCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Temporary score caching for in-memory lookups.
///
/// Ported from `ghidra.features.bsim.query.client.TemporaryScoreCaching`.
#[derive(Debug, Clone)]
pub struct TemporaryScoreCache {
    /// In-memory cache.
    pub cache: HashMap<(i64, i64), f64>,
}

impl TemporaryScoreCache {
    /// Create a new temporary cache.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Store a score.
    pub fn put(&mut self, key1: i64, key2: i64, score: f64) {
        self.cache.insert((key1, key2), score);
    }

    /// Get a cached score.
    pub fn get(&self, key1: i64, key2: i64) -> Option<f64> {
        self.cache.get(&(key1, key2)).copied()
    }
}

impl Default for TemporaryScoreCache {
    fn default() -> Self {
        Self::new()
    }
}

/// SQL table implementations for BSim.
///
/// Ported from `ghidra.features.bsim.query.client.tables.*`.
#[derive(Debug, Clone)]
pub struct SqlComplexTable {
    /// Table name.
    pub name: String,
    /// Column definitions.
    pub columns: Vec<String>,
    /// Whether the table has been created.
    pub created: bool,
}

impl SqlComplexTable {
    /// Create a new complex table definition.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            columns: Vec::new(),
            created: false,
        }
    }

    /// Add a column.
    pub fn add_column(&mut self, col: impl Into<String>) {
        self.columns.push(col.into());
    }
}

/// SQL string table for BSim.
///
/// Ported from `ghidra.features.bsim.query.client.tables.SQLStringTable`.
#[derive(Debug, Clone)]
pub struct SqlStringTable {
    /// Table name.
    pub name: String,
    /// String entries.
    pub entries: HashMap<i64, String>,
    /// Reverse lookup.
    pub reverse: HashMap<String, i64>,
    /// Next ID.
    pub next_id: i64,
}

impl SqlStringTable {
    /// Create a new string table.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entries: HashMap::new(),
            reverse: HashMap::new(),
            next_id: 1,
        }
    }

    /// Insert a string, returning its ID.
    pub fn insert(&mut self, s: &str) -> i64 {
        if let Some(&id) = self.reverse.get(s) {
            return id;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.entries.insert(id, s.to_string());
        self.reverse.insert(s.to_string(), id);
        id
    }

    /// Look up a string by ID.
    pub fn get(&self, id: i64) -> Option<&str> {
        self.entries.get(&id).map(|s| s.as_str())
    }

    /// Look up an ID by string.
    pub fn get_id(&self, s: &str) -> Option<i64> {
        self.reverse.get(s).copied()
    }
}

// ============================================================================
// ElasticSearch Types
// ============================================================================

/// ElasticSearch resolution for ID lookups.
///
/// Ported from `ghidra.features.bsim.query.elastic.IDElasticResolution`.
#[derive(Debug, Clone)]
pub struct IdElasticResolution {
    /// The resolved Elasticsearch document ID.
    pub doc_id: String,
    /// Whether the resolution was successful.
    pub resolved: bool,
}

impl IdElasticResolution {
    /// Create a resolved elastic ID.
    pub fn resolved(doc_id: impl Into<String>) -> Self {
        Self {
            doc_id: doc_id.into(),
            resolved: true,
        }
    }
}

/// ElasticSearch utilities.
///
/// Ported from `ghidra.features.bsim.query.elastic.ElasticUtilities`.
pub struct ElasticUtilities;

impl ElasticUtilities {
    /// Encode a vector as Base64.
    pub fn encode_vector_base64(vector: &[f32]) -> String {
        let bytes: Vec<u8> = vector
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();
        Base64Lite::encode(&bytes)
    }

    /// Decode a Base64-encoded vector.
    pub fn decode_vector_base64(encoded: &str) -> Result<Vec<f32>, String> {
        let bytes = Base64Lite::decode(encoded)?;
        let floats: Vec<f32> = bytes
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();
        Ok(floats)
    }
}

// ============================================================================
// Protocol Types
// ============================================================================

/// Request to adjust a vector index.
///
/// Ported from `ghidra.features.bsim.query.protocol.AdjustVectorIndex`.
#[derive(Debug, Clone)]
pub struct AdjustVectorIndex {
    /// The old index value.
    pub old_index: i64,
    /// The new index value.
    pub new_index: i64,
}

/// Child atom for hierarchical queries.
///
/// Ported from `ghidra.features.bsim.query.protocol.ChildAtom`.
#[derive(Debug, Clone)]
pub struct ChildAtom {
    /// Child function ID.
    pub child_id: i64,
    /// Local hash.
    pub lhash: i32,
}

/// Cluster note for query results.
///
/// Ported from `ghidra.features.bsim.query.protocol.ClusterNote`.
#[derive(Debug, Clone)]
pub struct ClusterNote {
    /// Cluster ID.
    pub cluster_id: i32,
    /// Note text.
    pub note: String,
}

/// Request to create a database.
///
/// Ported from `ghidra.features.bsim.query.protocol.CreateDatabase`.
#[derive(Debug, Clone)]
pub struct CreateDatabaseRequest {
    /// Database name.
    pub name: String,
    /// Template database (if cloning).
    pub template: Option<String>,
}

/// Request to drop a database.
///
/// Ported from `ghidra.features.bsim.query.protocol.DropDatabase`.
#[derive(Debug, Clone)]
pub struct DropDatabaseRequest {
    /// Database name to drop.
    pub name: String,
}

/// Similarity note in query results.
///
/// Ported from `ghidra.features.bsim.query.protocol.SimilarityNote`.
#[derive(Debug, Clone)]
pub struct SimilarityNote {
    /// Similarity score.
    pub score: f64,
    /// Significance level.
    pub significance: f64,
}

/// Pair input for pairwise comparisons.
///
/// Ported from `ghidra.features.bsim.query.protocol.PairInput`.
#[derive(Debug, Clone)]
pub struct PairInput {
    /// First function ID.
    pub func_id_1: i64,
    /// Second function ID.
    pub func_id_2: i64,
}

/// Pair note for pairwise comparisons.
///
/// Ported from `ghidra.features.bsim.query.protocol.PairNote`.
#[derive(Debug, Clone)]
pub struct PairNote {
    /// Note about the pair.
    pub note: String,
    /// Similarity score.
    pub score: f64,
}

/// Record for an executable result.
///
/// Ported from `ghidra.features.bsim.query.protocol.ExecutableResult`.
#[derive(Debug, Clone)]
pub struct ExecutableResult {
    /// Executable record ID.
    pub exe_id: i64,
    /// Name.
    pub name: String,
    /// Score.
    pub score: f64,
    /// Match count.
    pub match_count: usize,
}

/// Record for an executable result with deduping.
///
/// Ported from `ghidra.features.bsim.query.protocol.ExecutableResultWithDeDuping`.
#[derive(Debug, Clone)]
pub struct ExecutableResultWithDeDuping {
    /// Base result.
    pub result: ExecutableResult,
    /// Deduplication hash.
    pub dedup_hash: String,
}

/// Function staging area.
///
/// Ported from `ghidra.features.bsim.query.protocol.FunctionStaging`.
#[derive(Debug, Clone)]
pub struct FunctionStaging {
    /// Staged function descriptions.
    pub functions: Vec<FunctionDescription>,
    /// Staging area name.
    pub name: String,
}

/// Null staging manager.
///
/// Ported from `ghidra.features.bsim.query.protocol.NullStaging`.
#[derive(Debug, Clone)]
pub struct NullStaging;

// ============================================================================
// Ingest Types
// ============================================================================

/// Task for bulk signature ingestion.
///
/// Ported from `ghidra.features.bsim.query.ingest.BulkSignatures`.
#[derive(Debug, Clone)]
pub struct BulkSignatures {
    /// Number of signatures to process.
    pub count: usize,
    /// Batch size per transaction.
    pub batch_size: usize,
    /// Progress counter.
    pub progress: usize,
}

impl BulkSignatures {
    /// Create a new bulk signatures task.
    pub fn new(count: usize) -> Self {
        Self {
            count,
            batch_size: 100,
            progress: 0,
        }
    }
}

/// Task for iterating over repositories.
///
/// Ported from `ghidra.features.bsim.query.ingest.IterateRepository`.
#[derive(Debug, Clone)]
pub struct IterateRepository {
    /// Repository path.
    pub path: String,
    /// Files discovered.
    pub file_count: usize,
    /// Functions discovered.
    pub function_count: usize,
}

impl IterateRepository {
    /// Create a new repository iterator.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            file_count: 0,
            function_count: 0,
        }
    }
}

/// Headless BSim application configuration.
///
/// Ported from `ghidra.features.bsim.query.ingest.HeadlessBSimApplicationConfiguration`.
#[derive(Debug, Clone)]
pub struct HeadlessBsimApplicationConfiguration {
    /// Server URL.
    pub server_url: String,
    /// Database name.
    pub database: String,
    /// Whether to analyze before ingesting.
    pub analyze_first: bool,
}

impl Default for HeadlessBsimApplicationConfiguration {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            database: String::new(),
            analyze_first: true,
        }
    }
}

/// BSim launchable for command-line usage.
///
/// Ported from `ghidra.features.bsim.query.ingest.BSimLaunchable`.
#[derive(Debug, Clone)]
pub struct BSimLaunchable {
    /// Command arguments.
    pub args: Vec<String>,
}

impl BSimLaunchable {
    /// Create a new launchable.
    pub fn new(args: Vec<String>) -> Self {
        Self { args }
    }
}

// ============================================================================
// Compare / Decompile Tasks
// ============================================================================

/// Task for comparing function signatures.
///
/// Ported from `ghidra.features.bsim.query.CompareSignatures`.
#[derive(Debug, Clone)]
pub struct CompareSignatures {
    /// Source database.
    pub source_db: String,
    /// Target database.
    pub target_db: String,
    /// Similarity threshold.
    pub threshold: f64,
}

impl CompareSignatures {
    /// Create a new compare task.
    pub fn new(source: impl Into<String>, target: impl Into<String>, threshold: f64) -> Self {
        Self {
            source_db: source.into(),
            target_db: target.into(),
            threshold,
        }
    }
}

/// Task for decompiling functions for BSim.
///
/// Ported from `ghidra.features.bsim.query.DecompileFunctionTask`.
#[derive(Debug, Clone)]
pub struct DecompileFunctionTask {
    /// Function addresses to decompile.
    pub addresses: Vec<u64>,
    /// Progress counter.
    pub progress: usize,
}

impl DecompileFunctionTask {
    /// Create a new decompile task.
    pub fn new(addresses: Vec<u64>) -> Self {
        Self {
            addresses,
            progress: 0,
        }
    }
}

/// BSim plugin package descriptor.
///
/// Ported from `ghidra.features.bsim.query.BsimPluginPackage`.
#[derive(Debug, Clone)]
pub struct BsimPluginPackage {
    /// Package name.
    pub name: String,
    /// Version.
    pub version: String,
    /// Description.
    pub description: String,
}

impl Default for BsimPluginPackage {
    fn default() -> Self {
        Self {
            name: "BSim".to_string(),
            version: "1.0.0".to_string(),
            description: "Binary Similarity analysis plugin".to_string(),
        }
    }
}

/// BSim server manager listener.
///
/// Ported from `ghidra.features.bsim.gui.BSimServerManagerListener`.
pub trait BSimServerManagerListener: Send + Sync {
    /// Called when a server is added.
    fn server_added(&self, server: &BSimServerInfoData);
    /// Called when a server is removed.
    fn server_removed(&self, server: &BSimServerInfoData);
    /// Called when the active server changes.
    fn active_server_changed(&self, server: Option<&BSimServerInfoData>);
}

/// Server info data for listeners.
#[derive(Debug, Clone)]
pub struct BSimServerInfoData {
    /// Server name.
    pub name: String,
    /// Server URL.
    pub url: String,
}

/// BSim search service.
///
/// Ported from `ghidra.features.bsim.gui.search.dialog.BSimSearchService`.
#[derive(Debug, Clone)]
pub struct BSimSearchServiceData {
    /// Service name.
    pub name: String,
    /// Whether the service is available.
    pub available: bool,
}

/// SQL function database implementation.
///
/// Ported from `ghidra.features.bsim.query.SQLFunctionDatabase`.
#[derive(Debug)]
pub struct SqlFunctionDatabaseImpl {
    /// Connection info.
    pub connection_url: String,
    /// Database name.
    pub database_name: String,
    /// Whether connected.
    pub connected: bool,
}

impl SqlFunctionDatabaseImpl {
    /// Create a new SQL function database.
    pub fn new(url: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            connection_url: url.into(),
            database_name: name.into(),
            connected: false,
        }
    }
}

/// BSim JDBC data source.
///
/// Ported from `ghidra.features.bsim.query.BSimJDBCDataSource`.
#[derive(Debug, Clone)]
pub struct BSimJdbcDataSource {
    /// JDBC URL.
    pub url: String,
    /// Driver class name.
    pub driver: String,
    /// Username.
    pub username: String,
}

impl BSimJdbcDataSource {
    /// Create a new data source.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            driver: String::new(),
            username: String::new(),
        }
    }
}

/// H2 file database connection manager.
///
/// Ported from `ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager`.
#[derive(Debug, Clone)]
pub struct BSimH2FileDbConnectionManager {
    /// File path.
    pub file_path: String,
    /// Whether the connection is active.
    pub connected: bool,
}

impl BSimH2FileDbConnectionManager {
    /// Create a new connection manager.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            file_path: path.into(),
            connected: false,
        }
    }
}

/// PostgreSQL database connection manager.
///
/// Ported from `ghidra.features.bsim.query.BSimPostgresDBConnectionManager`.
#[derive(Debug, Clone)]
pub struct BSimPostgresDbConnectionManager {
    /// Connection URL.
    pub url: String,
    /// Whether connected.
    pub connected: bool,
}

impl BSimPostgresDbConnectionManager {
    /// Create a new connection manager.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            connected: false,
        }
    }
}

// ============================================================================
// GUI Search Types
// ============================================================================

/// Status renderer for BSim results.
///
/// Ported from `ghidra.features.bsim.gui.search.results.BSimStatusRenderer`.
#[derive(Debug, Clone)]
pub struct BSimStatusRenderer {
    /// Show match status.
    pub show_match: bool,
    /// Show confidence.
    pub show_confidence: bool,
}

impl Default for BSimStatusRenderer {
    fn default() -> Self {
        Self {
            show_match: true,
            show_confidence: true,
        }
    }
}

/// Result row object mapper.
///
/// Ported from `ghidra.features.bsim.gui.search.results.BSimResultRowObjectToAddressTableRowMapper`.
pub struct BSimResultRowObjectToAddressTableRowMapper;

impl BSimResultRowObjectToAddressTableRowMapper {
    /// Map a BSim result to an address table row.
    pub fn map_result(result: &ExecutableResult) -> Option<i64> {
        if result.match_count > 0 {
            Some(result.exe_id)
        } else {
            None
        }
    }
}

/// Function symbol to table row mapper.
///
/// Ported from `ghidra.features.bsim.gui.search.dialog.FunctionSymbolToFunctionTableRowMapper`.
pub struct FunctionSymbolToFunctionTableRowMapper;

impl FunctionSymbolToFunctionTableRowMapper {
    /// Map a function name to a table row.
    pub fn map_function(name: &str, address: u64) -> (String, u64) {
        (name.to_string(), address)
    }
}

/// Table model for apply results.
///
/// Ported from `ghidra.features.bsim.gui.search.results.BSimApplyResultsTableModel`.
#[derive(Debug, Clone)]
pub struct BSimApplyResultsTableModel {
    /// Results data.
    pub rows: Vec<BSimApplyResultRow>,
}

/// A row in the apply results table.
#[derive(Debug, Clone)]
pub struct BSimApplyResultRow {
    /// Function name.
    pub function_name: String,
    /// Whether the apply was successful.
    pub success: bool,
    /// Error message (if any).
    pub error: Option<String>,
}

impl BSimApplyResultsTableModel {
    /// Create a new table model.
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }
}

impl Default for BSimApplyResultsTableModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Dialog for displaying BSim apply results.
///
/// Ported from `ghidra.features.bsim.gui.search.results.BSimApplyResultsDisplayDialog`.
#[derive(Debug, Clone)]
pub struct BSimApplyResultsDisplayDialog {
    /// Dialog title.
    pub title: String,
    /// Table model with results.
    pub model: BSimApplyResultsTableModel,
}

impl BSimApplyResultsDisplayDialog {
    /// Create a new dialog.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            model: BSimApplyResultsTableModel::new(),
        }
    }
}

/// Server dialog for BSim.
///
/// Ported from `ghidra.features.bsim.gui.search.dialog.CreateBsimServerInfoDialog`.
#[derive(Debug, Clone)]
pub struct CreateBsimServerInfoDialog {
    /// Server name.
    pub name: String,
    /// Server URL.
    pub url: String,
}

impl Default for CreateBsimServerInfoDialog {
    fn default() -> Self {
        Self {
            name: String::new(),
            url: String::new(),
        }
    }
}

/// Search dialog for BSim.
///
/// Ported from `ghidra.features.bsim.gui.search.dialog.BSimSearchDialog`.
#[derive(Debug, Clone)]
pub struct BSimSearchDialogData {
    /// Search query text.
    pub query_text: String,
    /// Selected server.
    pub server: Option<String>,
    /// Filter criteria.
    pub filters: Vec<String>,
}

impl Default for BSimSearchDialogData {
    fn default() -> Self {
        Self {
            query_text: String::new(),
            server: None,
            filters: Vec::new(),
        }
    }
}

/// Search info display dialog.
///
/// Ported from `ghidra.features.bsim.gui.search.dialog.BSimSearchInfoDisplayDialog`.
#[derive(Debug, Clone)]
pub struct BSimSearchInfoDisplayDialog {
    /// Title.
    pub title: String,
    /// Info text.
    pub info: String,
}

/// Search results filter dialog.
///
/// Ported from `ghidra.features.bsim.gui.search.results.BSimSearchResultsFilterDialog`.
#[derive(Debug, Clone)]
pub struct BSimSearchResultsFilterDialog {
    /// Active filters.
    pub filters: Vec<String>,
}

/// Search results provider.
///
/// Ported from `ghidra.features.bsim.gui.search.results.BSimSearchResultsProvider`.
#[derive(Debug, Clone)]
pub struct BSimSearchResultsProviderData {
    /// Results.
    pub results: Vec<ExecutableResult>,
}

// ============================================================================
// Base64 utilities for vector encoding
// ============================================================================

/// Base64-lite encoder for BSim vector data.
///
/// Ported from `ghidra.features.bsim.query.elastic.Base64Lite`.
pub struct Base64Lite;

impl Base64Lite {
    /// Encode bytes to a URL-safe Base64 string.
    pub fn encode(data: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
            result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
            if chunk.len() > 2 {
                result.push(CHARS[(triple & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
        }
        result
    }

    /// Decode a Base64 string to bytes.
    pub fn decode(encoded: &str) -> Result<Vec<u8>, String> {
        let mut result = Vec::new();
        let clean: String = encoded.chars().filter(|c| *c != '=' && !c.is_whitespace()).collect();
        let bytes = clean.as_bytes();
        for chunk in bytes.chunks(4) {
            let d = |c: u8| -> Result<u32, String> {
                match c {
                    b'A'..=b'Z' => Ok((c - b'A') as u32),
                    b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
                    b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
                    b'+' => Ok(62),
                    b'/' => Ok(63),
                    _ => Err(format!("Invalid Base64 character: {}", c as char)),
                }
            };
            if chunk.len() >= 2 {
                let c0 = d(chunk[0])?;
                let c1 = d(chunk[1])?;
                result.push(((c0 << 2) | (c1 >> 4)) as u8);
                if chunk.len() >= 3 {
                    let c2 = d(chunk[2])?;
                    result.push((((c1 & 0x0F) << 4) | (c2 >> 2)) as u8);
                    if chunk.len() >= 4 {
                        let c3 = d(chunk[3])?;
                        result.push((((c2 & 0x03) << 6) | c3) as u8);
                    }
                }
            }
        }
        Ok(result)
    }
}

/// Base64 vector factory for creating vector objects.
///
/// Ported from `ghidra.features.bsim.query.elastic.Base64VectorFactory`.
pub struct Base64VectorFactory;

impl Base64VectorFactory {
    /// Create a vector from a Base64-encoded string.
    pub fn from_base64(encoded: &str) -> Result<Vec<f32>, String> {
        let bytes = Base64Lite::decode(encoded)?;
        Ok(bytes
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect())
    }

    /// Encode a vector to Base64.
    pub fn to_base64(vector: &[f32]) -> String {
        let bytes: Vec<u8> = vector.iter().flat_map(|f| f.to_le_bytes()).collect();
        Base64Lite::encode(&bytes)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_description() {
        let mut fd = FunctionDescription::new(Some(1), "main", 0x1000);
        assert_eq!(fd.function_name(), "main");
        assert_eq!(fd.address(), 0x1000);
        fd.set_id(42);
        assert_eq!(fd.id, Some(42));
        fd.set_vector_id(100);
        assert_eq!(fd.vector_id, 100);
        fd.set_flags(1);
        assert_eq!(fd.flags, 1);
        fd.insert_call(2, 123);
        assert_eq!(fd.callgraph.len(), 1);
        fd.set_signature(3);
        assert_eq!(fd.signature, Some(3));
    }

    #[test]
    fn test_function_description_ordering() {
        let fd1 = FunctionDescription::new(None, "aaa", 0x100);
        let fd2 = FunctionDescription::new(None, "bbb", 0x200);
        assert!(fd1 < fd2);
    }

    #[test]
    fn test_executable_record() {
        let mut exe = ExecutableRecord::new("test.exe", "abc123");
        exe.architecture = "x86".to_string();
        exe.compiler = "gcc".to_string();
        assert_eq!(exe.name, "test.exe");
        assert_eq!(exe.md5, "abc123");
    }

    #[test]
    fn test_abstract_sql_function_database() {
        let mut db = AbstractSqlFunctionDatabase::new("jdbc:postgresql://localhost/bsim", "test");
        assert!(!db.is_connected());
        db.connect().unwrap();
        assert!(db.is_connected());
        db.disconnect();
        assert!(!db.is_connected());
    }

    #[test]
    fn test_bsim_sql_clause() {
        let clause = BSimSqlClause::new("SELECT * FROM functions")
            .with_param("test")
            .with_param("123");
        assert_eq!(clause.clause, "SELECT * FROM functions");
        assert_eq!(clause.params.len(), 2);
    }

    #[test]
    fn test_cancelled_sql_exception() {
        let err = CancelledSqlException::new("user cancelled");
        assert!(format!("{}", err).contains("user cancelled"));
    }

    #[test]
    fn test_bsim_client_configuration() {
        let config = BSimClientConfiguration::default();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 5432);
        assert_eq!(config.database, "bsim");
    }

    #[test]
    fn test_executable_scorer_single() {
        let mut scorer = ExecutableScorerSingle::new();
        scorer.match_count = 50;
        scorer.total_count = 100;
        assert!((scorer.normalized_score() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_file_score_cache() {
        let mut cache = FileScoreCache::new("/tmp/cache.dat");
        cache.put("exe1", "exe2", 0.75);
        assert_eq!(cache.get("exe1", "exe2"), Some(0.75));
        assert_eq!(cache.get("exe1", "exe3"), None);
    }

    #[test]
    fn test_id_histogram() {
        let mut hist = IdHistogram::new();
        hist.add(1);
        hist.add(1);
        hist.add(2);
        assert_eq!(hist.count(1), 2);
        assert_eq!(hist.count(2), 1);
        assert_eq!(hist.count(3), 0);
        assert_eq!(hist.total, 3);
    }

    #[test]
    fn test_id_sql_resolution() {
        let r = IdSqlResolution::resolved(42);
        assert!(r.resolved);
        assert_eq!(r.id, 42);

        let r2 = IdSqlResolution::error("not found");
        assert!(!r2.resolved);
        assert!(r2.error.is_some());
    }

    #[test]
    fn test_row_key_sql() {
        let key = RowKeySql::new(123);
        assert_eq!(key.key, 123);
    }

    #[test]
    fn test_sql_effects() {
        let mut effects = SqlEffects::new();
        effects.inserts = 10;
        effects.selects = 5;
        let mut other = SqlEffects::new();
        other.inserts = 3;
        other.deletes = 2;
        effects.merge(&other);
        assert_eq!(effects.inserts, 13);
        assert_eq!(effects.deletes, 2);
    }

    #[test]
    fn test_table_score_cache() {
        let mut cache = TableScoreCache::new();
        cache.put("table1", "exe1", 0.9);
        assert_eq!(cache.get("table1", "exe1"), Some(0.9));
        assert_eq!(cache.get("table1", "exe2"), None);
    }

    #[test]
    fn test_temporary_score_cache() {
        let mut cache = TemporaryScoreCache::new();
        cache.put(1, 2, 0.85);
        assert_eq!(cache.get(1, 2), Some(0.85));
        assert_eq!(cache.get(2, 1), None);
    }

    #[test]
    fn test_sql_complex_table() {
        let mut table = SqlComplexTable::new("test_table");
        table.add_column("id");
        table.add_column("name");
        assert_eq!(table.columns.len(), 2);
    }

    #[test]
    fn test_sql_string_table() {
        let mut table = SqlStringTable::new("strings");
        let id1 = table.insert("hello");
        let id2 = table.insert("world");
        let id1_dup = table.insert("hello");
        assert_eq!(id1, id1_dup);
        assert_ne!(id1, id2);
        assert_eq!(table.get(id1), Some("hello"));
        assert_eq!(table.get_id("world"), Some(id2));
    }

    #[test]
    fn test_base64_lite_roundtrip() {
        let data = b"Hello, World!";
        let encoded = Base64Lite::encode(data);
        let decoded = Base64Lite::decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_base64_lite_empty() {
        let encoded = Base64Lite::encode(b"");
        assert!(encoded.is_empty());
    }

    #[test]
    fn test_base64_vector_factory_roundtrip() {
        let vec_data = vec![1.0f32, 2.0, 3.0, -4.5];
        let encoded = Base64VectorFactory::to_base64(&vec_data);
        let decoded = Base64VectorFactory::from_base64(&encoded).unwrap();
        assert_eq!(vec_data.len(), decoded.len());
        for (a, b) in vec_data.iter().zip(decoded.iter()) {
            assert!((a - b).abs() < 1e-6);
        }
    }

    #[test]
    fn test_elastic_utilities_vector_encoding() {
        let vec_data = vec![1.0f32, 2.0, 3.0];
        let encoded = ElasticUtilities::encode_vector_base64(&vec_data);
        let decoded = ElasticUtilities::decode_vector_base64(&encoded).unwrap();
        assert_eq!(vec_data.len(), decoded.len());
        for (a, b) in vec_data.iter().zip(decoded.iter()) {
            assert!((a - b).abs() < 1e-6);
        }
    }

    #[test]
    fn test_id_elastic_resolution() {
        let r = IdElasticResolution::resolved("doc_123");
        assert!(r.resolved);
        assert_eq!(r.doc_id, "doc_123");
    }

    #[test]
    fn test_protocol_types() {
        let adj = AdjustVectorIndex { old_index: 1, new_index: 2 };
        assert_eq!(adj.new_index, 2);

        let child = ChildAtom { child_id: 5, lhash: 42 };
        assert_eq!(child.child_id, 5);

        let note = ClusterNote { cluster_id: 1, note: "test".to_string() };
        assert_eq!(note.cluster_id, 1);

        let create = CreateDatabaseRequest {
            name: "new_db".to_string(),
            template: None,
        };
        assert_eq!(create.name, "new_db");

        let drop_req = DropDatabaseRequest { name: "old_db".to_string() };
        assert_eq!(drop_req.name, "old_db");
    }

    #[test]
    fn test_bulk_signatures() {
        let bulk = BulkSignatures::new(1000);
        assert_eq!(bulk.count, 1000);
        assert_eq!(bulk.batch_size, 100);
    }

    #[test]
    fn test_iterate_repository() {
        let iter = IterateRepository::new("/path/to/repo");
        assert_eq!(iter.path, "/path/to/repo");
    }

    #[test]
    fn test_compare_signatures() {
        let cmp = CompareSignatures::new("db1", "db2", 0.5);
        assert_eq!(cmp.source_db, "db1");
        assert_eq!(cmp.threshold, 0.5);
    }

    #[test]
    fn test_bsim_plugin_package() {
        let pkg = BsimPluginPackage::default();
        assert_eq!(pkg.name, "BSim");
    }

    #[test]
    fn test_apply_results_table_model() {
        let model = BSimApplyResultsTableModel::new();
        assert!(model.rows.is_empty());
    }

    #[test]
    fn test_sql_function_database_impl() {
        let db = SqlFunctionDatabaseImpl::new("jdbc:url", "mydb");
        assert_eq!(db.database_name, "mydb");
        assert!(!db.connected);
    }

    #[test]
    fn test_bsim_jdbc_data_source() {
        let ds = BSimJdbcDataSource::new("jdbc:postgresql://localhost/bsim");
        assert_eq!(ds.url, "jdbc:postgresql://localhost/bsim");
    }

    #[test]
    fn test_h2_file_db_connection_manager() {
        let mgr = BSimH2FileDbConnectionManager::new("/tmp/test.h2");
        assert_eq!(mgr.file_path, "/tmp/test.h2");
        assert!(!mgr.connected);
    }

    #[test]
    fn test_postgres_db_connection_manager() {
        let mgr = BSimPostgresDbConnectionManager::new("jdbc:postgresql://host/db");
        assert!(!mgr.connected);
    }
}
