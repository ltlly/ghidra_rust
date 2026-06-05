//! BSim query protocol types.
//!
//! Port of `ghidra.features.bsim.query.protocol`:
//! client-server protocol types for BSim queries.

pub mod protocol_ext;

use serde::{Deserialize, Serialize};

use super::super::description::{
    CategoryRecord, DatabaseInformation, ExecutableRecord, FunctionDescription,
    SignatureRecord, VectorResult,
};

/// An operator type for a BSim filter atom.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterOperator {
    /// Equals.
    Equals,
    /// Not equals.
    NotEquals,
    /// Contains.
    Contains,
    /// Starts with.
    StartsWith,
    /// Less than (for numeric fields).
    LessThan,
    /// Greater than (for numeric fields).
    GreaterThan,
}

/// An atom in a BSim filter expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterAtom {
    /// The field to filter on.
    pub field: String,
    /// The operator.
    pub operator: FilterOperator,
    /// The value to compare against.
    pub value: String,
}

impl FilterAtom {
    /// Create a new filter atom.
    pub fn new(
        field: impl Into<String>,
        operator: FilterOperator,
        value: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            operator,
            value: value.into(),
        }
    }
}

/// A similarity note describing a match between two functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityNote {
    /// Hash of the first function.
    pub hash_a: String,
    /// Hash of the second function.
    pub hash_b: String,
    /// Similarity score.
    pub similarity: f64,
    /// Significance score.
    pub significance: f64,
}

/// A result from a similarity query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityResult {
    /// The query function.
    pub query: FunctionDescription,
    /// Matched functions with their scores.
    pub matches: Vec<SimilarityNote>,
}

/// A vector result from a BSim query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityVectorResult {
    /// The function.
    pub function: FunctionDescription,
    /// Feature vector.
    pub vector: Vec<(u64, f64)>,
    /// Similarity score.
    pub similarity: f64,
}

/// Staging manager for batched insert operations.
#[derive(Debug, Clone)]
pub struct StagingManager {
    /// Staged function descriptions.
    staged_functions: Vec<FunctionDescription>,
    /// Staged signatures.
    staged_signatures: Vec<SignatureRecord>,
    /// Batch size for flushing.
    pub batch_size: usize,
}

impl StagingManager {
    /// Create a new staging manager.
    pub fn new(batch_size: usize) -> Self {
        Self {
            staged_functions: Vec::new(),
            staged_signatures: Vec::new(),
            batch_size,
        }
    }

    /// Stage a function for insertion.
    pub fn stage_function(&mut self, func: FunctionDescription) {
        self.staged_functions.push(func);
    }

    /// Stage a signature for insertion.
    pub fn stage_signature(&mut self, sig: SignatureRecord) {
        self.staged_signatures.push(sig);
    }

    /// Check if the batch is ready to flush.
    pub fn is_ready(&self) -> bool {
        self.staged_functions.len() >= self.batch_size
    }

    /// Get the number of staged items.
    pub fn staged_count(&self) -> usize {
        self.staged_functions.len()
    }

    /// Clear all staged items.
    pub fn clear(&mut self) {
        self.staged_functions.clear();
        self.staged_signatures.clear();
    }

    /// Take all staged functions (drains the buffer).
    pub fn drain_functions(&mut self) -> Vec<FunctionDescription> {
        std::mem::take(&mut self.staged_functions)
    }
}

/// Staging manager default batch size.
impl Default for StagingManager {
    fn default() -> Self {
        Self::new(100)
    }
}

// ============================================================================
// BSimQuery — the main query request
// ============================================================================

/// A BSim query request sent from client to server.
///
/// Port of `ghidra.features.bsim.query.protocol.BSimQuery`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimQuery {
    /// The function to search for similarities.
    pub query_function: FunctionDescription,
    /// The filter to apply to results.
    pub filter: BSimFilter,
    /// Maximum number of results to return.
    pub max_results: usize,
    /// Minimum similarity threshold.
    pub min_similarity: f64,
}

impl BSimQuery {
    /// Create a new query.
    pub fn new(query_function: FunctionDescription) -> Self {
        Self {
            query_function,
            filter: BSimFilter::new(),
            max_results: 100,
            min_similarity: 0.7,
        }
    }

    /// Set the maximum results.
    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results = max;
        self
    }

    /// Set the minimum similarity.
    pub fn with_min_similarity(mut self, threshold: f64) -> Self {
        self.min_similarity = threshold;
        self
    }
}

// ============================================================================
// BSimFilter — collection of filter atoms
// ============================================================================

/// A collection of filter atoms for narrowing BSim results.
///
/// Port of `ghidra.features.bsim.query.protocol.BSimFilter`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BSimFilter {
    /// The filter atoms.
    atoms: Vec<FilterAtom>,
    /// Mask for function description flags.
    filter_flags_mask: u32,
    /// Value for function description flags.
    filter_flags_value: u32,
}

impl BSimFilter {
    /// Create an empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a filter atom.
    pub fn add_atom(&mut self, atom: FilterAtom) {
        self.atoms.push(atom);
    }

    /// Get the number of atoms.
    pub fn num_atoms(&self) -> usize {
        self.atoms.len()
    }

    /// Get an atom by index.
    pub fn get_atom(&self, i: usize) -> Option<&FilterAtom> {
        self.atoms.get(i)
    }

    /// Get all atoms.
    pub fn atoms(&self) -> &[FilterAtom] {
        &self.atoms
    }

    /// Clear all atoms.
    pub fn clear(&mut self) {
        self.atoms.clear();
        self.filter_flags_mask = 0;
        self.filter_flags_value = 0;
    }

    /// Set the function flag bits for tag-based filtering.
    pub fn set_flag_filter(&mut self, mask: u32, value: u32) {
        self.filter_flags_mask = mask;
        self.filter_flags_value = value;
    }

    /// Get the flags mask.
    pub fn flags_mask(&self) -> u32 {
        self.filter_flags_mask
    }

    /// Get the flags value.
    pub fn flags_value(&self) -> u32 {
        self.filter_flags_value
    }

    /// Check if this filter is empty.
    pub fn is_empty(&self) -> bool {
        self.atoms.is_empty() && self.filter_flags_mask == 0
    }
}

// ============================================================================
// ExeSpecifier — identifies an executable
// ============================================================================

/// Identifies an executable in a BSim database.
///
/// Port of `ghidra.features.bsim.query.protocol.ExeSpecifier`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExeSpecifier {
    /// Executable name.
    pub name: String,
    /// Architecture string.
    pub architecture: String,
    /// MD5 hash.
    pub md5: String,
}

impl ExeSpecifier {
    /// Create a new executable specifier.
    pub fn new(name: impl Into<String>, architecture: impl Into<String>, md5: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            architecture: architecture.into(),
            md5: md5.into(),
        }
    }
}

// ============================================================================
// FunctionEntry — a function to insert/query
// ============================================================================

/// A function entry for BSim operations.
///
/// Port of `ghidra.features.bsim.query.protocol.FunctionEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionEntry {
    /// Function name.
    pub name: String,
    /// Entry point address.
    pub address: u64,
    /// Function body hash.
    pub body_hash: String,
    /// Optional feature vector.
    pub vector: Vec<(u64, f64)>,
}

impl FunctionEntry {
    /// Create a new function entry.
    pub fn new(name: impl Into<String>, address: u64, body_hash: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            address,
            body_hash: body_hash.into(),
            vector: Vec::new(),
        }
    }

    /// Add a feature to the vector.
    pub fn add_feature(&mut self, feature_id: u64, weight: f64) {
        self.vector.push((feature_id, weight));
    }
}

// ============================================================================
// Database management commands
// ============================================================================

/// Request to create a new BSim database.
///
/// Port of `ghidra.features.bsim.query.protocol.CreateDatabase`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDatabase {
    /// Database name.
    pub database_name: String,
    /// Database information.
    pub info: DatabaseInformation,
}

impl CreateDatabase {
    /// Create a new create-database request.
    pub fn new(database_name: impl Into<String>, info: DatabaseInformation) -> Self {
        Self {
            database_name: database_name.into(),
            info,
        }
    }
}

/// Request to drop a BSim database.
///
/// Port of `ghidra.features.bsim.query.protocol.DropDatabase`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DropDatabase {
    /// Database name to drop.
    pub database_name: String,
}

impl DropDatabase {
    /// Create a new drop-database request.
    pub fn new(database_name: impl Into<String>) -> Self {
        Self {
            database_name: database_name.into(),
        }
    }
}

// ============================================================================
// Insert operations
// ============================================================================

/// Request to insert function signatures into the database.
///
/// Port of `ghidra.features.bsim.query.protocol.InsertRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertRequest {
    /// The executable to associate with.
    pub exe_spec: ExeSpecifier,
    /// Functions to insert.
    pub functions: Vec<FunctionEntry>,
}

impl InsertRequest {
    /// Create a new insert request.
    pub fn new(exe_spec: ExeSpecifier) -> Self {
        Self {
            exe_spec,
            functions: Vec::new(),
        }
    }

    /// Add a function entry.
    pub fn add_function(&mut self, entry: FunctionEntry) {
        self.functions.push(entry);
    }

    /// Number of functions to insert.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }
}

/// Optional values to insert alongside signatures.
///
/// Port of `ghidra.features.bsim.query.protocol.InsertOptionalValues`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InsertOptionalValues {
    /// Category information.
    pub category: Option<String>,
    /// Compiler information.
    pub compiler: Option<String>,
    /// Additional metadata.
    pub metadata: std::collections::HashMap<String, String>,
}

impl InsertOptionalValues {
    /// Create empty optional values.
    pub fn new() -> Self {
        Self::default()
    }
}

// ============================================================================
// Cluster note for similarity results
// ============================================================================

/// A cluster note grouping similar functions.
///
/// Port of `ghidra.features.bsim.query.protocol.ClusterNote`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNote {
    /// Cluster identifier.
    pub cluster_id: u32,
    /// Function hashes in this cluster.
    pub function_hashes: Vec<String>,
    /// Average similarity within the cluster.
    pub avg_similarity: f64,
}

impl ClusterNote {
    /// Create a new cluster note.
    pub fn new(cluster_id: u32) -> Self {
        Self {
            cluster_id,
            function_hashes: Vec::new(),
            avg_similarity: 0.0,
        }
    }

    /// Add a function hash to the cluster.
    pub fn add_function(&mut self, hash: impl Into<String>) {
        self.function_hashes.push(hash.into());
    }
}

// ============================================================================
// ChildAtom for hierarchical filter evaluation
// ============================================================================

/// A child atom in a hierarchical filter expression.
///
/// Port of `ghidra.features.bsim.query.protocol.ChildAtom`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildAtom {
    /// The parent field name.
    pub parent_field: String,
    /// The child field name.
    pub child_field: String,
    /// The value to match.
    pub value: String,
}

impl ChildAtom {
    /// Create a new child atom.
    pub fn new(parent_field: impl Into<String>, child_field: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            parent_field: parent_field.into(),
            child_field: child_field.into(),
            value: value.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_atom() {
        let atom = FilterAtom::new("name", FilterOperator::Equals, "main");
        assert_eq!(atom.field, "name");
        assert_eq!(atom.operator, FilterOperator::Equals);
    }

    #[test]
    fn test_similarity_note() {
        let note = SimilarityNote {
            hash_a: "aaa".to_string(),
            hash_b: "bbb".to_string(),
            similarity: 0.9,
            significance: 0.95,
        };
        assert_eq!(note.similarity, 0.9);
    }

    #[test]
    fn test_staging_manager() {
        let mut sm = StagingManager::new(3);
        sm.stage_function(FunctionDescription::new(0, "f1", Some(0x1000)));
        sm.stage_function(FunctionDescription::new(0, "f2", Some(0x2000)));
        assert!(!sm.is_ready());
        sm.stage_function(FunctionDescription::new(0, "f3", Some(0x3000)));
        assert!(sm.is_ready());
        assert_eq!(sm.staged_count(), 3);
    }

    #[test]
    fn test_staging_drain() {
        let mut sm = StagingManager::new(10);
        sm.stage_function(FunctionDescription::new(0, "f1", Some(0x1000)));
        let drained = sm.drain_functions();
        assert_eq!(drained.len(), 1);
        assert_eq!(sm.staged_count(), 0);
    }

    #[test]
    fn test_staging_clear() {
        let mut sm = StagingManager::new(10);
        sm.stage_function(FunctionDescription::new(0, "f1", Some(0x1000)));
        sm.clear();
        assert_eq!(sm.staged_count(), 0);
    }

    #[test]
    fn test_bsim_query() {
        let q = BSimQuery::new(FunctionDescription::new(0, "main", Some(0x1000)))
            .with_max_results(50)
            .with_min_similarity(0.9);
        assert_eq!(q.max_results, 50);
        assert_eq!(q.min_similarity, 0.9);
        assert_eq!(q.query_function.function_name, "main");
    }

    #[test]
    fn test_bsim_filter() {
        let mut filter = BSimFilter::new();
        assert!(filter.is_empty());
        filter.add_atom(FilterAtom::new("arch", FilterOperator::Equals, "x86"));
        assert_eq!(filter.num_atoms(), 1);
        filter.set_flag_filter(0xFF, 0x01);
        assert_eq!(filter.flags_mask(), 0xFF);
        assert_eq!(filter.flags_value(), 0x01);
        filter.clear();
        assert!(filter.is_empty());
    }

    #[test]
    fn test_exe_specifier() {
        let spec = ExeSpecifier::new("libc.so", "x86:LE:64:default", "abc123");
        assert_eq!(spec.name, "libc.so");
        assert_eq!(spec.architecture, "x86:LE:64:default");
    }

    #[test]
    fn test_function_entry() {
        let mut entry = FunctionEntry::new("malloc", 0x1000, "hash123");
        entry.add_feature(1, 0.5);
        entry.add_feature(2, 0.3);
        assert_eq!(entry.vector.len(), 2);
        assert_eq!(entry.address, 0x1000);
    }

    #[test]
    fn test_insert_request() {
        let spec = ExeSpecifier::new("test", "x86", "md5");
        let mut req = InsertRequest::new(spec);
        req.add_function(FunctionEntry::new("f1", 0x100, "h1"));
        req.add_function(FunctionEntry::new("f2", 0x200, "h2"));
        assert_eq!(req.function_count(), 2);
    }

    #[test]
    fn test_create_database() {
        let mut info = DatabaseInformation::default();
        info.database_name = "test_db".to_string();
        let cmd = CreateDatabase::new("test_db", info);
        assert_eq!(cmd.database_name, "test_db");
    }

    #[test]
    fn test_drop_database() {
        let cmd = DropDatabase::new("old_db");
        assert_eq!(cmd.database_name, "old_db");
    }

    #[test]
    fn test_cluster_note() {
        let mut cluster = ClusterNote::new(1);
        cluster.add_function("hash_a");
        cluster.add_function("hash_b");
        cluster.avg_similarity = 0.85;
        assert_eq!(cluster.function_hashes.len(), 2);
        assert_eq!(cluster.cluster_id, 1);
    }

    #[test]
    fn test_child_atom() {
        let atom = ChildAtom::new("executable", "name", "libc");
        assert_eq!(atom.parent_field, "executable");
        assert_eq!(atom.child_field, "name");
        assert_eq!(atom.value, "libc");
    }

    #[test]
    fn test_insert_optional_values() {
        let mut opts = InsertOptionalValues::new();
        opts.category = Some("library".to_string());
        assert_eq!(opts.category.as_deref(), Some("library"));
    }
}
