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

// ============================================================================
// BSimQueryType / BSimResponseType — protocol tag enums
// ============================================================================

/// Tag identifying the kind of BSim query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BSimQueryType {
    /// Query by name.
    Name,
    /// Query executable info.
    ExeInfo,
    /// Query executable count.
    ExeCount,
    /// Query nearest matches.
    Nearest,
    /// Query nearest vector matches.
    NearestVector,
    /// Query pairs.
    Pair,
    /// Query children.
    Children,
    /// Query cluster.
    Cluster,
    /// Query info.
    Info,
    /// Query delete.
    Delete,
    /// Query update.
    Update,
    /// Query optional existence.
    OptionalExist,
    /// Query optional values.
    OptionalValues,
    /// Query vector IDs.
    VectorId,
    /// Query vector matches.
    VectorMatch,
}

/// Tag identifying the kind of BSim response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BSimResponseType {
    /// Response to a name query.
    Name,
    /// Response with executable information.
    Exe,
    /// Response with nearest matches.
    Nearest,
    /// Response with nearest vector matches.
    NearestVector,
    /// Response with pair results.
    Pair,
    /// Response with children results.
    Children,
    /// Response with cluster results.
    Cluster,
    /// Response with info.
    Info,
    /// Response to delete.
    Delete,
    /// Response to update.
    Update,
    /// Response with optional existence.
    OptionalExist,
    /// Response with optional values.
    OptionalValues,
    /// Response with vector IDs.
    VectorId,
    /// Response with vector matches.
    VectorMatch,
    /// Response with inserted data confirmation.
    Insert,
    /// Response with drop database confirmation.
    DropDatabase,
    /// Response with adjust index results.
    AdjustIndex,
    /// Response with password change.
    Password,
    /// Response with prewarm results.
    Prewarm,
    /// Error response.
    Error,
}

// ============================================================================
// BSimQueryBase — base type for all query messages
// ============================================================================

/// Base metadata for every BSim query message.
///
/// Port of the common fields in Ghidra's `BSimQuery` base class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimQueryBase {
    /// The protocol message name (e.g., `"querynearest"`).
    pub name: String,
    /// The query type tag.
    pub query_type: BSimQueryType,
}

impl BSimQueryBase {
    /// Create a new query base with the given name and type.
    pub fn new(name: impl Into<String>, query_type: BSimQueryType) -> Self {
        Self {
            name: name.into(),
            query_type,
        }
    }
}

// ============================================================================
// AdjustVectorIndex — adjust feature-vector index
// ============================================================================

/// Request to adjust the vector index.
///
/// Port of `ghidra.features.bsim.query.protocol.AdjustVectorIndex`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdjustVectorIndex {
    /// The vector IDs to adjust.
    pub vector_ids: Vec<u64>,
    /// The adjustment offsets.
    pub offsets: Vec<i64>,
}

impl AdjustVectorIndex {
    /// Create a new adjust request.
    pub fn new() -> Self {
        Self {
            vector_ids: Vec::new(),
            offsets: Vec::new(),
        }
    }

    /// Add an adjustment entry.
    pub fn add_adjustment(&mut self, vector_id: u64, offset: i64) {
        self.vector_ids.push(vector_id);
        self.offsets.push(offset);
    }
}

impl Default for AdjustVectorIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ExecutableResultWithDeDuping — de-duped executable results
// ============================================================================

/// A container for executable results that de-duplicates by MD5.
///
/// Port of `ghidra.features.bsim.query.protocol.ExecutableResultWithDeDuping`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutableResultWithDeDuping {
    /// Unique executable records indexed by MD5.
    pub executables: Vec<ExecutableRecord>,
    /// Total count before de-duplication.
    pub total_count: usize,
}

impl ExecutableResultWithDeDuping {
    /// Create empty results.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an executable record (de-duplicates by MD5).
    pub fn add_executable(&mut self, record: ExecutableRecord) {
        let md5 = record.md5.clone();
        if !self.executables.iter().any(|e| e.md5 == md5) {
            self.executables.push(record);
        }
        self.total_count += 1;
    }

    /// Number of unique executables.
    pub fn unique_count(&self) -> usize {
        self.executables.len()
    }
}

// ============================================================================
// FunctionStaging — staging area for function batch insertion
// ============================================================================

/// A staging area for batching function insertion into BSim.
///
/// Port of `ghidra.features.bsim.query.protocol.FunctionStaging`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionStaging {
    /// Functions staged for insertion.
    pub functions: Vec<FunctionEntry>,
    /// The associated executable specifier.
    pub exe_spec: Option<ExeSpecifier>,
    /// The batch size.
    pub batch_size: usize,
}

impl FunctionStaging {
    /// Create a new staging area with a given batch size.
    pub fn new(batch_size: usize) -> Self {
        Self {
            functions: Vec::new(),
            exe_spec: None,
            batch_size,
        }
    }

    /// Stage a function entry.
    pub fn stage_function(&mut self, entry: FunctionEntry) {
        self.functions.push(entry);
    }

    /// Set the executable specifier.
    pub fn set_exe_spec(&mut self, spec: ExeSpecifier) {
        self.exe_spec = Some(spec);
    }

    /// Check if the staging area has reached its batch size.
    pub fn is_full(&self) -> bool {
        self.functions.len() >= self.batch_size
    }

    /// Number of staged functions.
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// Whether the staging area is empty.
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// Drain all staged functions.
    pub fn drain(&mut self) -> Vec<FunctionEntry> {
        std::mem::take(&mut self.functions)
    }
}

// ============================================================================
// NullStaging — a no-op staging implementation
// ============================================================================

/// A no-op staging manager that does nothing.
///
/// Port of `ghidra.features.bsim.query.protocol.NullStaging`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NullStaging;

impl NullStaging {
    /// Create a null staging.
    pub fn new() -> Self {
        Self
    }
}

// ============================================================================
// PairInput / PairNote — function pair comparison
// ============================================================================

/// Input describing a pair of functions to compare.
///
/// Port of `ghidra.features.bsim.query.protocol.PairInput`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairInput {
    /// Name of the first function.
    pub name_a: String,
    /// Name of the second function.
    pub name_b: String,
    /// MD5 of first executable.
    pub md5_a: String,
    /// MD5 of second executable.
    pub md5_b: String,
    /// Address of first function.
    pub address_a: u64,
    /// Address of second function.
    pub address_b: u64,
}

impl PairInput {
    /// Create a new pair input.
    pub fn new(
        name_a: impl Into<String>,
        name_b: impl Into<String>,
        md5_a: impl Into<String>,
        md5_b: impl Into<String>,
        address_a: u64,
        address_b: u64,
    ) -> Self {
        Self {
            name_a: name_a.into(),
            name_b: name_b.into(),
            md5_a: md5_a.into(),
            md5_b: md5_b.into(),
            address_a,
            address_b,
        }
    }
}

/// A note describing the result of comparing a pair of functions.
///
/// Port of `ghidra.features.bsim.query.protocol.PairNote`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairNote {
    /// The pair input this note corresponds to.
    pub pair: PairInput,
    /// Similarity score.
    pub similarity: f64,
    /// Significance score.
    pub significance: f64,
    /// Whether a match was found.
    pub matched: bool,
}

impl PairNote {
    /// Create a new pair note.
    pub fn new(pair: PairInput, similarity: f64, significance: f64) -> Self {
        Self {
            pair,
            similarity,
            significance,
            matched: similarity > 0.0,
        }
    }
}

// ============================================================================
// PasswordChange
// ============================================================================

/// Request to change the database password.
///
/// Port of `ghidra.features.bsim.query.protocol.PasswordChange`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordChange {
    /// Old password.
    pub old_password: String,
    /// New password.
    pub new_password: String,
}

impl PasswordChange {
    /// Create a new password change request.
    pub fn new(old_password: impl Into<String>, new_password: impl Into<String>) -> Self {
        Self {
            old_password: old_password.into(),
            new_password: new_password.into(),
        }
    }
}

// ============================================================================
// PreFilter — pre-query filter constraints
// ============================================================================

/// Pre-filter applied before main BSim query processing.
///
/// Port of `ghidra.features.bsim.query.protocol.PreFilter`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PreFilter {
    /// Minimum function body size.
    pub min_body_size: Option<u64>,
    /// Maximum function body size.
    pub max_body_size: Option<u64>,
    /// Architecture filter.
    pub architecture: Option<String>,
    /// Compiler filter.
    pub compiler: Option<String>,
    /// Minimum instruction count.
    pub min_instructions: Option<u32>,
}

impl PreFilter {
    /// Create an empty pre-filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a function would pass this pre-filter.
    pub fn passes(&self, body_size: u64, _num_instructions: u32) -> bool {
        if let Some(min) = self.min_body_size {
            if body_size < min {
                return false;
            }
        }
        if let Some(max) = self.max_body_size {
            if body_size > max {
                return false;
            }
        }
        if let Some(min_inst) = self.min_instructions {
            if _num_instructions < min_inst {
                return false;
            }
        }
        true
    }
}

// ============================================================================
// PrewarmRequest
// ============================================================================

/// Request to prewarm the database cache.
///
/// Port of `ghidra.features.bsim.query.protocol.PrewarmRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrewarmRequest {
    /// Whether to prewarm the vector cache.
    pub warm_vectors: bool,
    /// Whether to prewarm the description cache.
    pub warm_descriptions: bool,
    /// Maximum entries to prewarm.
    pub max_entries: usize,
}

impl PrewarmRequest {
    /// Create a new prewarm request.
    pub fn new() -> Self {
        Self {
            warm_vectors: true,
            warm_descriptions: true,
            max_entries: 1000,
        }
    }
}

impl Default for PrewarmRequest {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Install requests — category / metadata / tag
// ============================================================================

/// Request to install a new category.
///
/// Port of `ghidra.features.bsim.query.protocol.InstallCategoryRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallCategoryRequest {
    /// Category name.
    pub name: String,
    /// Category description.
    pub description: String,
    /// Parent category (if hierarchical).
    pub parent: Option<String>,
}

impl InstallCategoryRequest {
    /// Create a new install-category request.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parent: None,
        }
    }

    /// Set the parent category.
    pub fn with_parent(mut self, parent: impl Into<String>) -> Self {
        self.parent = Some(parent.into());
        self
    }
}

/// Request to install metadata for a database entry.
///
/// Port of `ghidra.features.bsim.query.protocol.InstallMetadataRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallMetadataRequest {
    /// Key-value metadata pairs.
    pub metadata: std::collections::HashMap<String, String>,
}

impl InstallMetadataRequest {
    /// Create a new install-metadata request.
    pub fn new() -> Self {
        Self {
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Add a metadata entry.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Get a metadata value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(|s| s.as_str())
    }
}

impl Default for InstallMetadataRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Request to install a function tag.
///
/// Port of `ghidra.features.bsim.query.protocol.InstallTagRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallTagRequest {
    /// Tag name.
    pub tag_name: String,
    /// Tag description.
    pub description: String,
}

impl InstallTagRequest {
    /// Create a new install-tag request.
    pub fn new(tag_name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            tag_name: tag_name.into(),
            description: description.into(),
        }
    }
}

// ============================================================================
// Query types
// ============================================================================

/// Query for executables by name.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryName`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryName {
    /// The executable name to query.
    pub name_exec: String,
    /// The MD5 filter.
    pub md5: Option<String>,
    /// The architecture filter.
    pub arch: Option<String>,
    /// Response storage.
    pub has_response: bool,
}

impl QueryName {
    /// Create a query by executable name.
    pub fn new(name_exec: impl Into<String>) -> Self {
        Self {
            name_exec: name_exec.into(),
            md5: None,
            arch: None,
            has_response: false,
        }
    }

    /// Add an MD5 filter.
    pub fn with_md5(mut self, md5: impl Into<String>) -> Self {
        self.md5 = Some(md5.into());
        self
    }

    /// Add an architecture filter.
    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.arch = Some(arch.into());
        self
    }
}

/// Sort order for executable queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExeTableOrderColumn {
    /// Sort by MD5.
    Md5,
    /// Sort by name.
    Name,
    /// Sort by architecture.
    Architecture,
    /// Sort by compiler.
    Compiler,
    /// Sort by category.
    Category,
}

impl Default for ExeTableOrderColumn {
    fn default() -> Self {
        Self::Md5
    }
}

/// Query for executable information records.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryExeInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryExeInfo {
    /// Maximum results to return.
    pub limit: usize,
    /// MD5 filter.
    pub filter_md5: Option<String>,
    /// Executable name filter.
    pub filter_exe_name: Option<String>,
    /// Architecture filter.
    pub filter_arch: Option<String>,
    /// Compiler name filter.
    pub filter_compiler_name: Option<String>,
    /// Sort column.
    pub sort_column: ExeTableOrderColumn,
    /// Whether to include fakes.
    pub include_fakes: bool,
    /// Whether to fill in categories.
    pub fillin_categories: bool,
}

impl QueryExeInfo {
    /// Create a default query (first 20 executables).
    pub fn new() -> Self {
        Self {
            limit: 20,
            filter_md5: None,
            filter_exe_name: None,
            filter_arch: None,
            filter_compiler_name: None,
            sort_column: ExeTableOrderColumn::Md5,
            include_fakes: false,
            fillin_categories: true,
        }
    }

    /// Set the result limit.
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }
}

impl Default for QueryExeInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Query for counting executable records.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryExeCount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryExeCount {
    /// MD5 filter.
    pub filter_md5: Option<String>,
    /// Executable name filter.
    pub filter_exe_name: Option<String>,
    /// Architecture filter.
    pub filter_arch: Option<String>,
    /// Compiler name filter.
    pub filter_compiler_name: Option<String>,
    /// Whether to include fakes.
    pub include_fakes: bool,
}

impl QueryExeCount {
    /// Create a new count query with no filters.
    pub fn new() -> Self {
        Self {
            filter_md5: None,
            filter_exe_name: None,
            filter_arch: None,
            filter_compiler_name: None,
            include_fakes: false,
        }
    }

    /// Create a count query with all filters.
    pub fn with_filters(
        filter_md5: Option<String>,
        filter_exe_name: Option<String>,
        filter_arch: Option<String>,
        filter_compiler_name: Option<String>,
        include_fakes: bool,
    ) -> Self {
        Self {
            filter_md5,
            filter_exe_name,
            filter_arch,
            filter_compiler_name,
            include_fakes,
        }
    }
}

impl Default for QueryExeCount {
    fn default() -> Self {
        Self::new()
    }
}

/// Query for nearest function matches.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryNearest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryNearest {
    /// Similarity threshold (default 0.7).
    pub thresh: f64,
    /// Significance threshold (default 0.0).
    pub signifthresh: f64,
    /// Maximum matches per function.
    pub max: usize,
    /// Maximum unique vectors to return.
    pub vectormax: usize,
    /// Whether to fill in categories.
    pub fillin_categories: bool,
    /// Optional BSim filter.
    pub bsim_filter: Option<BSimFilter>,
    /// Function descriptions for the query.
    pub functions: Vec<FunctionDescription>,
}

impl QueryNearest {
    /// Default similarity threshold.
    pub const DEFAULT_SIMILARITY_THRESHOLD: f64 = 0.7;
    /// Default significance threshold.
    pub const DEFAULT_SIGNIFICANCE_THRESHOLD: f64 = 0.0;
    /// Default max matches.
    pub const DEFAULT_MAX_MATCHES: usize = 20;

    /// Create a new nearest query with default parameters.
    pub fn new() -> Self {
        Self {
            thresh: Self::DEFAULT_SIMILARITY_THRESHOLD,
            signifthresh: Self::DEFAULT_SIGNIFICANCE_THRESHOLD,
            max: Self::DEFAULT_MAX_MATCHES,
            vectormax: 0,
            fillin_categories: true,
            bsim_filter: None,
            functions: Vec::new(),
        }
    }

    /// Add a function description.
    pub fn add_function(&mut self, func: FunctionDescription) {
        self.functions.push(func);
    }

    /// Set the filter.
    pub fn set_filter(&mut self, filter: BSimFilter) {
        self.bsim_filter = Some(filter);
    }
}

impl Default for QueryNearest {
    fn default() -> Self {
        Self::new()
    }
}

/// Query for nearest vector matches.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryNearestVector`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryNearestVector {
    /// The vector to match against.
    pub query_vector: Vec<(u64, f64)>,
    /// Similarity threshold.
    pub thresh: f64,
    /// Maximum matches.
    pub max: usize,
}

impl QueryNearestVector {
    /// Create a new nearest-vector query.
    pub fn new(thresh: f64, max: usize) -> Self {
        Self {
            query_vector: Vec::new(),
            thresh,
            max,
        }
    }

    /// Add a feature to the query vector.
    pub fn add_feature(&mut self, feature_id: u64, weight: f64) {
        self.query_vector.push((feature_id, weight));
    }
}

/// Query for pair-wise function comparisons.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryPair`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryPair {
    /// The pairs to compare.
    pub pairs: Vec<PairInput>,
}

impl QueryPair {
    /// Create a new pair query.
    pub fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    /// Add a pair.
    pub fn add_pair(&mut self, pair: PairInput) {
        self.pairs.push(pair);
    }

    /// Number of pairs.
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }
}

impl Default for QueryPair {
    fn default() -> Self {
        Self::new()
    }
}

/// Query for children of specified functions within an executable.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryChildren`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryChildren {
    /// MD5 of the executable.
    pub md5sum: Option<String>,
    /// Executable name.
    pub name_exec: Option<String>,
    /// Architecture.
    pub arch: Option<String>,
    /// Compiler name.
    pub name_compiler: Option<String>,
    /// Function keys to query children for.
    pub function_keys: Vec<FunctionEntry>,
}

impl QueryChildren {
    /// Create a new children query.
    pub fn new() -> Self {
        Self {
            md5sum: None,
            name_exec: None,
            arch: None,
            name_compiler: None,
            function_keys: Vec::new(),
        }
    }

    /// Add a function key.
    pub fn add_function_key(&mut self, entry: FunctionEntry) {
        self.function_keys.push(entry);
    }
}

impl Default for QueryChildren {
    fn default() -> Self {
        Self::new()
    }
}

/// Query for clusters of similar functions.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryCluster`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryCluster {
    /// Function descriptions for cluster roots.
    pub functions: Vec<FunctionDescription>,
    /// Similarity threshold for clustering.
    pub thresh: f64,
    /// Significance threshold.
    pub signifthresh: f64,
    /// Maximum vector results per function.
    pub vectormax: usize,
}

impl QueryCluster {
    /// Create a new cluster query.
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
            thresh: 0.9,
            signifthresh: 0.0,
            vectormax: 50,
        }
    }

    /// Add a function description.
    pub fn add_function(&mut self, func: FunctionDescription) {
        self.functions.push(func);
    }

    /// Create a local staging copy with the same thresholds.
    pub fn local_staging_copy(&self) -> Self {
        Self {
            functions: Vec::new(),
            thresh: self.thresh,
            signifthresh: self.signifthresh,
            vectormax: self.vectormax,
        }
    }
}

impl Default for QueryCluster {
    fn default() -> Self {
        Self::new()
    }
}

/// Query for deleting records.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryDelete`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryDelete {
    /// Executable MD5 to delete.
    pub md5: String,
    /// Function names to delete (empty = delete all for the executable).
    pub function_names: Vec<String>,
}

impl QueryDelete {
    /// Create a delete query for a full executable.
    pub fn new(md5: impl Into<String>) -> Self {
        Self {
            md5: md5.into(),
            function_names: Vec::new(),
        }
    }

    /// Add a specific function name to delete.
    pub fn add_function(&mut self, name: impl Into<String>) {
        self.function_names.push(name.into());
    }
}

/// Query for general database info.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryInfo {
    /// Whether to include detailed statistics.
    pub include_stats: bool,
}

impl QueryInfo {
    /// Create a new info query.
    pub fn new(include_stats: bool) -> Self {
        Self { include_stats }
    }
}

/// Query for updating records.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryUpdate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryUpdate {
    /// Executable MD5 to update.
    pub md5: String,
    /// Fields to update.
    pub fields: std::collections::HashMap<String, String>,
}

impl QueryUpdate {
    /// Create a new update query.
    pub fn new(md5: impl Into<String>) -> Self {
        Self {
            md5: md5.into(),
            fields: std::collections::HashMap::new(),
        }
    }

    /// Set a field value.
    pub fn set_field(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.fields.insert(key.into(), value.into());
    }
}

/// Query for checking optional value existence.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryOptionalExist`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryOptionalExist {
    /// The executable to query.
    pub md5: String,
    /// Optional value keys to check.
    pub keys: Vec<String>,
}

impl QueryOptionalExist {
    /// Create a new existence check query.
    pub fn new(md5: impl Into<String>) -> Self {
        Self {
            md5: md5.into(),
            keys: Vec::new(),
        }
    }

    /// Add a key to check.
    pub fn add_key(&mut self, key: impl Into<String>) {
        self.keys.push(key.into());
    }
}

/// Query for retrieving optional values.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryOptionalValues`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryOptionalValues {
    /// The executable to query.
    pub md5: String,
    /// Optional value keys to retrieve.
    pub keys: Vec<String>,
}

impl QueryOptionalValues {
    /// Create a new optional-values query.
    pub fn new(md5: impl Into<String>) -> Self {
        Self {
            md5: md5.into(),
            keys: Vec::new(),
        }
    }

    /// Add a key to retrieve.
    pub fn add_key(&mut self, key: impl Into<String>) {
        self.keys.push(key.into());
    }
}

/// Query for vector IDs.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryVectorId`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryVectorId {
    /// Function names to query vectors for.
    pub function_names: Vec<String>,
    /// Executable MD5.
    pub md5: String,
}

impl QueryVectorId {
    /// Create a new vector-ID query.
    pub fn new(md5: impl Into<String>) -> Self {
        Self {
            function_names: Vec::new(),
            md5: md5.into(),
        }
    }

    /// Add a function name.
    pub fn add_function(&mut self, name: impl Into<String>) {
        self.function_names.push(name.into());
    }
}

/// Query for vector-based matches.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryVectorMatch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryVectorMatch {
    /// The query vectors.
    pub query_vectors: Vec<Vec<(u64, f64)>>,
    /// Similarity threshold.
    pub thresh: f64,
    /// Maximum results.
    pub max: usize,
}

impl QueryVectorMatch {
    /// Create a new vector-match query.
    pub fn new(thresh: f64, max: usize) -> Self {
        Self {
            query_vectors: Vec::new(),
            thresh,
            max,
        }
    }

    /// Add a query vector.
    pub fn add_vector(&mut self, vector: Vec<(u64, f64)>) {
        self.query_vectors.push(vector);
    }
}

/// A record for a query response.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryResponseRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponseRecord {
    /// The function description.
    pub function: FunctionDescription,
    /// The signature record.
    pub signature: Option<SignatureRecord>,
    /// Similarity score (if applicable).
    pub similarity: Option<f64>,
    /// Significance score (if applicable).
    pub significance: Option<f64>,
}

impl QueryResponseRecord {
    /// Create a new response record.
    pub fn new(function: FunctionDescription) -> Self {
        Self {
            function,
            signature: None,
            similarity: None,
            significance: None,
        }
    }

    /// Set the similarity and significance scores.
    pub fn with_scores(mut self, similarity: f64, significance: f64) -> Self {
        self.similarity = Some(similarity);
        self.significance = Some(significance);
        self
    }
}

// ============================================================================
// Response types
// ============================================================================

/// Response to a name query.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseName`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseName {
    /// The executable records found.
    pub executables: Vec<ExecutableRecord>,
    /// Total count.
    pub total: usize,
}

impl ResponseName {
    /// Create a new response.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an executable record.
    pub fn add_executable(&mut self, record: ExecutableRecord) {
        self.executables.push(record);
        self.total = self.executables.len();
    }
}

/// Response containing executable records.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseExe`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseExe {
    /// The executable records.
    pub executables: Vec<ExecutableRecord>,
    /// Total count (may be larger than `executables.len()` if paginated).
    pub total: usize,
}

impl ResponseExe {
    /// Create a new response.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an executable record.
    pub fn add_executable(&mut self, record: ExecutableRecord) {
        self.executables.push(record);
        self.total = self.executables.len();
    }
}

/// Response with nearest function matches.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseNearest`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseNearest {
    /// The similarity results.
    pub results: Vec<SimilarityResult>,
    /// Description manager data (serialized flag).
    pub has_manager: bool,
}

impl ResponseNearest {
    /// Create a new response.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a similarity result.
    pub fn add_result(&mut self, result: SimilarityResult) {
        self.results.push(result);
    }
}

/// Response with nearest vector matches.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseNearestVector`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseNearestVector {
    /// The similarity vector results.
    pub results: Vec<SimilarityVectorResult>,
}

impl ResponseNearestVector {
    /// Create a new response.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a result.
    pub fn add_result(&mut self, result: SimilarityVectorResult) {
        self.results.push(result);
    }
}

/// Response with pair comparison results.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponsePair`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponsePair {
    /// Pair comparison notes.
    pub notes: Vec<PairNote>,
}

impl ResponsePair {
    /// Create a new response.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pair note.
    pub fn add_note(&mut self, note: PairNote) {
        self.notes.push(note);
    }
}

/// Response with children results.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseChildren`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseChildren {
    /// Child function records.
    pub children: Vec<FunctionDescription>,
    /// Total count.
    pub total: usize,
}

impl ResponseChildren {
    /// Create a new response.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a child function.
    pub fn add_child(&mut self, func: FunctionDescription) {
        self.children.push(func);
        self.total = self.children.len();
    }
}

/// Response with cluster results.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseCluster`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseCluster {
    /// The cluster notes.
    pub clusters: Vec<ClusterNote>,
    /// Total number of clusters.
    pub total: usize,
}

impl ResponseCluster {
    /// Create a new response.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a cluster note.
    pub fn add_cluster(&mut self, cluster: ClusterNote) {
        self.clusters.push(cluster);
        self.total = self.clusters.len();
    }
}

/// Response with database info.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseInfo`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseInfo {
    /// Database information.
    pub info: Option<DatabaseInformation>,
    /// Number of executables.
    pub exe_count: usize,
    /// Number of functions.
    pub function_count: usize,
}

impl ResponseInfo {
    /// Create a new info response.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Response to a delete query.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseDelete`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseDelete {
    /// Whether the delete was successful.
    pub success: bool,
    /// Number of records deleted.
    pub deleted_count: usize,
}

impl ResponseDelete {
    /// Create a delete response.
    pub fn new(success: bool, deleted_count: usize) -> Self {
        Self {
            success,
            deleted_count,
        }
    }
}

/// Response confirming drop database.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseDropDatabase`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseDropDatabase {
    /// Whether the drop was successful.
    pub success: bool,
    /// Error message if failed.
    pub error_message: Option<String>,
}

impl ResponseDropDatabase {
    /// Create a successful drop response.
    pub fn success() -> Self {
        Self {
            success: true,
            error_message: None,
        }
    }

    /// Create a failed drop response.
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            success: false,
            error_message: Some(message.into()),
        }
    }
}

/// Error response.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseError`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseError {
    /// Error code.
    pub error_code: i32,
    /// Error message.
    pub message: String,
    /// Whether the error is recoverable.
    pub recoverable: bool,
}

impl ResponseError {
    /// Create a new error response.
    pub fn new(error_code: i32, message: impl Into<String>) -> Self {
        Self {
            error_code,
            message: message.into(),
            recoverable: false,
        }
    }

    /// Mark the error as recoverable.
    pub fn as_recoverable(mut self) -> Self {
        self.recoverable = true;
        self
    }
}

/// Response to an insert operation.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseInsert`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseInsert {
    /// Whether the insert was successful.
    pub success: bool,
    /// Number of records inserted.
    pub inserted_count: usize,
    /// Any warning messages.
    pub warnings: Vec<String>,
}

impl ResponseInsert {
    /// Create a successful insert response.
    pub fn success(inserted_count: usize) -> Self {
        Self {
            success: true,
            inserted_count,
            warnings: Vec::new(),
        }
    }

    /// Add a warning.
    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }
}

/// Response with adjust index results.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseAdjustIndex`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAdjustIndex {
    /// Whether the adjustment was successful.
    pub success: bool,
    /// Number of entries adjusted.
    pub adjusted_count: usize,
}

impl ResponseAdjustIndex {
    /// Create a new adjust-index response.
    pub fn new(success: bool, adjusted_count: usize) -> Self {
        Self {
            success,
            adjusted_count,
        }
    }
}

/// Response with optional value existence.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseOptionalExist`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseOptionalExist {
    /// Keys and whether they exist.
    pub existence: std::collections::HashMap<String, bool>,
}

impl ResponseOptionalExist {
    /// Create a new response.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set existence for a key.
    pub fn set_exists(&mut self, key: impl Into<String>, exists: bool) {
        self.existence.insert(key.into(), exists);
    }

    /// Check if a key exists.
    pub fn exists(&self, key: &str) -> Option<bool> {
        self.existence.get(key).copied()
    }
}

/// Response with optional values.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseOptionalValues`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseOptionalValues {
    /// Key-value pairs.
    pub values: std::collections::HashMap<String, String>,
}

impl ResponseOptionalValues {
    /// Create a new response.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a value.
    pub fn set_value(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values.insert(key.into(), value.into());
    }

    /// Get a value.
    pub fn get_value(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(|s| s.as_str())
    }
}

/// Response to a password change.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponsePassword`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePassword {
    /// Whether the password change was successful.
    pub success: bool,
    /// Error message if failed.
    pub error_message: Option<String>,
}

impl ResponsePassword {
    /// Create a successful response.
    pub fn success() -> Self {
        Self {
            success: true,
            error_message: None,
        }
    }

    /// Create a failed response.
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            success: false,
            error_message: Some(message.into()),
        }
    }
}

/// Response to a prewarm request.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponsePrewarm`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePrewarm {
    /// Whether the prewarm was successful.
    pub success: bool,
    /// Number of entries warmed.
    pub entries_warmed: usize,
}

impl ResponsePrewarm {
    /// Create a prewarm response.
    pub fn new(success: bool, entries_warmed: usize) -> Self {
        Self {
            success,
            entries_warmed,
        }
    }
}

/// Response to an update query.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseUpdate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseUpdate {
    /// Whether the update was successful.
    pub success: bool,
    /// Number of records updated.
    pub records_updated: usize,
}

impl ResponseUpdate {
    /// Create an update response.
    pub fn new(success: bool, records_updated: usize) -> Self {
        Self {
            success,
            records_updated,
        }
    }
}

/// Response with vector IDs.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseVectorId`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseVectorId {
    /// The vector IDs.
    pub vector_ids: Vec<u64>,
}

impl ResponseVectorId {
    /// Create a new response.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a vector ID.
    pub fn add_id(&mut self, id: u64) {
        self.vector_ids.push(id);
    }
}

/// Response with vector matches.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseVectorMatch`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseVectorMatch {
    /// The matching similarity notes.
    pub matches: Vec<SimilarityNote>,
}

impl ResponseVectorMatch {
    /// Create a new response.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a match.
    pub fn add_match(&mut self, note: SimilarityNote) {
        self.matches.push(note);
    }

    /// Number of matches.
    pub fn match_count(&self) -> usize {
        self.matches.len()
    }
}

/// A match record from a child query.
///
/// Port of `ghidra.features.bsim.query.protocol.ChildMatchRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildMatchRecord {
    /// The parent function.
    pub parent: FunctionDescription,
    /// The child function.
    pub child: FunctionDescription,
    /// Similarity score.
    pub similarity: f64,
}

impl ChildMatchRecord {
    /// Create a new child match record.
    pub fn new(parent: FunctionDescription, child: FunctionDescription, similarity: f64) -> Self {
        Self {
            parent,
            child,
            similarity,
        }
    }
}

// ExecutableRecord is re-exported from description.rs

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

    // ---- New protocol type tests ----

    #[test]
    fn test_bsim_query_type_enum() {
        assert_ne!(BSimQueryType::Name, BSimQueryType::ExeInfo);
        assert_eq!(BSimQueryType::Nearest, BSimQueryType::Nearest);
    }

    #[test]
    fn test_bsim_response_type_enum() {
        assert_ne!(BSimResponseType::Name, BSimResponseType::Error);
    }

    #[test]
    fn test_bsim_query_base() {
        let base = BSimQueryBase::new("querynearest", BSimQueryType::Nearest);
        assert_eq!(base.name, "querynearest");
        assert_eq!(base.query_type, BSimQueryType::Nearest);
    }

    #[test]
    fn test_adjust_vector_index() {
        let mut adj = AdjustVectorIndex::new();
        adj.add_adjustment(1, 10);
        adj.add_adjustment(2, -5);
        assert_eq!(adj.vector_ids.len(), 2);
        assert_eq!(adj.offsets, vec![10, -5]);
    }

    #[test]
    fn test_executable_result_with_deduping() {
        let mut result = ExecutableResultWithDeDuping::new();
        let exe = ExecutableRecord::new("abc123", "test", "x86", "gcc");
        result.add_executable(exe.clone());
        result.add_executable(exe); // same md5, should be deduped
        assert_eq!(result.unique_count(), 1);
        assert_eq!(result.total_count, 2);
    }

    #[test]
    fn test_function_staging() {
        let mut staging = FunctionStaging::new(5);
        assert!(staging.is_empty());
        staging.stage_function(FunctionEntry::new("f1", 0x100, "h1"));
        staging.stage_function(FunctionEntry::new("f2", 0x200, "h2"));
        assert_eq!(staging.len(), 2);
        assert!(!staging.is_full());

        let spec = ExeSpecifier::new("test", "x86", "md5");
        staging.set_exe_spec(spec);
        assert!(staging.exe_spec.is_some());
    }

    #[test]
    fn test_function_staging_drain() {
        let mut staging = FunctionStaging::new(5);
        staging.stage_function(FunctionEntry::new("f1", 0x100, "h1"));
        let entries = staging.drain();
        assert_eq!(entries.len(), 1);
        assert!(staging.is_empty());
    }

    #[test]
    fn test_null_staging() {
        let ns = NullStaging::new();
        assert_eq!(std::mem::size_of_val(&ns), 0);
    }

    #[test]
    fn test_pair_input() {
        let pair = PairInput::new("func_a", "func_b", "md5a", "md5b", 0x1000, 0x2000);
        assert_eq!(pair.name_a, "func_a");
        assert_eq!(pair.address_b, 0x2000);
    }

    #[test]
    fn test_pair_note() {
        let pair = PairInput::new("a", "b", "m1", "m2", 0x100, 0x200);
        let note = PairNote::new(pair, 0.85, 0.9);
        assert!(note.matched);
        assert_eq!(note.similarity, 0.85);

        let pair2 = PairInput::new("c", "d", "m3", "m4", 0x300, 0x400);
        let note2 = PairNote::new(pair2, 0.0, 0.0);
        assert!(!note2.matched);
    }

    #[test]
    fn test_password_change() {
        let pc = PasswordChange::new("old_pass", "new_pass");
        assert_eq!(pc.old_password, "old_pass");
        assert_eq!(pc.new_password, "new_pass");
    }

    #[test]
    fn test_pre_filter() {
        let mut pf = PreFilter::new();
        assert!(pf.passes(100, 50));

        pf.min_body_size = Some(50);
        assert!(!pf.passes(30, 50));
        assert!(pf.passes(100, 50));

        pf.max_body_size = Some(500);
        assert!(!pf.passes(1000, 50));

        pf.min_instructions = Some(10);
        assert!(!pf.passes(200, 5));
    }

    #[test]
    fn test_prewarm_request() {
        let req = PrewarmRequest::new();
        assert!(req.warm_vectors);
        assert!(req.warm_descriptions);
        assert_eq!(req.max_entries, 1000);
    }

    #[test]
    fn test_install_category_request() {
        let req = InstallCategoryRequest::new("crypto", "Cryptographic functions")
            .with_parent("security");
        assert_eq!(req.name, "crypto");
        assert_eq!(req.parent.as_deref(), Some("security"));
    }

    #[test]
    fn test_install_metadata_request() {
        let mut req = InstallMetadataRequest::new();
        req.set("version", "1.0");
        assert_eq!(req.get("version"), Some("1.0"));
        assert!(req.get("nonexistent").is_none());
    }

    #[test]
    fn test_install_tag_request() {
        let req = InstallTagRequest::new("library", "Standard library functions");
        assert_eq!(req.tag_name, "library");
    }

    #[test]
    fn test_query_name() {
        let q = QueryName::new("libc.so").with_md5("abc123").with_arch("x86");
        assert_eq!(q.name_exec, "libc.so");
        assert_eq!(q.md5.as_deref(), Some("abc123"));
        assert_eq!(q.arch.as_deref(), Some("x86"));
    }

    #[test]
    fn test_query_exe_info() {
        let q = QueryExeInfo::new().with_limit(100);
        assert_eq!(q.limit, 100);
        assert!(!q.include_fakes);
        assert!(q.fillin_categories);
    }

    #[test]
    fn test_query_exe_count() {
        let q = QueryExeCount::with_filters(
            None,
            Some("test".to_string()),
            Some("x86".to_string()),
            None,
            false,
        );
        assert_eq!(q.filter_exe_name.as_deref(), Some("test"));
        assert_eq!(q.filter_arch.as_deref(), Some("x86"));
    }

    #[test]
    fn test_query_nearest() {
        let mut q = QueryNearest::new();
        assert_eq!(q.thresh, QueryNearest::DEFAULT_SIMILARITY_THRESHOLD);
        q.add_function(FunctionDescription::new(0, "test", Some(0x1000)));
        assert_eq!(q.functions.len(), 1);
    }

    #[test]
    fn test_query_nearest_vector() {
        let mut q = QueryNearestVector::new(0.7, 20);
        q.add_feature(1, 0.5);
        q.add_feature(2, 0.3);
        assert_eq!(q.query_vector.len(), 2);
    }

    #[test]
    fn test_query_pair() {
        let mut q = QueryPair::new();
        assert!(q.is_empty());
        q.add_pair(PairInput::new("a", "b", "m1", "m2", 0x100, 0x200));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_query_children() {
        let mut q = QueryChildren::new();
        q.md5sum = Some("abc".to_string());
        q.add_function_key(FunctionEntry::new("f1", 0x100, "h1"));
        assert_eq!(q.function_keys.len(), 1);
    }

    #[test]
    fn test_query_cluster() {
        let mut q = QueryCluster::new();
        assert_eq!(q.thresh, 0.9);
        q.add_function(FunctionDescription::new(0, "f1", Some(0x100)));

        let copy = q.local_staging_copy();
        assert!((copy.thresh - 0.9).abs() < 1e-10);
        assert!(copy.functions.is_empty());
    }

    #[test]
    fn test_query_delete() {
        let mut q = QueryDelete::new("abc123");
        q.add_function("func_a");
        q.add_function("func_b");
        assert_eq!(q.md5, "abc123");
        assert_eq!(q.function_names.len(), 2);
    }

    #[test]
    fn test_query_info() {
        let q = QueryInfo::new(true);
        assert!(q.include_stats);
    }

    #[test]
    fn test_query_update() {
        let mut q = QueryUpdate::new("abc");
        q.set_field("compiler", "gcc");
        assert_eq!(q.fields.get("compiler").map(|s| s.as_str()), Some("gcc"));
    }

    #[test]
    fn test_query_optional_exist() {
        let mut q = QueryOptionalExist::new("md5");
        q.add_key("key1");
        q.add_key("key2");
        assert_eq!(q.keys.len(), 2);
    }

    #[test]
    fn test_query_optional_values() {
        let mut q = QueryOptionalValues::new("md5");
        q.add_key("version");
        assert_eq!(q.keys.len(), 1);
    }

    #[test]
    fn test_query_vector_id() {
        let mut q = QueryVectorId::new("md5");
        q.add_function("func1");
        assert_eq!(q.function_names.len(), 1);
    }

    #[test]
    fn test_query_vector_match() {
        let mut q = QueryVectorMatch::new(0.7, 20);
        q.add_vector(vec![(1, 0.5), (2, 0.3)]);
        assert_eq!(q.query_vectors.len(), 1);
    }

    #[test]
    fn test_query_response_record() {
        let func = FunctionDescription::new(0, "test", Some(0x1000));
        let record = QueryResponseRecord::new(func).with_scores(0.9, 0.95);
        assert_eq!(record.similarity, Some(0.9));
        assert_eq!(record.significance, Some(0.95));
    }

    #[test]
    fn test_response_name() {
        let mut r = ResponseName::new();
        let exe = ExecutableRecord::new("abc", "test", "x86", "gcc");
        r.add_executable(exe);
        assert_eq!(r.total, 1);
    }

    #[test]
    fn test_response_exe() {
        let mut r = ResponseExe::new();
        let exe = ExecutableRecord::new("abc", "test", "x86", "gcc");
        r.add_executable(exe);
        assert_eq!(r.total, 1);
    }

    #[test]
    fn test_response_nearest() {
        let mut r = ResponseNearest::new();
        assert!(r.results.is_empty());
    }

    #[test]
    fn test_response_nearest_vector() {
        let mut r = ResponseNearestVector::new();
        r.add_result(SimilarityVectorResult { function: FunctionDescription::new(0, "test", Some(0x1000)), vector: vec![], similarity: 0.9 });
        assert_eq!(r.results.len(), 1);
    }

    #[test]
    fn test_response_pair() {
        let mut r = ResponsePair::new();
        let pair = PairInput::new("a", "b", "m1", "m2", 0x100, 0x200);
        r.add_note(PairNote::new(pair, 0.8, 0.85));
        assert_eq!(r.notes.len(), 1);
    }

    #[test]
    fn test_response_children() {
        let mut r = ResponseChildren::new();
        r.add_child(FunctionDescription::new(0, "child1", Some(0x200)));
        assert_eq!(r.total, 1);
    }

    #[test]
    fn test_response_cluster() {
        let mut r = ResponseCluster::new();
        r.add_cluster(ClusterNote::new(1));
        assert_eq!(r.total, 1);
    }

    #[test]
    fn test_response_info() {
        let r = ResponseInfo::new();
        assert!(r.info.is_none());
    }

    #[test]
    fn test_response_delete() {
        let r = ResponseDelete::new(true, 5);
        assert!(r.success);
        assert_eq!(r.deleted_count, 5);
    }

    #[test]
    fn test_response_drop_database() {
        let ok = ResponseDropDatabase::success();
        assert!(ok.success);

        let fail = ResponseDropDatabase::failure("permission denied");
        assert!(!fail.success);
        assert!(fail.error_message.is_some());
    }

    #[test]
    fn test_response_error() {
        let err = ResponseError::new(404, "not found").as_recoverable();
        assert_eq!(err.error_code, 404);
        assert!(err.recoverable);
    }

    #[test]
    fn test_response_insert() {
        let mut r = ResponseInsert::success(10);
        assert!(r.success);
        assert_eq!(r.inserted_count, 10);
        r.add_warning("skipped duplicate");
        assert_eq!(r.warnings.len(), 1);
    }

    #[test]
    fn test_response_adjust_index() {
        let r = ResponseAdjustIndex::new(true, 3);
        assert!(r.success);
        assert_eq!(r.adjusted_count, 3);
    }

    #[test]
    fn test_response_optional_exist() {
        let mut r = ResponseOptionalExist::new();
        r.set_exists("key1", true);
        r.set_exists("key2", false);
        assert_eq!(r.exists("key1"), Some(true));
        assert_eq!(r.exists("key2"), Some(false));
        assert_eq!(r.exists("key3"), None);
    }

    #[test]
    fn test_response_optional_values() {
        let mut r = ResponseOptionalValues::new();
        r.set_value("version", "2.0");
        assert_eq!(r.get_value("version"), Some("2.0"));
        assert!(r.get_value("missing").is_none());
    }

    #[test]
    fn test_response_password_protocol() {
        let ok = ResponsePassword::success();
        assert!(ok.success);
        let fail = ResponsePassword::failure("wrong");
        assert!(!fail.success);
    }

    #[test]
    fn test_response_prewarm_protocol() {
        let r = ResponsePrewarm::new(true, 100);
        assert!(r.success);
        assert_eq!(r.entries_warmed, 100);
    }

    #[test]
    fn test_response_update_protocol() {
        let r = ResponseUpdate::new(true, 42);
        assert!(r.success);
        assert_eq!(r.records_updated, 42);
    }

    #[test]
    fn test_response_vector_id_protocol() {
        let mut r = ResponseVectorId::new();
        r.add_id(10);
        r.add_id(20);
        assert_eq!(r.vector_ids, vec![10, 20]);
    }

    #[test]
    fn test_response_vector_match_protocol() {
        let mut r = ResponseVectorMatch::new();
        let note = SimilarityNote {
            hash_a: "a".into(),
            hash_b: "b".into(),
            similarity: 0.9,
            significance: 0.95,
        };
        r.add_match(note);
        assert_eq!(r.match_count(), 1);
    }

    #[test]
    fn test_child_match_record() {
        let parent = FunctionDescription::new(0, "parent", Some(0x1000));
        let child = FunctionDescription::new(1, "child", Some(0x2000));
        let record = ChildMatchRecord::new(parent, child, 0.95);
        assert_eq!(record.parent.function_name, "parent");
        assert_eq!(record.child.function_name, "child");
        assert_eq!(record.similarity, 0.95);
    }

    #[test]
    fn test_exe_table_order_column_default() {
        assert_eq!(ExeTableOrderColumn::default(), ExeTableOrderColumn::Md5);
    }

    #[test]
    fn test_protocol_serialization_roundtrip() {
        let q = QueryNearest::new();
        let json = serde_json::to_string(&q).unwrap();
        let _: QueryNearest = serde_json::from_str(&json).unwrap();
    }
}
