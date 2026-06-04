//! BSim protocol types -- Rust port of Ghidra's `ghidra.features.bsim.query.protocol` package.
//!
//! This module provides all the query/response protocol types used by the BSim
//! client-server communication. Each type represents a specific database
//! operation (query, insert, delete, etc.) that can be serialized to/from XML.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::description::{
    CategoryRecord, DatabaseInformation, DescriptionManager, ExecutableRecord,
    FunctionDescription, RowKey, SignatureRecord, VectorResult,
};
use super::FeatureVector;

// ============================================================================
// QueryResponseRecord -- base for all query responses
// ============================================================================

/// Base trait for all BSim query response records.
///
/// Every response type implements this trait to provide a uniform
/// interface for processing query results.
pub trait QueryResponseRecord {
    /// Human-readable name of the response type.
    fn response_name(&self) -> &str;
}

// ============================================================================
// FilterAtom / BSimFilter
// ============================================================================

/// An operator type for a BSim filter atom.
///
/// Each operator specifies which field of the ExecutableRecord or
/// FunctionDescription to match against.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FilterOperator {
    /// Match by executable name (positive).
    ExecutableName,
    /// Match by executable name (negative / exclude).
    NotExecutableName,
    /// Match by architecture string.
    Architecture,
    /// Match by NOT architecture string.
    NotArchitecture,
    /// Match by compiler name.
    Compiler,
    /// Match by NOT compiler name.
    NotCompiler,
    /// Match by MD5 hash.
    Md5,
    /// Match by NOT MD5 hash.
    NotMd5,
    /// Match by executable category.
    ExecutableCategory,
    /// Match by NOT executable category.
    NotExecutableCategory,
    /// Match by function tag.
    FunctionTag,
    /// Match by date earlier than.
    DateEarlier,
    /// Match by date later than.
    DateLater,
    /// Match by path prefix.
    PathStarts,
    /// Custom filter operator with string identifier.
    Custom(String),
}

impl FilterOperator {
    /// Parse a filter operator from its string name.
    pub fn from_name(name: &str) -> Self {
        match name {
            "exename" => Self::ExecutableName,
            "notexename" => Self::NotExecutableName,
            "architecture" => Self::Architecture,
            "notarchitecture" => Self::NotArchitecture,
            "compiler" => Self::Compiler,
            "notcompiler" => Self::NotCompiler,
            "md5" => Self::Md5,
            "notmd5" => Self::NotMd5,
            "execat" => Self::ExecutableCategory,
            "notexecat" => Self::NotExecutableCategory,
            "functag" => Self::FunctionTag,
            "dateearlier" => Self::DateEarlier,
            "datelater" => Self::DateLater,
            "pathstarts" => Self::PathStarts,
            _ => Self::Custom(name.to_string()),
        }
    }

    /// Whether this filter type supports OR-multiple semantics (vs AND).
    pub fn or_multiple_entries(&self) -> bool {
        matches!(
            self,
            Self::NotExecutableName
                | Self::NotArchitecture
                | Self::NotCompiler
                | Self::NotMd5
                | Self::NotExecutableCategory
        )
    }
}

/// A single filter atom: an operator paired with a value string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterAtom {
    /// The filter operator.
    pub operator: FilterOperator,
    /// The value string to match against.
    pub value: String,
}

impl FilterAtom {
    /// Create a new filter atom.
    pub fn new(operator: FilterOperator, value: impl Into<String>) -> Self {
        Self {
            operator,
            value: value.into(),
        }
    }
}

/// A collection of filter atoms that can be applied to filter BSim results.
///
/// Mirrors Ghidra's BSimFilter. Supports AND/OR semantics depending on the
/// filter operator type.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BSimFilter {
    /// The raw filter atoms.
    pub atoms: Vec<FilterAtom>,
    /// AND-grouped filters (positive match: all must pass).
    and_map: HashMap<String, Vec<FilterAtom>>,
    /// OR-grouped filters (negative match: at least one must pass).
    or_map: HashMap<String, Vec<FilterAtom>>,
}

impl BSimFilter {
    /// Create a new empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a filter atom.
    pub fn add_atom(&mut self, atom: FilterAtom) {
        let name = match &atom.operator {
            FilterOperator::Custom(s) => s.clone(),
            other => format!("{:?}", other),
        };
        if atom.operator.or_multiple_entries() {
            self.or_map.entry(name).or_default().push(atom.clone());
        } else {
            self.and_map.entry(name).or_default().push(atom.clone());
        }
        self.atoms.push(atom);
    }

    /// Test whether an ExecutableRecord passes this filter.
    ///
    /// Returns `true` if the record should be kept, `false` if filtered out.
    pub fn is_filtered(&self, exe: &ExecutableRecord) -> bool {
        // Check positive (AND) filters.
        for atoms in self.and_map.values() {
            if !Self::evaluate_and(atoms, exe) {
                return false;
            }
        }
        // Check negative (OR) filters.
        for atoms in self.or_map.values() {
            if !Self::evaluate_or(atoms, exe) {
                return false;
            }
        }
        true
    }

    /// Evaluate an AND group: ALL atoms must match.
    fn evaluate_and(atoms: &[FilterAtom], exe: &ExecutableRecord) -> bool {
        for atom in atoms {
            if !Self::match_atom(atom, exe) {
                return false;
            }
        }
        true
    }

    /// Evaluate an OR group: at least ONE atom must match.
    fn evaluate_or(atoms: &[FilterAtom], exe: &ExecutableRecord) -> bool {
        for atom in atoms {
            if Self::match_atom(atom, exe) {
                return true;
            }
        }
        false
    }

    /// Match a single atom against an executable record.
    fn match_atom(atom: &FilterAtom, exe: &ExecutableRecord) -> bool {
        match &atom.operator {
            FilterOperator::ExecutableName => exe.executable_name == atom.value,
            FilterOperator::NotExecutableName => exe.executable_name != atom.value,
            FilterOperator::Architecture => exe.architecture == atom.value,
            FilterOperator::NotArchitecture => exe.architecture != atom.value,
            FilterOperator::Compiler => exe.compiler_name == atom.value,
            FilterOperator::NotCompiler => exe.compiler_name != atom.value,
            FilterOperator::Md5 => exe.md5 == atom.value,
            FilterOperator::NotMd5 => exe.md5 != atom.value,
            FilterOperator::ExecutableCategory => exe
                .categories
                .iter()
                .any(|c| c.category == atom.value),
            FilterOperator::NotExecutableCategory => !exe
                .categories
                .iter()
                .any(|c| c.category == atom.value),
            _ => true, // Unknown filter types are not applied.
        }
    }

    /// Number of filter atoms.
    pub fn len(&self) -> usize {
        self.atoms.len()
    }

    /// Whether the filter is empty (no atoms).
    pub fn is_empty(&self) -> bool {
        self.atoms.is_empty()
    }
}

// ============================================================================
// ExeSpecifier
// ============================================================================

/// Identifies an executable within a BSim database query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExeSpecifier {
    /// The MD5 hash of the executable.
    pub md5: String,
    /// The executable name.
    pub executable_name: String,
    /// The architecture string.
    pub architecture: String,
}

impl ExeSpecifier {
    /// Create a new exe specifier.
    pub fn new(
        md5: impl Into<String>,
        executable_name: impl Into<String>,
        architecture: impl Into<String>,
    ) -> Self {
        Self {
            md5: md5.into(),
            executable_name: executable_name.into(),
            architecture: architecture.into(),
        }
    }

    /// Create from an ExecutableRecord.
    pub fn from_record(exe: &ExecutableRecord) -> Self {
        Self {
            md5: exe.md5.clone(),
            executable_name: exe.executable_name.clone(),
            architecture: exe.architecture.clone(),
        }
    }
}

// ============================================================================
// FunctionEntry
// ============================================================================

/// Identifying information for a function within a single executable.
///
/// Used in protocol messages to reference functions by name and address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionEntry {
    /// Name of the function within the executable.
    pub func_name: String,
    /// Address of the function.
    pub address: u64,
}

impl FunctionEntry {
    /// Create a new function entry.
    pub fn new(func_name: impl Into<String>, address: u64) -> Self {
        Self {
            func_name: func_name.into(),
            address,
        }
    }

    /// Create from a FunctionDescription.
    pub fn from_description(desc: &FunctionDescription) -> Self {
        Self {
            func_name: desc.function_name.clone(),
            address: desc.address.unwrap_or(0),
        }
    }
}

// ============================================================================
// SimilarityNote / SimilarityResult / SimilarityVectorResult
// ============================================================================

/// A single similarity match note: a matched function with its scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityNote {
    /// The matched function description.
    pub function: FunctionDescription,
    /// Cosine similarity score (0.0 - 1.0).
    pub similarity: f64,
    /// Significance score (higher = more significant).
    pub significance: f64,
}

impl SimilarityNote {
    /// Create a new similarity note.
    pub fn new(function: FunctionDescription, similarity: f64, significance: f64) -> Self {
        Self {
            function,
            similarity,
            significance,
        }
    }
}

/// A collection of matches to an (originally) queried function.
///
/// Contains the base function and all similar functions found in the database.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimilarityResult {
    /// The original function that was queried.
    pub base_func: Option<FunctionDescription>,
    /// Functions to which base is similar.
    pub notes: Vec<SimilarityNote>,
    /// Total number of functions in database meeting thresholds.
    pub total_count: u32,
}

impl SimilarityResult {
    /// Create a new empty similarity result for the given base function.
    pub fn new(base_func: FunctionDescription) -> Self {
        Self {
            base_func: Some(base_func),
            notes: Vec::new(),
            total_count: 0,
        }
    }

    /// Add a similarity note.
    pub fn add_note(
        &mut self,
        function: FunctionDescription,
        similarity: f64,
        significance: f64,
    ) {
        self.notes.push(SimilarityNote::new(function, similarity, significance));
    }

    /// Get the base function.
    pub fn get_base(&self) -> Option<&FunctionDescription> {
        self.base_func.as_ref()
    }

    /// Get the number of notes (matches).
    pub fn note_count(&self) -> usize {
        self.notes.len()
    }

    /// Iterate over the notes.
    pub fn notes(&self) -> &[SimilarityNote] {
        &self.notes
    }

    /// Set the total count.
    pub fn set_total_count(&mut self, count: u32) {
        self.total_count = count;
    }
}

/// A similarity result with an associated vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityVectorResult {
    /// The similarity result.
    pub result: SimilarityResult,
    /// The feature vector of the queried function.
    pub query_vector: Option<FeatureVector>,
}

impl SimilarityVectorResult {
    /// Create a new similarity vector result.
    pub fn new(result: SimilarityResult, query_vector: Option<FeatureVector>) -> Self {
        Self {
            result,
            query_vector,
        }
    }
}

// ============================================================================
// ClusterNote / PairNote / PairInput
// ============================================================================

/// A cluster of similar functions, identified by a vector-id.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterNote {
    /// The vector-id that defines the cluster center.
    pub vector_id: u64,
    /// Functions in the cluster.
    pub functions: Vec<FunctionDescription>,
    /// Similarity score to the cluster center.
    pub similarity: f64,
    /// Significance of the cluster match.
    pub significance: f64,
    /// Total hit count in the database.
    pub hit_count: u32,
}

impl ClusterNote {
    /// Create a new cluster note.
    pub fn new(vector_id: u64) -> Self {
        Self {
            vector_id,
            ..Default::default()
        }
    }
}

/// A note about a pair of similar functions from different executables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairNote {
    /// First function in the pair.
    pub func_a: FunctionDescription,
    /// Second function in the pair.
    pub func_b: FunctionDescription,
    /// Similarity score between the pair.
    pub similarity: f64,
    /// Significance of the pair match.
    pub significance: f64,
}

impl PairNote {
    /// Create a new pair note.
    pub fn new(
        func_a: FunctionDescription,
        func_b: FunctionDescription,
        similarity: f64,
        significance: f64,
    ) -> Self {
        Self {
            func_a,
            func_b,
            similarity,
            significance,
        }
    }
}

/// Input for a pair query: two function entries to compare.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairInput {
    /// First function.
    pub entry_a: FunctionEntry,
    /// MD5 of the first function's executable.
    pub md5_a: String,
    /// Second function.
    pub entry_b: FunctionEntry,
    /// MD5 of the second function's executable.
    pub md5_b: String,
}

// ============================================================================
// ChildAtom / ChildMatchRecord
// ============================================================================

/// A child atom in a BSim hierarchy (parent-child function relationship).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildAtom {
    /// Index of the parent function in the DescriptionManager.
    pub parent_index: usize,
    /// Index of the child function.
    pub child_index: usize,
    /// Location hash at the call site.
    pub location_hash: u32,
}

impl ChildAtom {
    /// Create a new child atom.
    pub fn new(parent_index: usize, child_index: usize, location_hash: u32) -> Self {
        Self {
            parent_index,
            child_index,
            location_hash,
        }
    }
}

/// A record of a child function match during query processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildMatchRecord {
    /// The child function.
    pub child: FunctionDescription,
    /// The parent function.
    pub parent: FunctionDescription,
    /// Location hash at the call site.
    pub location_hash: u32,
}

// ============================================================================
// Staging types
// ============================================================================

/// Function staging data for incremental insertions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionStaging {
    /// Functions staged for insertion.
    pub entries: Vec<FunctionEntry>,
    /// Staging batch identifier.
    pub batch_id: u32,
}

impl FunctionStaging {
    /// Create a new function staging.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function entry to the staging area.
    pub fn add_entry(&mut self, entry: FunctionEntry) {
        self.entries.push(entry);
    }
}

/// Null staging (empty/no-op staging).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NullStaging;

/// Manages staging of function entries for batch insertions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StagingManager {
    /// Current staging entries.
    pub stages: Vec<FunctionStaging>,
    /// Current stage index.
    pub current_stage: usize,
}

impl StagingManager {
    /// Create a new staging manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new stage.
    pub fn add_stage(&mut self, stage: FunctionStaging) {
        self.stages.push(stage);
    }

    /// Get the current stage.
    pub fn current(&self) -> Option<&FunctionStaging> {
        self.stages.get(self.current_stage)
    }

    /// Advance to the next stage. Returns false if no more stages.
    pub fn advance(&mut self) -> bool {
        if self.current_stage + 1 < self.stages.len() {
            self.current_stage += 1;
            true
        } else {
            false
        }
    }

    /// Total number of stages.
    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }
}

// ============================================================================
// BSimQuery -- abstract base for all queries
// ============================================================================

/// Enum of all possible BSim query types.
///
/// This replaces the Java abstract class hierarchy with a single enum.
#[derive(Debug, Clone)]
pub enum BSimQueryType {
    /// Query for nearest neighbors by function signature.
    QueryNearest(QueryNearest),
    /// Query for nearest neighbors by raw vector.
    QueryNearestVector(QueryNearestVector),
    /// Insert signatures into the database.
    InsertRequest(InsertRequest),
    /// Query by function name.
    QueryName(QueryName),
    /// Delete entries from the database.
    QueryDelete(QueryDelete),
    /// Query for function pairs.
    QueryPair(QueryPair),
    /// Query for children (callgraph).
    QueryChildren(QueryChildren),
    /// Query for cluster information.
    QueryCluster(QueryCluster),
    /// Query for executable info.
    QueryExeInfo(QueryExeInfo),
    /// Query for executable count.
    QueryExeCount(QueryExeCount),
    /// Query for database info.
    QueryInfo(QueryInfo),
    /// Update database entries.
    QueryUpdate(QueryUpdate),
    /// Query for vector by ID.
    QueryVectorId(QueryVectorId),
    /// Query for vector match.
    QueryVectorMatch(QueryVectorMatch),
    /// Query for optional values.
    QueryOptionalValues(QueryOptionalValues),
    /// Query for optional existence.
    QueryOptionalExist(QueryOptionalExist),
    /// Create a new database.
    CreateDatabase(CreateDatabase),
    /// Drop a database.
    DropDatabase(DropDatabase),
    /// Install category request.
    InstallCategoryRequest(InstallCategoryRequest),
    /// Install metadata request.
    InstallMetadataRequest(InstallMetadataRequest),
    /// Install tag request.
    InstallTagRequest(InstallTagRequest),
    /// Insert optional values.
    InsertOptionalValues(InsertOptionalValues),
    /// Adjust vector index.
    AdjustVectorIndex(AdjustVectorIndex),
    /// Password change.
    PasswordChange(PasswordChange),
    /// Prewarm request.
    PrewarmRequest(PrewarmRequest),
}

/// The common fields shared by all BSim queries.
#[derive(Debug, Clone)]
pub struct BSimQueryBase {
    /// Name of the query type.
    pub name: String,
    /// Similarity threshold (0.0 - 1.0).
    pub similarity_threshold: f64,
    /// Significance threshold.
    pub significance_threshold: f64,
    /// Maximum number of results.
    pub max_results: u32,
    /// The description manager with function data.
    pub manager: Option<DescriptionManager>,
    /// Filter to apply.
    pub filter: Option<BSimFilter>,
}

impl Default for BSimQueryBase {
    fn default() -> Self {
        Self {
            name: String::new(),
            similarity_threshold: 0.7,
            significance_threshold: 4.0,
            max_results: 100,
            manager: None,
            filter: None,
        }
    }
}

// ============================================================================
// Query types
// ============================================================================

/// Query for nearest neighbors to a set of functions.
#[derive(Debug, Clone)]
pub struct QueryNearest {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// The functions to query.
    pub query_functions: Vec<FunctionEntry>,
    /// MD5 of the executable being queried.
    pub query_md5: String,
    /// Number of staging stages.
    pub num_stages: u32,
}

impl QueryNearest {
    /// Create a new nearest query.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "querynearest".to_string(),
                ..Default::default()
            },
            query_functions: Vec::new(),
            query_md5: String::new(),
            num_stages: 0,
        }
    }

    /// Add a function to query.
    pub fn add_function(&mut self, entry: FunctionEntry) {
        self.query_functions.push(entry);
    }
}

impl Default for QueryNearest {
    fn default() -> Self {
        Self::new()
    }
}

/// Query for nearest neighbors by raw feature vector.
#[derive(Debug, Clone)]
pub struct QueryNearestVector {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// The query vectors.
    pub vectors: Vec<FeatureVector>,
}

impl QueryNearestVector {
    /// Create a new nearest-vector query.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "querynearestvector".to_string(),
                ..Default::default()
            },
            vectors: Vec::new(),
        }
    }
}

impl Default for QueryNearestVector {
    fn default() -> Self {
        Self::new()
    }
}

/// Insert request: insert function signatures into the database.
#[derive(Debug, Clone)]
pub struct InsertRequest {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// The executable to insert functions from.
    pub exe_record: Option<ExecutableRecord>,
    /// Functions with their signatures.
    pub functions: Vec<FunctionDescription>,
}

impl InsertRequest {
    /// Create a new insert request.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "insert".to_string(),
                ..Default::default()
            },
            exe_record: None,
            functions: Vec::new(),
        }
    }
}

impl Default for InsertRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Query by function name.
#[derive(Debug, Clone)]
pub struct QueryName {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// The function name to search for.
    pub function_name: String,
}

impl QueryName {
    /// Create a new name query.
    pub fn new(function_name: impl Into<String>) -> Self {
        Self {
            base: BSimQueryBase {
                name: "queryname".to_string(),
                ..Default::default()
            },
            function_name: function_name.into(),
        }
    }
}

/// Delete query: remove entries from the database.
#[derive(Debug, Clone)]
pub struct QueryDelete {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// Functions to delete.
    pub functions: Vec<FunctionEntry>,
    /// MD5 of the executable to delete from.
    pub md5: String,
}

impl QueryDelete {
    /// Create a new delete query.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "querydelete".to_string(),
                ..Default::default()
            },
            functions: Vec::new(),
            md5: String::new(),
        }
    }
}

impl Default for QueryDelete {
    fn default() -> Self {
        Self::new()
    }
}

/// Query for function pairs between executables.
#[derive(Debug, Clone)]
pub struct QueryPair {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// First executable specifier.
    pub exe_a: Option<ExeSpecifier>,
    /// Second executable specifier.
    pub exe_b: Option<ExeSpecifier>,
}

impl QueryPair {
    /// Create a new pair query.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "querypair".to_string(),
                ..Default::default()
            },
            exe_a: None,
            exe_b: None,
        }
    }
}

impl Default for QueryPair {
    fn default() -> Self {
        Self::new()
    }
}

/// Query for children (callgraph edges) of functions.
#[derive(Debug, Clone)]
pub struct QueryChildren {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// Functions whose children to retrieve.
    pub parents: Vec<FunctionEntry>,
    /// MD5 of the executable.
    pub md5: String,
}

impl QueryChildren {
    /// Create a new children query.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "querychildren".to_string(),
                ..Default::default()
            },
            parents: Vec::new(),
            md5: String::new(),
        }
    }
}

impl Default for QueryChildren {
    fn default() -> Self {
        Self::new()
    }
}

/// Query for cluster information.
#[derive(Debug, Clone)]
pub struct QueryCluster {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// Vector ID of the cluster center.
    pub vector_id: u64,
}

impl QueryCluster {
    /// Create a new cluster query.
    pub fn new(vector_id: u64) -> Self {
        Self {
            base: BSimQueryBase {
                name: "querycluster".to_string(),
                ..Default::default()
            },
            vector_id,
        }
    }
}

/// Query for executable information.
#[derive(Debug, Clone)]
pub struct QueryExeInfo {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// The executable specifier.
    pub exe: Option<ExeSpecifier>,
}

impl QueryExeInfo {
    /// Create a new exe info query.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "queryexeinfo".to_string(),
                ..Default::default()
            },
            exe: None,
        }
    }
}

impl Default for QueryExeInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Query for executable count.
#[derive(Debug, Clone)]
pub struct QueryExeCount {
    /// Base query fields.
    pub base: BSimQueryBase,
}

impl QueryExeCount {
    /// Create a new exe count query.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "queryexecount".to_string(),
                ..Default::default()
            },
        }
    }
}

impl Default for QueryExeCount {
    fn default() -> Self {
        Self::new()
    }
}

/// Query for database-level information.
#[derive(Debug, Clone)]
pub struct QueryInfo {
    /// Base query fields.
    pub base: BSimQueryBase,
}

impl QueryInfo {
    /// Create a new info query.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "queryinfo".to_string(),
                ..Default::default()
            },
        }
    }
}

impl Default for QueryInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Update database entries.
#[derive(Debug, Clone)]
pub struct QueryUpdate {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// The executable to update.
    pub exe_record: Option<ExecutableRecord>,
    /// Functions to update.
    pub functions: Vec<FunctionDescription>,
}

impl QueryUpdate {
    /// Create a new update query.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "queryupdate".to_string(),
                ..Default::default()
            },
            exe_record: None,
            functions: Vec::new(),
        }
    }
}

impl Default for QueryUpdate {
    fn default() -> Self {
        Self::new()
    }
}

/// Query for vector by ID.
#[derive(Debug, Clone)]
pub struct QueryVectorId {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// The vector ID to look up.
    pub vector_id: u64,
}

impl QueryVectorId {
    /// Create a new vector ID query.
    pub fn new(vector_id: u64) -> Self {
        Self {
            base: BSimQueryBase {
                name: "queryvectorid".to_string(),
                ..Default::default()
            },
            vector_id,
        }
    }
}

/// Query for vector match.
#[derive(Debug, Clone)]
pub struct QueryVectorMatch {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// The vector to match against.
    pub vector: Option<FeatureVector>,
}

impl QueryVectorMatch {
    /// Create a new vector match query.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "queryvectormatch".to_string(),
                ..Default::default()
            },
            vector: None,
        }
    }
}

impl Default for QueryVectorMatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Query for optional values.
#[derive(Debug, Clone)]
pub struct QueryOptionalValues {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// The key to look up.
    pub key: String,
}

impl QueryOptionalValues {
    /// Create a new optional values query.
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            base: BSimQueryBase {
                name: "queryoptionalvalues".to_string(),
                ..Default::default()
            },
            key: key.into(),
        }
    }
}

/// Query for optional existence.
#[derive(Debug, Clone)]
pub struct QueryOptionalExist {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// The key to check.
    pub key: String,
}

impl QueryOptionalExist {
    /// Create a new optional exist query.
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            base: BSimQueryBase {
                name: "queryoptionalexist".to_string(),
                ..Default::default()
            },
            key: key.into(),
        }
    }
}

/// Create a new database.
#[derive(Debug, Clone)]
pub struct CreateDatabase {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// Database info for the new database.
    pub info: Option<DatabaseInformation>,
}

impl CreateDatabase {
    /// Create a new create-database query.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "createdatabase".to_string(),
                ..Default::default()
            },
            info: None,
        }
    }
}

impl Default for CreateDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Drop (delete) a database.
#[derive(Debug, Clone)]
pub struct DropDatabase {
    /// Base query fields.
    pub base: BSimQueryBase,
}

impl DropDatabase {
    /// Create a new drop-database query.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "dropdatabase".to_string(),
                ..Default::default()
            },
        }
    }
}

impl Default for DropDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Install a category into the database.
#[derive(Debug, Clone)]
pub struct InstallCategoryRequest {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// Category to install.
    pub category: Option<CategoryRecord>,
}

impl InstallCategoryRequest {
    /// Create a new install category request.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "installcategory".to_string(),
                ..Default::default()
            },
            category: None,
        }
    }
}

impl Default for InstallCategoryRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Install metadata request.
#[derive(Debug, Clone)]
pub struct InstallMetadataRequest {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// The database info to install.
    pub info: Option<DatabaseInformation>,
}

impl InstallMetadataRequest {
    /// Create a new install metadata request.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "installmetadata".to_string(),
                ..Default::default()
            },
            info: None,
        }
    }
}

impl Default for InstallMetadataRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Install a function tag.
#[derive(Debug, Clone)]
pub struct InstallTagRequest {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// Tag name to install.
    pub tag_name: String,
}

impl InstallTagRequest {
    /// Create a new install tag request.
    pub fn new(tag_name: impl Into<String>) -> Self {
        Self {
            base: BSimQueryBase {
                name: "installtag".to_string(),
                ..Default::default()
            },
            tag_name: tag_name.into(),
        }
    }
}

/// Insert optional key-value pairs.
#[derive(Debug, Clone)]
pub struct InsertOptionalValues {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// Key-value pairs to insert.
    pub values: HashMap<String, String>,
}

impl InsertOptionalValues {
    /// Create a new insert optional values request.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "insertoptionalvalues".to_string(),
                ..Default::default()
            },
            values: HashMap::new(),
        }
    }
}

impl Default for InsertOptionalValues {
    fn default() -> Self {
        Self::new()
    }
}

/// Adjust vector index.
#[derive(Debug, Clone)]
pub struct AdjustVectorIndex {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// Old vector ID.
    pub old_id: u64,
    /// New vector ID.
    pub new_id: u64,
}

impl AdjustVectorIndex {
    /// Create a new adjust vector index request.
    pub fn new(old_id: u64, new_id: u64) -> Self {
        Self {
            base: BSimQueryBase {
                name: "adjustvectorindex".to_string(),
                ..Default::default()
            },
            old_id,
            new_id,
        }
    }
}

/// Password change request.
#[derive(Debug, Clone)]
pub struct PasswordChange {
    /// Base query fields.
    pub base: BSimQueryBase,
    /// The new password.
    pub password: String,
}

impl PasswordChange {
    /// Create a new password change request.
    pub fn new(password: impl Into<String>) -> Self {
        Self {
            base: BSimQueryBase {
                name: "passwordchange".to_string(),
                ..Default::default()
            },
            password: password.into(),
        }
    }
}

/// Prewarm request (warm up database caches).
#[derive(Debug, Clone)]
pub struct PrewarmRequest {
    /// Base query fields.
    pub base: BSimQueryBase,
}

impl PrewarmRequest {
    /// Create a new prewarm request.
    pub fn new() -> Self {
        Self {
            base: BSimQueryBase {
                name: "prewarmrequest".to_string(),
                ..Default::default()
            },
        }
    }
}

impl Default for PrewarmRequest {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Response types
// ============================================================================

/// Enum of all possible BSim response types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BSimResponseType {
    /// Response to a nearest query.
    ResponseNearest(ResponseNearest),
    /// Response to a nearest-vector query.
    ResponseNearestVector(ResponseNearestVector),
    /// Response to an insert request.
    ResponseInsert(ResponseInsert),
    /// Response to a name query.
    ResponseName(ResponseName),
    /// Response to a delete query.
    ResponseDelete(ResponseDelete),
    /// Response to a pair query.
    ResponsePair(ResponsePair),
    /// Response to a children query.
    ResponseChildren(ResponseChildren),
    /// Response to a cluster query.
    ResponseCluster(ResponseCluster),
    /// Response to an exe info query.
    ResponseExe(ResponseExe),
    /// Response to a database info query.
    ResponseInfo(ResponseInfo),
    /// Response to an update query.
    ResponseUpdate(ResponseUpdate),
    /// Response to a vector ID query.
    ResponseVectorId(ResponseVectorId),
    /// Response to a vector match query.
    ResponseVectorMatch(ResponseVectorMatch),
    /// Response to an optional values query.
    ResponseOptionalValues(ResponseOptionalValues),
    /// Response to an optional exist query.
    ResponseOptionalExist(ResponseOptionalExist),
    /// Response to a drop database request.
    ResponseDropDatabase(ResponseDropDatabase),
    /// Response to an adjust index request.
    ResponseAdjustIndex(ResponseAdjustIndex),
    /// Response to a password change request.
    ResponsePassword(ResponsePassword),
    /// Response to a prewarm request.
    ResponsePrewarm(ResponsePrewarm),
    /// An error response.
    ResponseError(ResponseError),
}

/// Base for all response records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryResponseRecordBase {
    /// Whether the query was successful.
    pub success: bool,
    /// Error message if the query failed.
    pub error_message: Option<String>,
}

/// Response to a nearest query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseNearest {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
    /// Similarity results for each queried function.
    pub results: Vec<SimilarityResult>,
    /// Staging information.
    pub staging: Option<StagingManager>,
}

impl ResponseNearest {
    /// Create a new empty nearest response.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Response to a nearest-vector query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseNearestVector {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
    /// Vector results.
    pub results: Vec<SimilarityVectorResult>,
}

/// Response to an insert request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseInsert {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
    /// The number of functions inserted.
    pub insert_count: u32,
}

/// Response to a name query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseName {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
    /// The matched functions.
    pub functions: Vec<FunctionDescription>,
}

/// Response to a delete query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseDelete {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
    /// The number of functions deleted.
    pub delete_count: u32,
}

/// Response to a pair query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponsePair {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
    /// The pair results.
    pub pairs: Vec<PairNote>,
}

/// Response to a children query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseChildren {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
    /// The child atoms (callgraph edges).
    pub children: Vec<ChildAtom>,
}

/// Response to a cluster query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseCluster {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
    /// Cluster information.
    pub clusters: Vec<ClusterNote>,
}

/// Response to an exe info query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseExe {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
    /// The executable records.
    pub executables: Vec<ExecutableRecord>,
    /// Total count.
    pub total_count: u32,
}

/// Response to a database info query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseInfo {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
    /// The database information.
    pub info: Option<DatabaseInformation>,
}

/// Response to an update query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseUpdate {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
    /// The number of entries updated.
    pub update_count: u32,
}

/// Response to a vector ID query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseVectorId {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
    /// The vector result.
    pub vector: Option<VectorResult>,
}

/// Response to a vector match query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseVectorMatch {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
    /// Matching vector results.
    pub vectors: Vec<VectorResult>,
}

/// Response to an optional values query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseOptionalValues {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
    /// The values.
    pub values: HashMap<String, String>,
}

/// Response to an optional exist query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseOptionalExist {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
    /// Whether the key exists.
    pub exists: bool,
}

/// Response to a drop database request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseDropDatabase {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
}

/// Response to an adjust index request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseAdjustIndex {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
}

/// Response to a password change request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponsePassword {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
}

/// Response to a prewarm request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponsePrewarm {
    /// Base response fields.
    pub base: QueryResponseRecordBase,
}

/// An error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseError {
    /// The error message.
    pub error_message: String,
    /// Error code (if available).
    pub error_code: i32,
}

impl ResponseError {
    /// Create a new error response.
    pub fn new(error_message: impl Into<String>, error_code: i32) -> Self {
        Self {
            error_message: error_message.into(),
            error_code,
        }
    }
}

// ============================================================================
// ExecutableResultWithDeDuping
// ============================================================================

/// Result of comparing executables with de-duplication of shared function matches.
///
/// Tracks the score between a pair of executables, ensuring that functions
/// with multiple similar matches are not over-counted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutableResultWithDeDuping {
    /// The executable record.
    pub exe_record: Option<ExecutableRecord>,
    /// Accumulated score.
    pub score: f64,
    /// Number of matching functions.
    pub match_count: u32,
    /// Per-vector results.
    pub vector_results: Vec<VectorResult>,
}

impl ExecutableResultWithDeDuping {
    /// Create a new de-duping result.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add score contribution from a function pair match.
    pub fn add_score(&mut self, significance: f64) {
        self.score += significance;
        self.match_count += 1;
    }
}

// ============================================================================
// PreFilter
// ============================================================================

/// A pre-filter applied to executable records before similarity search.
///
/// Used to narrow down which executables are considered during a query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PreFilter {
    /// Include only these executables (by MD5).
    pub include_md5s: Vec<String>,
    /// Exclude these executables (by MD5).
    pub exclude_md5s: Vec<String>,
    /// Include only executables matching these categories.
    pub include_categories: Vec<CategoryRecord>,
    /// Minimum function count required.
    pub min_function_count: u32,
}

impl PreFilter {
    /// Create a new empty pre-filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Test whether an executable record passes the pre-filter.
    pub fn is_included(&self, exe: &ExecutableRecord) -> bool {
        // Check exclusions.
        if self.exclude_md5s.contains(&exe.md5) {
            return false;
        }
        // Check inclusions (if any specified, must match at least one).
        if !self.include_md5s.is_empty() && !self.include_md5s.contains(&exe.md5) {
            return false;
        }
        true
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bsim::description::ExecutableRecord;

    #[test]
    fn filter_atom_creation() {
        let atom = FilterAtom::new(FilterOperator::ExecutableName, "test.exe");
        assert_eq!(atom.value, "test.exe");
        assert_eq!(atom.operator, FilterOperator::ExecutableName);
    }

    #[test]
    fn filter_operator_or_multiple() {
        assert!(!FilterOperator::ExecutableName.or_multiple_entries());
        assert!(FilterOperator::NotExecutableName.or_multiple_entries());
        assert!(FilterOperator::NotMd5.or_multiple_entries());
    }

    #[test]
    fn bsim_filter_empty_passes_all() {
        let filter = BSimFilter::new();
        let exe = ExecutableRecord::new("abc", "test.exe", "x86", "gcc");
        assert!(filter.is_filtered(&exe));
    }

    #[test]
    fn bsim_filter_name_positive() {
        let mut filter = BSimFilter::new();
        filter.add_atom(FilterAtom::new(FilterOperator::ExecutableName, "target.exe"));

        let match_exe = ExecutableRecord::new("abc", "target.exe", "x86", "gcc");
        let miss_exe = ExecutableRecord::new("def", "other.exe", "x86", "gcc");

        assert!(filter.is_filtered(&match_exe));
        assert!(!filter.is_filtered(&miss_exe));
    }

    #[test]
    fn bsim_filter_negative_or_semantics() {
        let mut filter = BSimFilter::new();
        filter.add_atom(FilterAtom::new(FilterOperator::NotExecutableName, "bad1.exe"));
        filter.add_atom(FilterAtom::new(FilterOperator::NotExecutableName, "bad2.exe"));

        let good_exe = ExecutableRecord::new("abc", "good.exe", "x86", "gcc");
        let bad_exe = ExecutableRecord::new("def", "bad1.exe", "x86", "gcc");

        // OR semantics: at least one must match (i.e., name must differ from at least one).
        assert!(filter.is_filtered(&good_exe));
        assert!(filter.is_filtered(&bad_exe)); // "bad1.exe" != "bad2.exe" -> passes OR
    }

    #[test]
    fn function_entry_from_description() {
        let func = FunctionDescription::new(0, "main", Some(0x1000));
        let entry = FunctionEntry::from_description(&func);
        assert_eq!(entry.func_name, "main");
        assert_eq!(entry.address, 0x1000);
    }

    #[test]
    fn similarity_result_notes() {
        let base = FunctionDescription::new(0, "query_fn", Some(0x1000));
        let mut result = SimilarityResult::new(base);
        assert_eq!(result.note_count(), 0);

        let match_fn = FunctionDescription::new(0, "match_fn", Some(0x2000));
        result.add_note(match_fn, 0.95, 5.0);
        assert_eq!(result.note_count(), 1);
        assert!((result.notes()[0].similarity - 0.95).abs() < 1e-9);
    }

    #[test]
    fn staging_manager_advance() {
        let mut mgr = StagingManager::new();
        assert_eq!(mgr.stage_count(), 0);
        assert!(mgr.current().is_none());

        let stage1 = FunctionStaging::new();
        let stage2 = FunctionStaging::new();
        mgr.add_stage(stage1);
        mgr.add_stage(stage2);

        assert_eq!(mgr.stage_count(), 2);
        assert!(mgr.current().is_some());
        assert!(mgr.advance());
        assert!(!mgr.advance()); // No more stages.
    }

    #[test]
    fn pre_filter_include_exclude() {
        let mut pf = PreFilter::new();
        pf.exclude_md5s.push("bad_md5".to_string());

        let good = ExecutableRecord::new("good_md5", "good", "x86", "gcc");
        let bad = ExecutableRecord::new("bad_md5", "bad", "x86", "gcc");

        assert!(pf.is_included(&good));
        assert!(!pf.is_included(&bad));
    }

    #[test]
    fn exe_specifier_from_record() {
        let exe = ExecutableRecord::new("abc123", "prog", "x86:LE:64", "gcc");
        let spec = ExeSpecifier::from_record(&exe);
        assert_eq!(spec.md5, "abc123");
        assert_eq!(spec.executable_name, "prog");
        assert_eq!(spec.architecture, "x86:LE:64");
    }

    #[test]
    fn executable_result_deduping() {
        let mut result = ExecutableResultWithDeDuping::new();
        result.add_score(5.0);
        result.add_score(3.0);
        assert_eq!(result.match_count, 2);
        assert!((result.score - 8.0).abs() < 1e-9);
    }

    #[test]
    fn query_nearest_add_function() {
        let mut q = QueryNearest::new();
        assert_eq!(q.query_functions.len(), 0);
        q.add_function(FunctionEntry::new("main", 0x1000));
        assert_eq!(q.query_functions.len(), 1);
    }

    #[test]
    fn cluster_note_creation() {
        let cn = ClusterNote::new(42);
        assert_eq!(cn.vector_id, 42);
        assert_eq!(cn.hit_count, 0);
    }

    #[test]
    fn pre_filter_include_md5s() {
        let mut pf = PreFilter::new();
        pf.include_md5s.push("aaa".to_string());
        pf.include_md5s.push("bbb".to_string());

        let a = ExecutableRecord::new("aaa", "a", "x86", "gcc");
        let b = ExecutableRecord::new("bbb", "b", "x86", "gcc");
        let c = ExecutableRecord::new("ccc", "c", "x86", "gcc");

        assert!(pf.is_included(&a));
        assert!(pf.is_included(&b));
        assert!(!pf.is_included(&c));
    }

    #[test]
    fn bsim_filter_multiple_and_atoms() {
        let mut filter = BSimFilter::new();
        filter.add_atom(FilterAtom::new(FilterOperator::ExecutableName, "target.exe"));
        filter.add_atom(FilterAtom::new(FilterOperator::Architecture, "x86:LE:64"));

        let matching = ExecutableRecord::new("abc", "target.exe", "x86:LE:64", "gcc");
        let wrong_arch = ExecutableRecord::new("def", "target.exe", "arm:LE:32", "gcc");
        let wrong_name = ExecutableRecord::new("ghi", "other.exe", "x86:LE:64", "gcc");

        assert!(filter.is_filtered(&matching));
        assert!(!filter.is_filtered(&wrong_arch));
        assert!(!filter.is_filtered(&wrong_name));
    }
}
