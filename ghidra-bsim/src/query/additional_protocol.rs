//! Port of additional BSim protocol messages.
//!
//! Ports the remaining protocol message types from
//! `ghidra.features.bsim.query.protocol` that are not yet in `protocol.rs`.
//!
//! These include: `InstallCategoryRequest`, `InstallMetadataRequest`,
//! `InstallTagRequest`, `PrewarmRequest`, `QueryExeCount`, `QueryExeInfo`,
//! `QueryNearestVector`, `QueryOptionalExist`, `QueryOptionalValues`,
//! `QueryUpdate`, `QueryVectorId`, `QueryVectorMatch`,
//! `ResponseAdjustIndex`, `ResponseChildren`, `ResponseCluster`,
//! `ResponseDelete`, `ResponseDropDatabase`, `ResponseError`, `ResponseExe`,
//! `ResponseInfo`, `ResponseInsert`, `ResponseName`, `ResponseNearestVector`,
//! `ResponseOptionalExist`, `ResponseOptionalValues`, `ResponsePair`,
//! `ResponsePassword`, `ResponseUpdate`, `ResponseVectorId`,
//! `ResponseVectorMatch`.

use serde::{Deserialize, Serialize};

use super::protocol::{ExeSpecifier, FilterAtom, FilterType};

/// Request to install a category into a BSim database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallCategoryRequest {
    /// Database name.
    pub database: String,
    /// Category name.
    pub category: String,
    /// Category description.
    pub description: String,
}

/// Request to install metadata for an executable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallMetadataRequest {
    /// The executable specifier.
    pub exe: ExeSpecifier,
    /// Key-value metadata pairs.
    pub metadata: Vec<(String, String)>,
}

/// Request to install tags for a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallTagRequest {
    /// Function name or address.
    pub function_id: String,
    /// Tags to install.
    pub tags: Vec<String>,
}

/// Request to pre-warm the database caches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrewarmRequest {
    /// Database name.
    pub database: String,
}

/// Query for the number of executables matching a filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryExeCount {
    /// The filter to apply.
    pub filter: FilterAtom,
}

/// Query for information about executables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryExeInfo {
    /// The executable specifier.
    pub exe: ExeSpecifier,
}

/// Query for nearest functions using vector similarity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryNearestVector {
    /// The query vector.
    pub vector: Vec<f64>,
    /// Number of nearest neighbors to return.
    pub count: usize,
    /// The filter to apply.
    pub filter: FilterAtom,
}

/// Query for whether optional values exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryOptionalExist {
    /// The optional field name.
    pub field_name: String,
}

/// Query for optional values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryOptionalValues {
    /// The optional field name.
    pub field_name: String,
}

/// Query to update function information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryUpdate {
    /// The function id to update.
    pub function_id: String,
    /// New name (if renaming).
    pub new_name: Option<String>,
    /// New namespace (if moving).
    pub new_namespace: Option<String>,
}

/// Query for vector id of a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryVectorId {
    /// The function id.
    pub function_id: String,
}

/// Query for vector matches above a threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryVectorMatch {
    /// The query vector.
    pub vector: Vec<f64>,
    /// Minimum similarity threshold.
    pub threshold: f64,
}

// ---- Responses ----

/// Response to an adjust-vector-index request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAdjustIndex {
    /// New index value.
    pub new_index: i64,
}

/// Response containing children of a category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseChildren {
    /// Child names.
    pub children: Vec<String>,
}

/// Response containing cluster information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseCluster {
    /// Cluster assignments.
    pub clusters: Vec<(String, usize)>,
}

/// Response to a delete request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseDelete {
    /// Number of records deleted.
    pub count: usize,
}

/// Response to a drop-database request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseDropDatabase {
    /// Whether the drop was successful.
    pub success: bool,
}

/// Response containing an error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseError {
    /// Error message.
    pub message: String,
    /// Error code.
    pub code: i32,
}

/// Response containing executable information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseExe {
    /// Executable name.
    pub name: String,
    /// Executable info fields.
    pub info: Vec<(String, String)>,
}

/// Response containing database info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseInfo {
    /// Database info key-value pairs.
    pub info: Vec<(String, String)>,
}

/// Response to an insert request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseInsert {
    /// Number of records inserted.
    pub count: usize,
}

/// A function name record in a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseNameRecord {
    /// Function name.
    pub name: String,
    /// Whether an error occurred.
    pub has_error: bool,
    /// Error message if any.
    pub error_message: Option<String>,
}

/// Response containing function name information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseName {
    /// Function records.
    pub records: Vec<ResponseNameRecord>,
}

/// Response containing nearest-vector results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseNearestVector {
    /// Nearest function matches.
    pub matches: Vec<VectorMatchResult>,
}

/// A single vector match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorMatchResult {
    /// Function id.
    pub function_id: String,
    /// Similarity score.
    pub score: f64,
    /// Function name.
    pub name: Option<String>,
}

/// Response for optional value existence check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseOptionalExist {
    /// Whether the optional field exists.
    pub exists: bool,
}

/// Response containing optional values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseOptionalValues {
    /// The values found.
    pub values: Vec<String>,
}

/// Response to a pair query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePair {
    /// Matched pairs.
    pub pairs: Vec<(String, String, f64)>,
}

/// Response to a password change request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePassword {
    /// Whether the password change was successful.
    pub success: bool,
}

/// Response to an update request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseUpdate {
    /// Whether the update was successful.
    pub success: bool,
}

/// Response containing a vector id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseVectorId {
    /// The vector id.
    pub vector_id: Option<Vec<f64>>,
}

/// Response containing vector match results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseVectorMatch {
    /// Matched results.
    pub matches: Vec<VectorMatchResult>,
}

// ============================================================================
// Missing protocol types (ported from Java)
// ============================================================================

/// A BSim query object that wraps a query message with metadata.
///
/// Port of `BSimQuery.java` -- the base class for all BSim queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimQuery {
    /// The type of query.
    pub query_type: BSimQueryType,
    /// The database to query.
    pub database: String,
    /// Filter atoms applied to this query.
    pub filters: Vec<FilterAtom>,
    /// The type filter.
    pub type_filter: Option<FilterType>,
}

/// The type of BSim query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BSimQueryType {
    /// Query for nearest neighbors.
    Nearest,
    /// Query by name.
    Name,
    /// Query for pairs.
    Pair,
    /// Query for children.
    Children,
    /// Query for cluster info.
    Cluster,
    /// Query for info.
    Info,
    /// Query for delete.
    Delete,
    /// Query for exe count.
    ExeCount,
    /// Query for exe info.
    ExeInfo,
    /// Query for nearest vector.
    NearestVector,
    /// Query for vector ID.
    VectorId,
    /// Query for vector match.
    VectorMatch,
    /// Query for optional existence.
    OptionalExist,
    /// Query for optional values.
    OptionalValues,
    /// Query for update.
    Update,
}

/// Cluster note data in a BSim response.
///
/// Port of `ClusterNote.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNote {
    /// Function name.
    pub function_name: String,
    /// Cluster ID.
    pub cluster_id: usize,
    /// Confidence score.
    pub confidence: f64,
    /// Optional note text.
    pub note: Option<String>,
}

/// A similarity note attached to a function match.
///
/// Port of `SimilarityNote.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityNote {
    /// The function this note is attached to.
    pub function_name: String,
    /// The similarity score.
    pub similarity: f64,
    /// Additional information about the similarity.
    pub details: Vec<(String, String)>,
}

/// A similarity result record.
///
/// Port of `SimilarityResult.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityResult {
    /// The matched function name.
    pub function_name: String,
    /// The executable name.
    pub executable_name: String,
    /// The similarity score.
    pub score: f64,
    /// The similarity metric used.
    pub metric: String,
    /// MD5 of the executable.
    pub md5: Option<String>,
    /// Optional address of the function.
    pub address: Option<String>,
}

/// A vector-based similarity result.
///
/// Port of `SimilarityVectorResult.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityVectorResult {
    /// The matched function name.
    pub function_name: String,
    /// The similarity score.
    pub score: f64,
    /// The feature vector.
    pub vector: Vec<f64>,
    /// The executable name.
    pub executable_name: Option<String>,
}

/// Deduplication info for executable results.
///
/// Port of `ExecutableResultWithDeDuping.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutableResultWithDeDuping {
    /// The executable name.
    pub name: String,
    /// Number of functions.
    pub function_count: usize,
    /// Number of unique functions (after dedup).
    pub unique_count: usize,
    /// MD5 hash.
    pub md5: Option<String>,
    /// Architecture name.
    pub architecture: Option<String>,
}

/// A function entry in the BSim database.
///
/// Port of `FunctionEntry.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionEntry {
    /// Function name.
    pub name: String,
    /// Function address (hex string).
    pub address: String,
    /// Function size in bytes.
    pub size: u32,
    /// The executable this function belongs to.
    pub executable_name: Option<String>,
    /// The function's feature vector.
    pub vector: Option<Vec<f64>>,
    /// Tags associated with this function.
    pub tags: Vec<String>,
}

/// Function staging for batch insert operations.
///
/// Port of `FunctionStaging.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionStaging {
    /// Staged function entries.
    pub entries: Vec<FunctionEntry>,
    /// The executable these functions belong to.
    pub executable_name: String,
    /// Batch id for tracking.
    pub batch_id: String,
}

/// Response to a prewarm request.
///
/// Port of `ResponsePrewarm.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePrewarm {
    /// Whether prewarming was successful.
    pub success: bool,
    /// Number of pages warmed.
    pub pages_loaded: usize,
}

/// Response to a nearest query.
///
/// Port of `ResponseNearest.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseNearest {
    /// The matched results.
    pub results: Vec<SimilarityResult>,
}

/// Insert request data for batch insertions.
///
/// Port of `InsertRequest.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertRequest {
    /// The executable specifier.
    pub exe: ExeSpecifier,
    /// Function entries to insert.
    pub entries: Vec<FunctionEntry>,
    /// Whether to overwrite existing entries.
    pub overwrite: bool,
}

/// Password change request.
///
/// Port of `PasswordChange.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordChange {
    /// The database name.
    pub database: String,
    /// Old password.
    pub old_password: String,
    /// New password.
    pub new_password: String,
}

/// Function staging manager for managing batch inserts.
///
/// Port of `StagingManager.java` (already in protocol.rs, this adds
/// the staging manager operations).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagingManagerState {
    /// Current staging entries.
    pub staged: Vec<FunctionStaging>,
    /// Maximum entries per batch.
    pub batch_size: usize,
    /// Total entries staged so far.
    pub total_staged: usize,
}

impl StagingManagerState {
    /// Create a new staging manager state.
    pub fn new(batch_size: usize) -> Self {
        Self {
            staged: Vec::new(),
            batch_size,
            total_staged: 0,
        }
    }

    /// Add a function staging batch.
    pub fn add_batch(&mut self, staging: FunctionStaging) {
        self.total_staged += staging.entries.len();
        self.staged.push(staging);
    }

    /// Check if staging is full.
    pub fn is_full(&self) -> bool {
        self.staged.len() >= self.batch_size
    }

    /// Flush all staged entries (return them and clear).
    pub fn flush(&mut self) -> Vec<FunctionStaging> {
        let result = std::mem::take(&mut self.staged);
        self.total_staged = 0;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_install_category_request() {
        let req = InstallCategoryRequest {
            database: "testdb".into(),
            category: "cat1".into(),
            description: "Test category".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("testdb"));
    }

    #[test]
    fn test_query_exe_count() {
        let q = QueryExeCount { filter: FilterAtom { filter_type: FilterType::ArchitectureMatch, value: "x86".into() } };
        assert_eq!(q.filter.value, "x86");
    }

    #[test]
    fn test_response_error() {
        let r = ResponseError { message: "fail".into(), code: 404 };
        assert_eq!(r.code, 404);
    }

    #[test]
    fn test_vector_match_result() {
        let r = VectorMatchResult { function_id: "f1".into(), score: 0.95, name: Some("main".into()) };
        assert!(r.score > 0.9);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let r = ResponseInsert { count: 42 };
        let json = serde_json::to_string(&r).unwrap();
        let back: ResponseInsert = serde_json::from_str(&json).unwrap();
        assert_eq!(back.count, 42);
    }

    #[test]
    fn test_bsim_query() {
        let q = BSimQuery {
            query_type: BSimQueryType::Nearest,
            database: "testdb".into(),
            filters: vec![],
            type_filter: None,
        };
        assert_eq!(q.query_type, BSimQueryType::Nearest);
        let json = serde_json::to_string(&q).unwrap();
        let back: BSimQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(back.database, "testdb");
    }

    #[test]
    fn test_cluster_note() {
        let cn = ClusterNote {
            function_name: "main".into(),
            cluster_id: 42,
            confidence: 0.95,
            note: Some("high confidence".into()),
        };
        assert_eq!(cn.cluster_id, 42);
    }

    #[test]
    fn test_similarity_result() {
        let sr = SimilarityResult {
            function_name: "func_a".into(),
            executable_name: "exe_a".into(),
            score: 0.85,
            metric: "cosine".into(),
            md5: Some("abc123".into()),
            address: Some("0x1000".into()),
        };
        assert!(sr.score > 0.8);
    }

    #[test]
    fn test_similarity_vector_result() {
        let svr = SimilarityVectorResult {
            function_name: "func_b".into(),
            score: 0.75,
            vector: vec![1.0, 2.0, 3.0],
            executable_name: None,
        };
        assert_eq!(svr.vector.len(), 3);
    }

    #[test]
    fn test_executable_result_with_deduping() {
        let er = ExecutableResultWithDeDuping {
            name: "test.exe".into(),
            function_count: 100,
            unique_count: 85,
            md5: Some("def456".into()),
            architecture: Some("x86".into()),
        };
        assert!(er.unique_count <= er.function_count);
    }

    #[test]
    fn test_function_entry() {
        let fe = FunctionEntry {
            name: "main".into(),
            address: "0x1000".into(),
            size: 64,
            executable_name: Some("test.exe".into()),
            vector: Some(vec![0.1, 0.2]),
            tags: vec!["entry".into()],
        };
        assert_eq!(fe.name, "main");
        assert_eq!(fe.size, 64);
    }

    #[test]
    fn test_function_staging() {
        let fs = FunctionStaging {
            entries: vec![
                FunctionEntry {
                    name: "a".into(),
                    address: "0x1000".into(),
                    size: 16,
                    executable_name: None,
                    vector: None,
                    tags: vec![],
                },
            ],
            executable_name: "test.exe".into(),
            batch_id: "batch1".into(),
        };
        assert_eq!(fs.entries.len(), 1);
    }

    #[test]
    fn test_staging_manager_state() {
        let mut sm = StagingManagerState::new(10);
        assert!(!sm.is_full());

        sm.add_batch(FunctionStaging {
            entries: vec![
                FunctionEntry {
                    name: "f1".into(),
                    address: "0x1000".into(),
                    size: 16,
                    executable_name: None,
                    vector: None,
                    tags: vec![],
                },
            ],
            executable_name: "exe".into(),
            batch_id: "b1".into(),
        });
        assert_eq!(sm.total_staged, 1);

        let flushed = sm.flush();
        assert_eq!(flushed.len(), 1);
        assert_eq!(sm.total_staged, 0);
    }

    #[test]
    fn test_response_nearest() {
        let rn = ResponseNearest {
            results: vec![SimilarityResult {
                function_name: "f1".into(),
                executable_name: "e1".into(),
                score: 0.9,
                metric: "cosine".into(),
                md5: None,
                address: None,
            }],
        };
        assert_eq!(rn.results.len(), 1);
    }

    #[test]
    fn test_response_prewarm() {
        let rp = ResponsePrewarm {
            success: true,
            pages_loaded: 1024,
        };
        assert!(rp.success);
    }

    #[test]
    fn test_password_change() {
        let pc = PasswordChange {
            database: "mydb".into(),
            old_password: "old".into(),
            new_password: "new".into(),
        };
        assert_eq!(pc.database, "mydb");
    }

    #[test]
    fn test_insert_request() {
        let ir = InsertRequest {
            exe: ExeSpecifier::new("test.exe"),
            entries: vec![],
            overwrite: false,
        };
        assert!(!ir.overwrite);
    }

    #[test]
    fn test_similarity_note() {
        let sn = SimilarityNote {
            function_name: "main".into(),
            similarity: 0.95,
            details: vec![("type".into(), "exact".into())],
        };
        assert_eq!(sn.similarity, 0.95);
    }
}
