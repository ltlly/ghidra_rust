//! Additional BSim response types.
//!
//! Port of Ghidra's `ghidra.features.bsim.query.protocol` response types
//! that handle specific response scenarios not covered in the base protocol.
//!
//! These types implement the response side of BSim RPC messages for:
//! - Error responses with codes and descriptions
//! - Insert acknowledgments
//! - Database operation results (drop, password changes)
//! - Query results (name, pair, delete, cluster, info)
//! - Vector and metadata responses

use serde::{Deserialize, Serialize};

use super::protocol::{ExeSpecifier, FilterAtom, QueryResponseRecord};
use super::description::{BSimFunctionDescription, SimilarityMetric, VectorResult};

/// Error response from the BSim server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseError {
    /// Error code.
    pub error_code: i32,
    /// Error message.
    pub message: String,
    /// The query that caused the error (if available).
    pub original_query: Option<String>,
}

impl ResponseError {
    /// Create a new error response.
    pub fn new(error_code: i32, message: impl Into<String>) -> Self {
        Self {
            error_code,
            message: message.into(),
            original_query: None,
        }
    }

    /// Whether this is a connection error.
    pub fn is_connection_error(&self) -> bool {
        self.error_code >= 100 && self.error_code < 200
    }

    /// Whether this is a query error.
    pub fn is_query_error(&self) -> bool {
        self.error_code >= 200 && self.error_code < 300
    }

    /// Whether this is a permission error.
    pub fn is_permission_error(&self) -> bool {
        self.error_code == 403 || self.error_code == 401
    }
}

impl std::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BSim error {}: {}", self.error_code, self.message)
    }
}

impl std::error::Error for ResponseError {}

/// Response to an insert request, confirming data was stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseInsert {
    /// The number of functions inserted.
    pub functions_inserted: usize,
    /// The number of executables created or updated.
    pub executables_affected: usize,
    /// The database name.
    pub database: String,
}

/// Response confirming a database was dropped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseDropDatabase {
    /// The name of the dropped database.
    pub database: String,
    /// Whether the drop was successful.
    pub success: bool,
}

/// Response confirming a password change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePassword {
    /// Whether the password change was successful.
    pub success: bool,
    /// Optional message.
    pub message: Option<String>,
}

/// Response containing executable information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseExe {
    /// The executable specifier.
    pub exe: ExeSpecifier,
    /// The number of functions in the executable.
    pub function_count: usize,
    /// The executable's metadata.
    pub metadata: Vec<(String, String)>,
}

/// Response containing general information about the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseInfo {
    /// The database name.
    pub database: String,
    /// Server version string.
    pub server_version: String,
    /// Total number of executables.
    pub total_executables: usize,
    /// Total number of functions.
    pub total_functions: usize,
    /// Database-specific metadata.
    pub metadata: Vec<(String, String)>,
}

/// Response for a name query (search by function name).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseName {
    /// Functions matching the query.
    pub results: Vec<BSimFunctionDescription>,
    /// Total number of matches (may be larger than results.len()).
    pub total_matches: usize,
}

/// Response for a pair similarity query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePair {
    /// The similarity result.
    pub similarity: f64,
    /// The metric used.
    pub metric: SimilarityMetric,
    /// Whether the functions are considered similar.
    pub is_similar: bool,
}

/// Response for a delete operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseDelete {
    /// The number of functions deleted.
    pub functions_deleted: usize,
    /// The number of executables affected.
    pub executables_affected: usize,
}

/// Response for a cluster query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseCluster {
    /// Cluster assignments: (function_id -> cluster_id).
    pub clusters: Vec<(String, usize)>,
    /// Number of clusters found.
    pub cluster_count: usize,
}

/// Response for a query-nearest operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseNearest {
    /// The nearest function matches.
    pub matches: Vec<NearestMatch>,
    /// The total number of candidates examined.
    pub candidates_examined: usize,
}

/// A single nearest-match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearestMatch {
    /// The matching function description.
    pub function: BSimFunctionDescription,
    /// Similarity score.
    pub score: f64,
    /// The metric used for comparison.
    pub metric: SimilarityMetric,
}

/// Response for a query-children operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseChildren {
    /// Child function names.
    pub children: Vec<String>,
    /// The parent function.
    pub parent: String,
}

/// Response for a vector ID query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseVectorId {
    /// The vector ID.
    pub vector_id: Option<u64>,
    /// Whether the vector was found.
    pub found: bool,
}

/// Response for a vector match query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseVectorMatch {
    /// Matching vector results.
    pub results: Vec<VectorResult>,
    /// The metric used.
    pub metric: SimilarityMetric,
    /// Total number of vectors searched.
    pub vectors_searched: usize,
}

/// Response for optional values query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseOptionalValues {
    /// Key-value pairs returned.
    pub values: Vec<(String, String)>,
}

/// Response for optional existence check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseOptionalExist {
    /// Which keys exist.
    pub existing_keys: Vec<String>,
}

/// Response for a query-update operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseUpdate {
    /// Number of records updated.
    pub records_updated: usize,
}

/// Response for a nearest-vector query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseNearestVector {
    /// The nearest vector matches with scores.
    pub matches: Vec<(VectorResult, f64)>,
}

/// Response for adjusting a vector index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAdjustIndex {
    /// The adjusted index.
    pub new_index: u64,
    /// Whether the adjustment was successful.
    pub success: bool,
}

/// Response for a prewarm request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePrewarm {
    /// Whether the prewarm was successful.
    pub success: bool,
    /// Cache entries loaded.
    pub entries_loaded: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_error() {
        let err = ResponseError::new(500, "internal error");
        assert_eq!(err.error_code, 500);
        assert!(!err.is_connection_error());
        assert!(!err.is_query_error());
        assert!(!err.is_permission_error());
        assert!(format!("{}", err).contains("500"));
    }

    #[test]
    fn test_response_error_connection() {
        let err = ResponseError::new(101, "connection refused");
        assert!(err.is_connection_error());
        assert!(!err.is_query_error());
    }

    #[test]
    fn test_response_error_query() {
        let err = ResponseError::new(201, "bad query");
        assert!(!err.is_connection_error());
        assert!(err.is_query_error());
    }

    #[test]
    fn test_response_error_permission() {
        let err = ResponseError::new(403, "forbidden");
        assert!(err.is_permission_error());
    }

    #[test]
    fn test_response_insert() {
        let r = ResponseInsert {
            functions_inserted: 100,
            executables_affected: 5,
            database: "test_db".to_string(),
        };
        assert_eq!(r.functions_inserted, 100);
        assert_eq!(r.executables_affected, 5);
    }

    #[test]
    fn test_response_drop_database() {
        let r = ResponseDropDatabase {
            database: "old_db".to_string(),
            success: true,
        };
        assert!(r.success);
    }

    #[test]
    fn test_response_info() {
        let r = ResponseInfo {
            database: "main".to_string(),
            server_version: "1.0".to_string(),
            total_executables: 42,
            total_functions: 10000,
            metadata: vec![],
        };
        assert_eq!(r.total_executables, 42);
        assert_eq!(r.total_functions, 10000);
    }

    #[test]
    fn test_response_name() {
        let r = ResponseName {
            results: vec![],
            total_matches: 0,
        };
        assert_eq!(r.total_matches, 0);
    }

    #[test]
    fn test_nearest_match() {
        // Verify NearestMatch can be constructed.
        let m = NearestMatch {
            function: BSimFunctionDescription::new("exe", "test_func", 0x1000),
            score: 0.95,
            metric: SimilarityMetric::Cosine,
        };
        assert!((m.score - 0.95).abs() < 1e-10);
    }

    #[test]
    fn test_response_vector_id() {
        let r = ResponseVectorId {
            vector_id: Some(42),
            found: true,
        };
        assert!(r.found);
        assert_eq!(r.vector_id, Some(42));
    }

    #[test]
    fn test_response_update() {
        let r = ResponseUpdate {
            records_updated: 10,
        };
        assert_eq!(r.records_updated, 10);
    }

    #[test]
    fn test_response_prewarm() {
        let r = ResponsePrewarm {
            success: true,
            entries_loaded: 500,
        };
        assert!(r.success);
        assert_eq!(r.entries_loaded, 500);
    }
}
