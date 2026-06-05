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
}
