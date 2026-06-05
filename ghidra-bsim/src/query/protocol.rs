//! BSim wire protocol types.
//!
//! Ports `ghidra.features.bsim.query.protocol` from Ghidra's Java source.

use serde::{Deserialize, Serialize};

use super::description::{BSimExecutableInfo, BSimFunctionDescription, SimilarityMetric};

/// A BSim request message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BSimRequest {
    /// Register a new executable.
    RegisterExecutable(BSimExecutableInfo),
    /// Ingest function descriptions.
    IngestFunctions(Vec<BSimFunctionDescription>),
    /// Query for similar functions.
    QuerySimilar {
        /// The function to find matches for.
        description: BSimFunctionDescription,
        /// Which metric to use.
        metric: SimilarityMetric,
        /// Maximum results to return.
        max_results: usize,
        /// Minimum similarity threshold.
        min_similarity: f64,
    },
    /// Query by function hash.
    QueryByHash(String),
    /// Get functions for an executable.
    GetFunctions(String),
    /// Get executable info.
    GetExecutableInfo(String),
    /// Get total function count.
    GetFunctionCount,
    /// Get total executable count.
    GetExecutableCount,
    /// Remove an executable.
    RemoveExecutable(String),
    /// Health check / ping.
    Ping,
}

/// A BSim response message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BSimResponse {
    /// Success with no data.
    Success,
    /// Function descriptions returned.
    Functions(Vec<BSimFunctionDescription>),
    /// Executable info returned.
    ExecutableInfo(Option<BSimExecutableInfo>),
    /// A count value.
    Count(usize),
    /// An error response.
    Error(String),
    /// Pong response to ping.
    Pong,
}

impl BSimResponse {
    /// Whether this response indicates success.
    pub fn is_success(&self) -> bool {
        !matches!(self, BSimResponse::Error(_))
    }

    /// Get the error message if this is an error response.
    pub fn error_message(&self) -> Option<&str> {
        match self {
            BSimResponse::Error(msg) => Some(msg),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let req = BSimRequest::Ping;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("Ping"));

        let req = BSimRequest::GetFunctionCount;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("GetFunctionCount"));
    }

    #[test]
    fn test_response_success() {
        let resp = BSimResponse::Success;
        assert!(resp.is_success());
        assert!(resp.error_message().is_none());
    }

    #[test]
    fn test_response_error() {
        let resp = BSimResponse::Error("connection failed".into());
        assert!(!resp.is_success());
        assert_eq!(resp.error_message(), Some("connection failed"));
    }

    #[test]
    fn test_response_count() {
        let resp = BSimResponse::Count(42);
        assert!(resp.is_success());
        match resp {
            BSimResponse::Count(n) => assert_eq!(n, 42),
            _ => panic!("expected Count"),
        }
    }

    #[test]
    fn test_response_pong() {
        let resp = BSimResponse::Pong;
        assert!(resp.is_success());
    }

    #[test]
    fn test_request_query_serialization() {
        let func = BSimFunctionDescription::new("exe1", "main", 0x1000);
        let req = BSimRequest::QuerySimilar {
            description: func,
            metric: SimilarityMetric::Jaccard,
            max_results: 100,
            min_similarity: 0.5,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: BSimRequest = serde_json::from_str(&json).unwrap();
        match deserialized {
            BSimRequest::QuerySimilar { max_results, min_similarity, .. } => {
                assert_eq!(max_results, 100);
                assert!((min_similarity - 0.5).abs() < f64::EPSILON);
            }
            _ => panic!("expected QuerySimilar"),
        }
    }
}
