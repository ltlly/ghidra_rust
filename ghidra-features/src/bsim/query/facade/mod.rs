//! High-level facade for BSim operations.
//!
//! Port of `ghidra.features.bsim.query.facade`:
//! provides a simplified API for common BSim workflows.

use serde::{Deserialize, Serialize};

use super::super::description::{ExecutableRecord, FunctionDescription};

/// Result of a BSim similarity query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimQueryResult {
    /// The matched function.
    pub function: FunctionDescription,
    /// Similarity score (0.0 - 1.0).
    pub similarity: f64,
    /// Significance score.
    pub significance: f64,
    /// The executable containing the matched function.
    pub executable: Option<ExecutableRecord>,
}

/// High-level facade for BSim operations.
///
/// Wraps the lower-level query infrastructure with a simplified API
/// for common operations like "find similar functions" or
/// "query by signature."
pub struct BSimFacade {
    /// Database connection URL.
    url: String,
    /// Similarity threshold for queries.
    pub similarity_threshold: f64,
    /// Maximum results to return.
    pub max_results: usize,
}

impl BSimFacade {
    /// Create a new BSim facade.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            similarity_threshold: 0.7,
            max_results: 100,
        }
    }

    /// Get the connection URL.
    pub fn url(&self) -> &str {
        &self.url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_facade() {
        let facade = BSimFacade::new("jdbc:postgresql://localhost/bsim");
        assert_eq!(facade.url(), "jdbc:postgresql://localhost/bsim");
        assert_eq!(facade.similarity_threshold, 0.7);
        assert_eq!(facade.max_results, 100);
    }

    #[test]
    fn test_query_result() {
        let func = FunctionDescription::new(0, "test_func", Some(0x1000));
        let result = BSimQueryResult {
            function: func,
            similarity: 0.95,
            significance: 0.99,
            executable: None,
        };
        assert!(result.similarity > 0.9);
    }
}
