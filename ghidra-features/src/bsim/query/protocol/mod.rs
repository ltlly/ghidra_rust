//! BSim query protocol types.
//!
//! Port of `ghidra.features.bsim.query.protocol`:
//! client-server protocol types for BSim queries.

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
}
