//! Extended BSim protocol types.
//!
//! Additional request/response types ported from Ghidra's
//! `ghidra.features.bsim.query.protocol` package:
//! `QueryResponseRecord`, `SimilarityNote`, `SimilarityResult`,
//! `SimilarityVectorResult`, `ResponsePassword`, `ResponsePrewarm`,
//! `ResponseUpdate`, `ResponseVectorId`, `ResponseVectorMatch`,
//! `StagingManager`.

use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use std::collections::HashMap;

use super::super::FeatureVector;

/// A note describing a single function similarity match.
///
/// Port of Ghidra's `ghidra.features.bsim.query.protocol.SimilarityNote`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimilarityNote {
    /// The function name.
    pub function_name: String,
    /// The function address.
    pub address: u64,
    /// The executable cross-reference index.
    pub exe_xref_index: usize,
    /// Similarity score.
    pub similarity: f64,
    /// Significance score.
    pub significance: f64,
}

impl SimilarityNote {
    /// Create a new similarity note.
    pub fn new(
        function_name: impl Into<String>,
        address: u64,
        exe_xref_index: usize,
        similarity: f64,
        significance: f64,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            address,
            exe_xref_index,
            similarity,
            significance,
        }
    }

    /// Whether the similarity exceeds a threshold.
    pub fn is_significant(&self, threshold: f64) -> bool {
        self.similarity >= threshold
    }
}

impl PartialOrd for SimilarityNote {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.function_name.partial_cmp(&other.function_name)
    }
}

/// A set of similarity results for a query.
///
/// Port of Ghidra's `ghidra.features.bsim.query.protocol.SimilarityResult`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimilarityResult {
    /// The similarity notes (matches).
    pub notes: Vec<SimilarityNote>,
    /// Total number of matches found.
    pub total_matches: usize,
}

impl SimilarityResult {
    /// Create an empty similarity result.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a similarity note.
    pub fn add_note(&mut self, note: SimilarityNote) {
        self.notes.push(note);
        self.total_matches = self.notes.len();
    }

    /// Get notes sorted by similarity (descending).
    pub fn sorted_by_similarity(&self) -> Vec<&SimilarityNote> {
        let mut sorted: Vec<&SimilarityNote> = self.notes.iter().collect();
        sorted.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted
    }

    /// Filter notes above a threshold.
    pub fn above_threshold(&self, threshold: f64) -> Vec<&SimilarityNote> {
        self.notes.iter().filter(|n| n.similarity >= threshold).collect()
    }
}

/// Results of a vector match query.
///
/// Port of Ghidra's `ghidra.features.bsim.query.protocol.SimilarityVectorResult`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimilarityVectorResult {
    /// The similarity results.
    pub result: SimilarityResult,
    /// Additional vector data.
    pub vector_data: HashMap<String, FeatureVector>,
}

impl SimilarityVectorResult {
    /// Create a new similarity vector result.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a vector associated with a function key.
    pub fn add_vector(&mut self, key: impl Into<String>, vector: FeatureVector) {
        self.vector_data.insert(key.into(), vector);
    }

    /// Get a vector by key.
    pub fn get_vector(&self, key: &str) -> Option<&FeatureVector> {
        self.vector_data.get(key)
    }
}

/// Response to a password change request.
///
/// Port of Ghidra's `ghidra.features.bsim.query.protocol.ResponsePassword`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePassword {
    /// Whether the password change was successful.
    pub success: bool,
    /// Error message if the change failed.
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
/// Port of Ghidra's `ghidra.features.bsim.query.protocol.ResponsePrewarm`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePrewarm {
    /// Whether the prewarm was successful.
    pub success: bool,
    /// Number of vectors warmed.
    pub vectors_warmed: usize,
}

impl ResponsePrewarm {
    /// Create a prewarm response.
    pub fn new(success: bool, vectors_warmed: usize) -> Self {
        Self {
            success,
            vectors_warmed,
        }
    }
}

/// Response to an update request.
///
/// Port of Ghidra's `ghidra.features.bsim.query.protocol.ResponseUpdate`.
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

/// Response to a vector ID query.
///
/// Port of Ghidra's `ghidra.features.bsim.query.protocol.ResponseVectorId`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseVectorId {
    /// The vector IDs found.
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

/// Response to a vector match query.
///
/// Port of Ghidra's `ghidra.features.bsim.query.protocol.ResponseVectorMatch`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseVectorMatch {
    /// The matching functions and their similarity notes.
    pub matches: Vec<SimilarityNote>,
    /// The description manager with full function/executable data.
    pub has_manager: bool,
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

/// Manages staging of function data before committing to the database.
///
/// Port of Ghidra's `ghidra.features.bsim.query.protocol.StagingManager`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StagingManager {
    /// Staged function entries.
    pub staged: HashMap<String, StagedEntry>,
}

/// A single staged entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedEntry {
    /// The function name.
    pub function_name: String,
    /// The function address.
    pub address: u64,
    /// The executable index.
    pub exe_index: usize,
    /// The feature vector (if available).
    pub vector: Option<FeatureVector>,
}

impl StagingManager {
    /// Create a new staging manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stage a function entry.
    pub fn stage(
        &mut self,
        function_name: impl Into<String>,
        address: u64,
        exe_index: usize,
        vector: Option<FeatureVector>,
    ) {
        let name = function_name.into();
        self.staged.insert(
            name.clone(),
            StagedEntry {
                function_name: name,
                address,
                exe_index,
                vector,
            },
        );
    }

    /// Get the number of staged entries.
    pub fn count(&self) -> usize {
        self.staged.len()
    }

    /// Whether the staging area is empty.
    pub fn is_empty(&self) -> bool {
        self.staged.is_empty()
    }

    /// Clear all staged entries.
    pub fn clear(&mut self) {
        self.staged.clear();
    }

    /// Drain all entries (consuming).
    pub fn drain(&mut self) -> Vec<StagedEntry> {
        self.staged.drain().map(|(_, v)| v).collect()
    }

    /// Get a staged entry by function name.
    pub fn get(&self, function_name: &str) -> Option<&StagedEntry> {
        self.staged.get(function_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn similarity_note_creation() {
        let note = SimilarityNote::new("main", 0x1000, 0, 0.85, 0.9);
        assert_eq!(note.function_name, "main");
        assert!(note.is_significant(0.8));
        assert!(!note.is_significant(0.9));
    }

    #[test]
    fn similarity_result_operations() {
        let mut result = SimilarityResult::new();
        result.add_note(SimilarityNote::new("a", 0x1000, 0, 0.7, 0.8));
        result.add_note(SimilarityNote::new("b", 0x2000, 0, 0.9, 0.95));
        result.add_note(SimilarityNote::new("c", 0x3000, 0, 0.5, 0.6));

        assert_eq!(result.total_matches, 3);

        let sorted = result.sorted_by_similarity();
        assert_eq!(sorted[0].function_name, "b");
        assert_eq!(sorted[1].function_name, "a");
        assert_eq!(sorted[2].function_name, "c");

        let above = result.above_threshold(0.6);
        assert_eq!(above.len(), 2);
    }

    #[test]
    fn similarity_vector_result() {
        let mut svr = SimilarityVectorResult::new();
        svr.add_vector(
            "func_a",
            FeatureVector::from_pairs(vec![1, 2], vec![1.0, 1.0]),
        );
        assert!(svr.get_vector("func_a").is_some());
        assert!(svr.get_vector("func_b").is_none());
    }

    #[test]
    fn response_password() {
        let ok = ResponsePassword::success();
        assert!(ok.success);
        assert!(ok.error_message.is_none());

        let fail = ResponsePassword::failure("wrong password");
        assert!(!fail.success);
        assert!(fail.error_message.is_some());
    }

    #[test]
    fn response_prewarm() {
        let r = ResponsePrewarm::new(true, 100);
        assert!(r.success);
        assert_eq!(r.vectors_warmed, 100);
    }

    #[test]
    fn response_update() {
        let r = ResponseUpdate::new(true, 42);
        assert!(r.success);
        assert_eq!(r.records_updated, 42);
    }

    #[test]
    fn response_vector_id() {
        let mut r = ResponseVectorId::new();
        r.add_id(10);
        r.add_id(20);
        assert_eq!(r.vector_ids, vec![10, 20]);
    }

    #[test]
    fn response_vector_match() {
        let mut r = ResponseVectorMatch::new();
        r.add_match(SimilarityNote::new("f", 0x100, 0, 0.9, 0.95));
        assert_eq!(r.match_count(), 1);
    }

    #[test]
    fn staging_manager_operations() {
        let mut sm = StagingManager::new();
        assert!(sm.is_empty());

        sm.stage("main", 0x1000, 0, None);
        sm.stage("foo", 0x2000, 1, Some(FeatureVector::from_pairs(vec![1], vec![1.0])));

        assert_eq!(sm.count(), 2);
        assert!(sm.get("main").is_some());
        assert!(sm.get("nonexistent").is_none());

        let entry = sm.get("foo").unwrap();
        assert!(entry.vector.is_some());

        let entries = sm.drain();
        assert_eq!(entries.len(), 2);
        assert!(sm.is_empty());
    }

    #[test]
    fn staging_manager_clear() {
        let mut sm = StagingManager::new();
        sm.stage("a", 0x1000, 0, None);
        sm.stage("b", 0x2000, 0, None);
        sm.clear();
        assert!(sm.is_empty());
    }
}
