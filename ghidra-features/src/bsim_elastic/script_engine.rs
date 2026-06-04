//! BSim Script Engine -- computes similarity scores for Elasticsearch queries.
//!
//! Ported from `BSimScriptEngine.java` and `VectorCompareScriptFactory.java`
//! in the BSimElasticPlugin extension.
//!
//! The script engine provides a custom scoring script for Elasticsearch that
//! computes the cosine similarity between a stored LSH vector and a query
//! vector at query time.

use std::collections::HashMap;

/// The engine name used for registration.
const ENGINE_NAME: &str = "bsim_score";

// ---------------------------------------------------------------------------
// VectorCompareScriptFactory
// ---------------------------------------------------------------------------

/// Factory for creating vector comparison scripts.
///
/// The factory holds a reference (by name) to the LSH vector factory
/// and produces script instances that can compute cosine similarity
/// between stored and query vectors.
#[derive(Debug)]
pub struct VectorCompareScriptFactory {
    /// Name of the vector factory to use.
    pub vector_factory_name: String,
    /// The query vector to compare against.
    pub query_vector: Vec<f64>,
}

impl VectorCompareScriptFactory {
    /// Create a new factory.
    pub fn new(vector_factory_name: impl Into<String>, query_vector: Vec<f64>) -> Self {
        Self {
            vector_factory_name: vector_factory_name.into(),
            query_vector,
        }
    }

    /// Compute cosine similarity between two vectors.
    pub fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
        if a.len() != b.len() || a.is_empty() {
            return 0.0;
        }

        let mut dot = 0.0;
        let mut mag_a = 0.0;
        let mut mag_b = 0.0;

        for (x, y) in a.iter().zip(b.iter()) {
            dot += x * y;
            mag_a += x * x;
            mag_b += y * y;
        }

        let denom = mag_a.sqrt() * mag_b.sqrt();
        if denom == 0.0 {
            0.0
        } else {
            dot / denom
        }
    }
}

// ---------------------------------------------------------------------------
// ScoreScript
// ---------------------------------------------------------------------------

/// A score script that computes BSim similarity.
///
/// Holds the query vector and provides a `score` method that returns
/// the cosine similarity between the query vector and a document's
/// stored vector.
#[derive(Debug)]
pub struct ScoreScript {
    /// The query vector.
    pub query_vector: Vec<f64>,
    /// The script parameters.
    pub params: HashMap<String, serde_json::Value>,
}

impl ScoreScript {
    /// Create a new score script.
    pub fn new(query_vector: Vec<f64>) -> Self {
        Self {
            query_vector,
            params: HashMap::new(),
        }
    }

    /// Set script parameters.
    pub fn set_params(&mut self, params: HashMap<String, serde_json::Value>) {
        self.params = params;
    }

    /// Compute the score for a document with the given stored vector.
    ///
    /// Returns the cosine similarity between the query and stored vectors.
    pub fn score(&self, stored_vector: &[f64]) -> f64 {
        VectorCompareScriptFactory::cosine_similarity(&self.query_vector, stored_vector)
    }
}

// ---------------------------------------------------------------------------
// BSimScriptEngine
// ---------------------------------------------------------------------------

/// The BSim Elasticsearch script engine.
///
/// Implements a script engine that can execute BSim similarity scoring
/// scripts. This is the Rust equivalent of the Java `BSimScriptEngine`
/// that integrates with Elasticsearch's scripting framework.
#[derive(Debug)]
pub struct BSimScriptEngine {
    /// Registered script factories by name.
    factories: HashMap<String, String>,
}

impl BSimScriptEngine {
    /// Create a new script engine.
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// Get the engine type name.
    pub fn get_type(&self) -> &str {
        ENGINE_NAME
    }

    /// Execute a score computation.
    ///
    /// `stored_vector` is the document's vector, `query_vector` is the probe.
    pub fn execute_score(stored_vector: &[f64], query_vector: &[f64]) -> f64 {
        VectorCompareScriptFactory::cosine_similarity(stored_vector, query_vector)
    }

    /// Close the engine and free resources.
    pub fn close(&mut self) {
        self.factories.clear();
    }
}

impl Default for BSimScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosine_similarity_identical() {
        let a = vec![1.0, 2.0, 3.0];
        let sim = VectorCompareScriptFactory::cosine_similarity(&a, &a);
        assert!((sim - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        let sim = VectorCompareScriptFactory::cosine_similarity(&a, &b);
        assert!((sim - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_cosine_similarity_empty() {
        let a: Vec<f64> = vec![];
        let b: Vec<f64> = vec![];
        assert_eq!(VectorCompareScriptFactory::cosine_similarity(&a, &b), 0.0);
    }

    #[test]
    fn test_cosine_similarity_different_lengths() {
        let a = vec![1.0, 2.0];
        let b = vec![1.0, 2.0, 3.0];
        assert_eq!(VectorCompareScriptFactory::cosine_similarity(&a, &b), 0.0);
    }

    #[test]
    fn test_cosine_similarity_zero_vector() {
        let a = vec![0.0, 0.0];
        let b = vec![1.0, 2.0];
        assert_eq!(VectorCompareScriptFactory::cosine_similarity(&a, &b), 0.0);
    }

    #[test]
    fn test_cosine_similarity_known_value() {
        let a = vec![3.0, 4.0];
        let b = vec![4.0, 3.0];
        let sim = VectorCompareScriptFactory::cosine_similarity(&a, &b);
        let expected = (3.0 * 4.0 + 4.0 * 3.0) / (5.0 * 5.0);
        assert!((sim - expected).abs() < 1e-10);
    }

    #[test]
    fn test_vector_compare_script_factory() {
        let factory = VectorCompareScriptFactory::new("test_factory", vec![1.0, 0.0]);
        assert_eq!(factory.vector_factory_name, "test_factory");
        assert_eq!(factory.query_vector, vec![1.0, 0.0]);
    }

    #[test]
    fn test_score_script() {
        let query = vec![1.0, 0.0, 0.0];
        let script = ScoreScript::new(query);
        let stored = vec![1.0, 0.0, 0.0];
        assert!((script.score(&stored) - 1.0).abs() < 1e-10);

        let stored2 = vec![0.0, 1.0, 0.0];
        assert!((script.score(&stored2)).abs() < 1e-10);
    }

    #[test]
    fn test_bsim_script_engine() {
        let engine = BSimScriptEngine::new();
        assert_eq!(engine.get_type(), "bsim_score");

        let score =
            BSimScriptEngine::execute_score(&[1.0, 2.0, 3.0], &[1.0, 2.0, 3.0]);
        assert!((score - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_bsim_script_engine_close() {
        let mut engine = BSimScriptEngine::new();
        engine.close();
        assert!(engine.factories.is_empty());
    }
}
