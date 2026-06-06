//! SimilarityVectorResult -- vector-based similarity result.
//!
//! Ports `ghidra.features.bsim.query.protocol.SimilarityVectorResult`.

pub use super::core::VectorResultData as SimilarityVectorResult;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_similarity_vector_result_new() {
        let result = SimilarityVectorResult::new(42, 100);
        assert_eq!(result.vector_id, 42);
        assert_eq!(result.hit_count, 100);
        assert!(result.features.is_empty());
    }

    #[test]
    fn test_similarity_vector_result_with_features() {
        let mut result = SimilarityVectorResult::new(1, 5);
        result.features = vec![(1, 10), (2, 20), (3, 30)];
        assert_eq!(result.features.len(), 3);
    }

    #[test]
    fn test_similarity_vector_result_serialization() {
        let result = SimilarityVectorResult::new(99, 200);
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("99"));
        assert!(json.contains("200"));
        let back: SimilarityVectorResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.vector_id, 99);
        assert_eq!(back.hit_count, 200);
    }

    #[test]
    fn test_similarity_vector_result_clone() {
        let mut result = SimilarityVectorResult::new(10, 20);
        result.features = vec![(1, 5)];
        let cloned = result.clone();
        assert_eq!(cloned.vector_id, 10);
        assert_eq!(cloned.features.len(), 1);
    }

    #[test]
    fn test_similarity_vector_result_debug() {
        let result = SimilarityVectorResult::new(7, 15);
        let debug = format!("{:?}", result);
        assert!(debug.contains("7"));
        assert!(debug.contains("15"));
    }

    #[test]
    fn test_similarity_vector_result_xml_save() {
        let result = SimilarityVectorResult::new(42, 100);
        let mut xml = String::new();
        result.save_xml(&mut xml);
        assert!(xml.contains("vresult"));
        assert!(xml.contains("42"));
    }
}
