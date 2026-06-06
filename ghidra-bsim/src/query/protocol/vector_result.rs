//! VectorResult -- result of a vector similarity query.
//!
//! Ports `ghidra.features.bsim.query.description.VectorResult`.

pub use super::super::description::VectorResult;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::description::{BSimFunctionDescription, SignatureRecord};

    #[test]
    fn test_vector_result_new() {
        let sig = SignatureRecord::new(vec![0.1, 0.2, 0.3]);
        let func = BSimFunctionDescription::new("exe1", "main", 0x1000);
        let result = VectorResult::new(sig, func, 0.95);
        assert!((result.score - 0.95).abs() < f64::EPSILON);
        assert_eq!(result.rank, 0);
    }

    #[test]
    fn test_vector_result_with_rank() {
        let sig = SignatureRecord::new(vec![1.0, 2.0]);
        let func = BSimFunctionDescription::new("exe1", "printf", 0x4000);
        let result = VectorResult::new(sig, func, 0.85).with_rank(3);
        assert_eq!(result.rank, 3);
    }

    #[test]
    fn test_vector_result_signature_l2_norm() {
        let sig = SignatureRecord::new(vec![3.0, 4.0]);
        let func = BSimFunctionDescription::new("exe1", "func", 0x1000);
        let result = VectorResult::new(sig, func, 0.5);
        assert!((result.signature.l2_norm() - 5.0).abs() < 1e-10);
    }

    #[test]
    fn test_vector_result_clone() {
        let sig = SignatureRecord::new(vec![0.5, 0.5]);
        let func = BSimFunctionDescription::new("exe1", "func", 0x1000);
        let result = VectorResult::new(sig, func, 0.75).with_rank(2);
        let cloned = result.clone();
        assert!((cloned.score - 0.75).abs() < f64::EPSILON);
        assert_eq!(cloned.rank, 2);
    }

    #[test]
    fn test_vector_result_debug() {
        let sig = SignatureRecord::new(vec![1.0]);
        let func = BSimFunctionDescription::new("exe", "f", 0);
        let result = VectorResult::new(sig, func, 0.5);
        let debug = format!("{:?}", result);
        assert!(debug.contains("0.5"));
    }

    #[test]
    fn test_vector_result_serialization() {
        let sig = SignatureRecord::new(vec![0.1, 0.2]).with_vector_id(42);
        let func = BSimFunctionDescription::new("exe1", "main", 0x1000);
        let result = VectorResult::new(sig, func, 0.9);
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("0.9"));
        let back: VectorResult = serde_json::from_str(&json).unwrap();
        assert!((back.score - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_vector_result_empty_vector() {
        let sig = SignatureRecord::new(vec![]);
        let func = BSimFunctionDescription::new("exe1", "empty", 0x1000);
        let result = VectorResult::new(sig, func, 0.0);
        assert!(result.signature.vector.is_empty());
        assert!((result.signature.l2_norm()).abs() < f64::EPSILON);
    }
}
