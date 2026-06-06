//! AdjustVectorIndex -- request to rebuild or drop the main vector index.
//!
//! Ports `ghidra.features.bsim.query.protocol.AdjustVectorIndex`.

pub use super::core::AdjustVectorIndexRequest as AdjustVectorIndex;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adjust_vector_index_new() {
        let adj = AdjustVectorIndex::new(42);
        assert_eq!(adj.new_index, 42);
    }

    #[test]
    fn test_adjust_vector_index_save_xml() {
        let adj = AdjustVectorIndex::new(100);
        let mut xml = String::new();
        adj.save_xml(&mut xml);
        assert!(xml.contains("adjustvectorindex"));
        assert!(xml.contains("100"));
    }

    #[test]
    fn test_adjust_vector_index_clone() {
        let adj = AdjustVectorIndex::new(50);
        let cloned = adj.clone();
        assert_eq!(cloned.new_index, 50);
    }

    #[test]
    fn test_adjust_vector_index_debug() {
        let adj = AdjustVectorIndex::new(10);
        let dbg = format!("{:?}", adj);
        assert!(dbg.contains("10"));
    }
}
