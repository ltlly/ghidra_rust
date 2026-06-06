//! ExecutableResultWithDeDuping -- deduplicated executable match result.
//!
//! Ports `ghidra.features.bsim.query.protocol.ExecutableResultWithDeDuping`.
//! When aggregating similarity results across multiple queried functions,
//! matches pointing to the same executable are deduplicated, keeping only
//! the highest significance match per executable.

pub use super::core::ExecutableResultWithDeDuping;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::protocol::SimilarityNoteData;

    #[test]
    fn test_exe_result_dedup_new() {
        let er = ExecutableResultWithDeDuping::new("id1", "test.exe");
        assert_eq!(er.exe_id, "id1");
        assert_eq!(er.exe_name, "test.exe");
        assert_eq!(er.get_function_count(), 0);
        assert!((er.get_significance_sum() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_exe_result_dedup_add_function() {
        let mut er = ExecutableResultWithDeDuping::new("id1", "exe");
        er.add_function(5.0);
        er.add_function(3.0);
        assert_eq!(er.get_function_count(), 2);
        assert!((er.get_significance_sum() - 8.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_exe_result_dedup_ordering() {
        let mut a = ExecutableResultWithDeDuping::new("a", "exe_a");
        a.add_function(10.0);
        let mut b = ExecutableResultWithDeDuping::new("b", "exe_b");
        b.add_function(5.0);
        assert!(b < a);
    }

    #[test]
    fn test_exe_result_dedup_eq_by_id() {
        let a = ExecutableResultWithDeDuping::new("same_id", "exe_a");
        let b = ExecutableResultWithDeDuping::new("same_id", "exe_b");
        assert_eq!(a, b);
    }

    #[test]
    fn test_exe_result_dedup_neq_by_id() {
        let a = ExecutableResultWithDeDuping::new("id_a", "exe");
        let b = ExecutableResultWithDeDuping::new("id_b", "exe");
        assert_ne!(a, b);
    }

    #[test]
    fn test_exe_result_dedup_generate_from_notes() {
        let notes = vec![
            SimilarityNoteData::new("exe1", "func1", 0x100, 0.9, 10.0),
            SimilarityNoteData::new("exe1", "func2", 0x200, 0.8, 8.0),
            SimilarityNoteData::new("exe2", "func3", 0x300, 0.95, 12.0),
        ];
        let results = ExecutableResultWithDeDuping::generate_from_notes(notes);
        assert_eq!(results.len(), 2);
        let exe1 = results.iter().find(|r| r.exe_name == "exe1").unwrap();
        assert!((exe1.significance_sum - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_exe_result_dedup_generate_empty() {
        let results = ExecutableResultWithDeDuping::generate_from_notes(vec![]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_exe_result_dedup_generate_single_exe() {
        let notes = vec![
            SimilarityNoteData::new("exe", "f1", 0x100, 0.9, 10.0),
            SimilarityNoteData::new("exe", "f2", 0x200, 0.8, 8.0),
            SimilarityNoteData::new("exe", "f3", 0x300, 0.7, 6.0),
        ];
        let results = ExecutableResultWithDeDuping::generate_from_notes(notes);
        assert_eq!(results.len(), 1);
        // Should keep max significance = 10.0
        assert!((results[0].significance_sum - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_exe_result_dedup_save_xml() {
        let mut er = ExecutableResultWithDeDuping::new("id1", "test.exe");
        er.add_function(5.0);
        let mut xml = String::new();
        er.save_xml(&mut xml);
        assert!(xml.contains("exeresult"));
        assert!(xml.contains("test.exe"));
        assert!(xml.contains("1"));
    }

    #[test]
    fn test_exe_result_dedup_clone() {
        let er = ExecutableResultWithDeDuping::new("id1", "exe");
        let cloned = er.clone();
        assert_eq!(cloned, er);
    }

    #[test]
    fn test_exe_result_dedup_debug() {
        let er = ExecutableResultWithDeDuping::new("id1", "exe");
        let dbg = format!("{:?}", er);
        assert!(dbg.contains("exe"));
    }
}
