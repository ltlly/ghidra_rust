//! SimilarityResultRecord -- a collection of match notes for one queried function.
//!
//! Ports `ghidra.features.bsim.query.protocol.SimilarityResult`.

pub use super::core::SimilarityResultRecord as SimilarityResult;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::protocol::SimilarityNoteData;

    #[test]
    fn test_similarity_result_new() {
        let result = SimilarityResult::new("exe1", "main", 0x1000);
        assert_eq!(result.base_exe_name, "exe1");
        assert_eq!(result.base_func_name, "main");
        assert_eq!(result.base_address, 0x1000);
        assert!(result.notes.is_empty());
        assert_eq!(result.total_count, 0);
    }

    #[test]
    fn test_similarity_result_add_note() {
        let mut result = SimilarityResult::new("exe1", "main", 0x1000);
        result.add_note(SimilarityNoteData::new("exe2", "match1", 0x2000, 0.9, 5.0));
        assert_eq!(result.size(), 1);
    }

    #[test]
    fn test_similarity_result_add_notes() {
        let mut result = SimilarityResult::new("exe1", "main", 0x1000);
        let notes = vec![
            SimilarityNoteData::new("exe2", "f1", 0x2000, 0.9, 5.0),
            SimilarityNoteData::new("exe3", "f2", 0x3000, 0.8, 4.0),
        ];
        result.add_notes(notes);
        assert_eq!(result.size(), 2);
        assert_eq!(result.total_count, 2);
    }

    #[test]
    fn test_similarity_result_sort() {
        let mut result = SimilarityResult::new("exe1", "main", 0x1000);
        result.add_note(SimilarityNoteData::new("z_exe", "z_func", 0x3000, 0.9, 5.0));
        result.add_note(SimilarityNoteData::new("a_exe", "a_func", 0x1000, 0.8, 4.0));
        result.sort_notes();
        assert_eq!(result.notes[0].exe_name, "a_exe");
    }

    #[test]
    fn test_similarity_result_iter() {
        let mut result = SimilarityResult::new("exe1", "main", 0x1000);
        result.add_note(SimilarityNoteData::new("exe2", "f1", 0x2000, 0.9, 5.0));
        result.add_note(SimilarityNoteData::new("exe3", "f2", 0x3000, 0.8, 4.0));
        let count = result.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_similarity_result_getters() {
        let result = SimilarityResult::new("exe1", "func1", 0x1000);
        assert_eq!(result.get_base_exe_name(), "exe1");
        assert_eq!(result.get_base_func_name(), "func1");
        assert_eq!(result.get_base_address(), 0x1000);
    }

    #[test]
    fn test_similarity_result_xml_save() {
        let mut result = SimilarityResult::new("exe1", "main", 0x1000);
        result.add_note(SimilarityNoteData::new("exe2", "f1", 0x2000, 0.9, 5.0));
        let mut xml = String::new();
        result.save_xml(&mut xml);
        assert!(xml.contains("simresult"));
        assert!(xml.contains("exe1"));
        assert!(xml.contains("main"));
    }

    #[test]
    fn test_similarity_result_clone() {
        let mut result = SimilarityResult::new("exe1", "main", 0x1000);
        result.add_note(SimilarityNoteData::new("exe2", "f1", 0x2000, 0.9, 5.0));
        let cloned = result.clone();
        assert_eq!(cloned.size(), 1);
    }
}
