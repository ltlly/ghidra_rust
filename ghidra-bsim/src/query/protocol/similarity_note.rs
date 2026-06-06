//! SimilarityNote -- a single function similarity match.
//!
//! Ports `ghidra.features.bsim.query.protocol.SimilarityNote`.

pub use super::core::SimilarityNoteData as SimilarityNote;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_similarity_note_new() {
        let note = SimilarityNote::new("test.exe", "main", 0x1000, 0.95, 10.0);
        assert_eq!(note.exe_name, "test.exe");
        assert_eq!(note.func_name, "main");
        assert_eq!(note.address, 0x1000);
        assert!((note.similarity - 0.95).abs() < f64::EPSILON);
        assert!((note.significance - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_similarity_note_ordering() {
        let a = SimilarityNote::new("exe", "aaa", 0x100, 0.9, 5.0);
        let b = SimilarityNote::new("exe", "bbb", 0x200, 0.8, 4.0);
        assert!(a < b);
    }

    #[test]
    fn test_similarity_note_eq() {
        let a = SimilarityNote::new("exe", "func", 0x100, 0.9, 5.0);
        let b = SimilarityNote::new("exe", "func", 0x100, 0.5, 2.0);
        assert_eq!(a, b); // equality ignores similarity/significance
    }

    #[test]
    fn test_similarity_note_ne_by_name() {
        let a = SimilarityNote::new("exe", "func_a", 0x100, 0.9, 5.0);
        let b = SimilarityNote::new("exe", "func_b", 0x100, 0.9, 5.0);
        assert_ne!(a, b);
    }

    #[test]
    fn test_similarity_note_serialization() {
        let note = SimilarityNote::new("exe", "func", 0x1000, 0.85, 7.5);
        let json = serde_json::to_string(&note).unwrap();
        assert!(json.contains("exe"));
        assert!(json.contains("func"));
        let back: SimilarityNote = serde_json::from_str(&json).unwrap();
        assert_eq!(back, note);
    }

    #[test]
    fn test_similarity_note_clone() {
        let note = SimilarityNote::new("exe", "func", 0x100, 0.9, 5.0);
        let cloned = note.clone();
        assert_eq!(cloned, note);
    }

    #[test]
    fn test_similarity_note_xml_save() {
        let note = SimilarityNote::new("exe", "func", 0x1000, 0.85, 7.5);
        let mut xml = String::new();
        note.save_xml(&mut xml);
        assert!(xml.contains("snote"));
        assert!(xml.contains("exe"));
        assert!(xml.contains("func"));
    }
}
