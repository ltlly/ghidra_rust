//! PairNote -- result of a comparison between two functions.
//!
//! Ports `ghidra.features.bsim.query.protocol.PairNote`.
//! Includes descriptors for the original functions, the similarity and
//! significance scores, and other score information (dot product, hash counts).

pub use super::core::PairNoteData as PairNote;

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::core::{ExeSpecifier, FunctionEntryData};

    #[test]
    fn test_pair_note_new() {
        let note = PairNote::new(0.95, 10.0);
        assert!((note.similarity - 0.95).abs() < f64::EPSILON);
        assert!((note.significance - 10.0).abs() < f64::EPSILON);
        assert!(note.found);
        assert!(note.exe_a.is_none());
    }

    #[test]
    fn test_pair_note_not_found() {
        let note = PairNote::not_found();
        assert!(!note.found);
        assert!((note.similarity - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pair_note_with_details() {
        let note = PairNote::with_details(
            ExeSpecifier::new("a.exe"),
            FunctionEntryData::new("funcA", 0x100),
            ExeSpecifier::new("b.exe"),
            FunctionEntryData::new("funcB", 0x200),
            0.85,
            12.0,
            42.5,
            100,
            120,
            80,
        );
        assert!(note.found);
        assert!((note.similarity - 0.85).abs() < f64::EPSILON);
        assert!((note.dot_product() - 42.5).abs() < f64::EPSILON);
        assert_eq!(note.func1_hash_count(), 100);
        assert_eq!(note.func2_hash_count(), 120);
        assert_eq!(note.intersection_count(), 80);
        assert!(note.exe_a.is_some());
        assert_eq!(note.func_a.as_ref().unwrap().func_name, "funcA");
    }

    #[test]
    fn test_pair_note_getters() {
        let note = PairNote::with_details(
            ExeSpecifier::new("a"),
            FunctionEntryData::new("f1", 0x100),
            ExeSpecifier::new("b"),
            FunctionEntryData::new("f2", 0x200),
            0.5, 2.0, 10.0, 50, 60, 30,
        );
        assert_eq!(note.func1_hash_count(), 50);
        assert_eq!(note.func2_hash_count(), 60);
        assert_eq!(note.intersection_count(), 30);
    }

    #[test]
    fn test_pair_note_save_xml() {
        let note = PairNote::new(0.95, 10.0);
        let mut xml = String::new();
        note.save_xml(&mut xml);
        assert!(xml.contains("pairnote"));
        assert!(xml.contains("0.95"));
    }

    #[test]
    fn test_pair_note_clone() {
        let note = PairNote::new(0.9, 5.0);
        let cloned = note.clone();
        assert!((cloned.similarity - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pair_note_serialization() {
        let note = PairNote::new(0.8, 4.0);
        let json = serde_json::to_string(&note).unwrap();
        let back: PairNote = serde_json::from_str(&json).unwrap();
        assert!((back.similarity - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pair_note_debug() {
        let note = PairNote::new(0.5, 1.0);
        let dbg = format!("{:?}", note);
        assert!(dbg.contains("0.5"));
    }
}
