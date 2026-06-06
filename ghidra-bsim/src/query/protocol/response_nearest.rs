//! ResponseNearest -- response from a nearest-match query.
//!
//! Ports `ghidra.features.bsim.query.protocol.ResponseNearest`.

pub use super::core::ResponseNearest;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::protocol::SimilarityNoteData;

    #[test]
    fn test_response_nearest_new() {
        let rn = ResponseNearest::new();
        assert!(rn.results.is_empty());
        assert_eq!(rn.total_count, 0);
    }

    #[test]
    fn test_response_nearest_add_results() {
        let mut rn = ResponseNearest::new();
        let notes = vec![
            SimilarityNoteData::new("exe1", "func1", 0x100, 0.95, 10.0),
            SimilarityNoteData::new("exe2", "func2", 0x200, 0.85, 8.0),
        ];
        rn.add_results(notes);
        assert_eq!(rn.results.len(), 2);
        assert_eq!(rn.total_count, 2);
    }

    #[test]
    fn test_response_nearest_sort() {
        let mut rn = ResponseNearest::new();
        let notes = vec![
            SimilarityNoteData::new("exe1", "low", 0x100, 0.5, 3.0),
            SimilarityNoteData::new("exe2", "high", 0x200, 0.95, 10.0),
            SimilarityNoteData::new("exe3", "mid", 0x300, 0.7, 6.0),
        ];
        rn.add_results(notes);
        rn.sort_by_similarity();

        assert!((rn.results[0].similarity - 0.95).abs() < f64::EPSILON);
        assert!((rn.results[1].similarity - 0.7).abs() < f64::EPSILON);
        assert!((rn.results[2].similarity - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_response_nearest_merge() {
        let mut rn1 = ResponseNearest::new();
        rn1.add_results(vec![
            SimilarityNoteData::new("exe1", "f1", 0x100, 0.9, 5.0),
        ]);

        let mut rn2 = ResponseNearest::new();
        rn2.add_results(vec![
            SimilarityNoteData::new("exe2", "f2", 0x200, 0.8, 4.0),
        ]);

        rn1.merge_results(&rn2);
        assert_eq!(rn1.results.len(), 2);
        assert_eq!(rn1.total_count, 2);
    }

    #[test]
    fn test_response_nearest_clone() {
        let mut rn = ResponseNearest::new();
        rn.add_results(vec![
            SimilarityNoteData::new("exe", "func", 0x100, 0.9, 5.0),
        ]);
        let cloned = rn.clone();
        assert_eq!(cloned.results.len(), 1);
        assert_eq!(cloned.total_count, 1);
    }

    #[test]
    fn test_response_nearest_default() {
        let rn = ResponseNearest::default();
        assert!(rn.results.is_empty());
    }

    #[test]
    fn test_response_nearest_xml_save() {
        let mut rn = ResponseNearest::new();
        rn.add_results(vec![
            SimilarityNoteData::new("exe", "func", 0x100, 0.9, 5.0),
        ]);
        let mut xml = String::new();
        rn.save_xml(&mut xml);
        assert!(xml.contains("responsenearest"));
        assert!(xml.contains("totalcount"));
    }
}
