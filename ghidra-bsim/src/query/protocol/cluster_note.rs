//! ClusterNote -- a description of a function cluster match.
//!
//! Ports `ghidra.features.bsim.query.protocol.ClusterNote`.

pub use super::core::ClusterNoteData as ClusterNote;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_note_new() {
        let note = ClusterNote::new("exe1", "func1", 0x1000, 5, 0.95, 10.0);
        assert_eq!(note.exe_name, "exe1");
        assert_eq!(note.func_name, "func1");
        assert_eq!(note.address, 0x1000);
        assert_eq!(note.set_size, 5);
        assert!((note.max_similarity - 0.95).abs() < f64::EPSILON);
        assert!((note.significance - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cluster_note_save_xml() {
        let note = ClusterNote::new("exe1", "func1", 0x1000, 5, 0.95, 10.0);
        let mut xml = String::new();
        note.save_xml(&mut xml);
        assert!(xml.contains("cnote"));
        assert!(xml.contains("exe1"));
        assert!(xml.contains("func1"));
    }

    #[test]
    fn test_cluster_note_clone() {
        let note = ClusterNote::new("exe", "func", 0x100, 3, 0.8, 5.0);
        let cloned = note.clone();
        assert_eq!(cloned.set_size, 3);
        assert!((cloned.max_similarity - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cluster_note_debug() {
        let note = ClusterNote::new("exe", "func", 0x100, 1, 0.5, 1.0);
        let dbg = format!("{:?}", note);
        assert!(dbg.contains("exe"));
        assert!(dbg.contains("func"));
    }
}
