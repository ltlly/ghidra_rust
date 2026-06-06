//! QueryDelete -- request to delete specific executables from a BSim database.
//!
//! Ports `ghidra.features.bsim.query.protocol.QueryDelete`.
//! Takes a list of executable specifiers to be deleted.

pub use super::core::QueryDelete;

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::core::ExeSpecifier;

    #[test]
    fn test_query_delete_new() {
        let qd = QueryDelete::new(ExeSpecifier::new("bad.exe"));
        assert_eq!(qd.exe.exe_name, "bad.exe");
    }

    #[test]
    fn test_query_delete_save_xml() {
        let qd = QueryDelete::new(ExeSpecifier::new("delete_me.exe"));
        let mut xml = String::new();
        qd.save_xml(&mut xml);
        assert!(xml.contains("delete"));
        assert!(xml.contains("delete_me.exe"));
    }

    #[test]
    fn test_query_delete_by_md5() {
        let qd = QueryDelete::new(ExeSpecifier::from_md5("abc123"));
        assert_eq!(qd.exe.md5, "abc123");
    }

    #[test]
    fn test_query_delete_clone() {
        let qd = QueryDelete::new(ExeSpecifier::new("exe"));
        let cloned = qd.clone();
        assert_eq!(cloned.exe.exe_name, "exe");
    }

    #[test]
    fn test_query_delete_debug() {
        let qd = QueryDelete::new(ExeSpecifier::new("test"));
        let dbg = format!("{:?}", qd);
        assert!(dbg.contains("test"));
    }
}
