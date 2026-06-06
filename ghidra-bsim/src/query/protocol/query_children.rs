//! QueryChildren -- query for children of a function.
//!
//! Ports `ghidra.features.bsim.query.protocol.QueryChildren`.
//! Queries based on a single executable and specific function names within it.
//! The response contains the corresponding FunctionDescription records and a
//! record for each child of the specified functions.

pub use super::core::QueryChildren;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_children_new() {
        let qc = QueryChildren::new("exe1", "parent_func", 0x1000);
        assert_eq!(qc.parent_exe, "exe1");
        assert_eq!(qc.parent_name, "parent_func");
        assert_eq!(qc.parent_address, 0x1000);
    }

    #[test]
    fn test_query_children_save_xml() {
        let qc = QueryChildren::new("exe", "parent", 0x1000);
        let mut xml = String::new();
        qc.save_xml(&mut xml);
        assert!(xml.contains("querychildren"));
        assert!(xml.contains("exe"));
        assert!(xml.contains("parent"));
    }

    #[test]
    fn test_query_children_clone() {
        let qc = QueryChildren::new("exe", "func", 0x100);
        let cloned = qc.clone();
        assert_eq!(cloned.parent_exe, "exe");
        assert_eq!(cloned.parent_name, "func");
    }

    #[test]
    fn test_query_children_debug() {
        let qc = QueryChildren::new("exe", "func", 0x100);
        let dbg = format!("{:?}", qc);
        assert!(dbg.contains("exe"));
        assert!(dbg.contains("func"));
    }
}
