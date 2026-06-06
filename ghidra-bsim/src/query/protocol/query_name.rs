//! QueryName -- query for functions by name.
//!
//! Ports `ghidra.features.bsim.query.protocol.QueryName`.
//! Query for a single function in a single executable by giving either the
//! md5 of the executable, or its name and version, then giving the function
//! name. If the function name is empty, returns all functions in the executable.

pub use super::core::QueryName;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_name_new() {
        let qn = QueryName::new("main");
        assert_eq!(qn.name, "main");
    }

    #[test]
    fn test_query_name_empty() {
        let qn = QueryName::new("");
        assert!(qn.name.is_empty());
    }

    #[test]
    fn test_query_name_save_xml() {
        let qn = QueryName::new("my_function");
        let mut xml = String::new();
        qn.save_xml(&mut xml);
        assert!(xml.contains("queryname"));
        assert!(xml.contains("my_function"));
    }

    #[test]
    fn test_query_name_clone() {
        let qn = QueryName::new("func");
        let cloned = qn.clone();
        assert_eq!(cloned.name, "func");
    }

    #[test]
    fn test_query_name_debug() {
        let qn = QueryName::new("test");
        let dbg = format!("{:?}", qn);
        assert!(dbg.contains("test"));
    }
}
