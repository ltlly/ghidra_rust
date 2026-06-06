//! IdSqlResolution -- filter element resolution for SQL queries.
//!
//! Ports `ghidra.features.bsim.query.client.IDSQLResolution`.
//! Manages filter elements that need to be resolved to database IDs before
//! they can be converted to SQL clauses. In the Java codebase this is an
//! abstract class with subclasses for Architecture, Compiler, ExeCategory,
//! and ExternalFunction. In Rust we model this as an enum.

pub use super::core::IdSqlResolution;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_architecture_not_resolved() {
        let res = IdSqlResolution::architecture("x86");
        assert!(!res.is_resolved());
        assert_eq!(res.id1(), 0);
    }

    #[test]
    fn test_architecture_resolved() {
        let mut res = IdSqlResolution::architecture("arm");
        res.set_resolved_id(42);
        assert!(res.is_resolved());
        assert_eq!(res.id1(), 42);
    }

    #[test]
    fn test_compiler_not_resolved() {
        let res = IdSqlResolution::compiler("gcc");
        assert!(!res.is_resolved());
    }

    #[test]
    fn test_compiler_resolved() {
        let mut res = IdSqlResolution::compiler("clang");
        res.set_resolved_id(7);
        assert!(res.is_resolved());
        assert_eq!(res.id1(), 7);
    }

    #[test]
    fn test_exe_category_not_resolved() {
        let res = IdSqlResolution::exe_category("os", "linux");
        assert!(!res.is_resolved());
        assert_eq!(res.id1(), 0);
        assert_eq!(res.id2(), 0);
    }

    #[test]
    fn test_exe_category_resolved() {
        let mut res = IdSqlResolution::exe_category("os", "windows");
        res.set_resolved_ids(3, 4);
        assert!(res.is_resolved());
        assert_eq!(res.id1(), 3);
        assert_eq!(res.id2(), 4);
    }

    #[test]
    fn test_exe_category_partial_resolve() {
        let mut res = IdSqlResolution::exe_category("os", "mac");
        res.set_resolved_ids(0, 5);
        assert!(!res.is_resolved()); // category_id is 0
    }

    #[test]
    fn test_external_function() {
        let mut res = IdSqlResolution::external_function("lib.so", "malloc");
        assert!(!res.is_resolved());
        res.set_resolved_id(99);
        assert!(res.is_resolved());
        assert_eq!(res.id1(), 99);
    }

    #[test]
    fn test_id2_for_non_category() {
        let res = IdSqlResolution::architecture("x86");
        assert_eq!(res.id2(), 0);
    }

    #[test]
    fn test_save_xml_architecture() {
        let mut res = IdSqlResolution::architecture("arm");
        res.set_resolved_id(5);
        let mut xml = String::new();
        res.save_xml(&mut xml);
        assert!(xml.contains("idsql"));
        assert!(xml.contains("arch"));
        assert!(xml.contains("arm"));
    }

    #[test]
    fn test_save_xml_compiler() {
        let mut res = IdSqlResolution::compiler("gcc");
        res.set_resolved_id(3);
        let mut xml = String::new();
        res.save_xml(&mut xml);
        assert!(xml.contains("compiler"));
        assert!(xml.contains("gcc"));
    }

    #[test]
    fn test_save_xml_exe_category() {
        let mut res = IdSqlResolution::exe_category("os", "linux");
        res.set_resolved_ids(1, 2);
        let mut xml = String::new();
        res.save_xml(&mut xml);
        assert!(xml.contains("category"));
        assert!(xml.contains("os"));
        assert!(xml.contains("linux"));
    }

    #[test]
    fn test_save_xml_external_function() {
        let mut res = IdSqlResolution::external_function("libc.so", "printf");
        res.set_resolved_id(55);
        let mut xml = String::new();
        res.save_xml(&mut xml);
        assert!(xml.contains("extfunc"));
        assert!(xml.contains("libc.so"));
        assert!(xml.contains("printf"));
    }

    #[test]
    fn test_clone() {
        let res = IdSqlResolution::compiler("clang");
        let cloned = res.clone();
        assert_eq!(cloned.id1(), 0);
    }

    #[test]
    fn test_debug() {
        let res = IdSqlResolution::architecture("x86");
        let dbg = format!("{:?}", res);
        assert!(dbg.contains("x86"));
    }

    #[test]
    fn test_set_resolved_id_on_category_noop() {
        let mut res = IdSqlResolution::exe_category("os", "linux");
        res.set_resolved_id(99); // no-op for category variant
        assert!(!res.is_resolved()); // still 0
    }
}
