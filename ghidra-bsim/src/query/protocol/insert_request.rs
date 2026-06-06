//! InsertRequest -- request to insert functions into a BSim database.
//!
//! Ports `ghidra.features.bsim.query.protocol.InsertRequest`.
//! Contains a set of executables and functions to be inserted, with optional
//! repository and path overrides.

pub use super::core::InsertRequestData as InsertRequest;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::description::BSimFunctionDescription;
    use super::super::core::ExeSpecifier;

    #[test]
    fn test_insert_request_new() {
        let req = InsertRequest::new(ExeSpecifier::new("test.exe"));
        assert_eq!(req.exe_specifier.exe_name, "test.exe");
        assert!(req.functions.is_empty());
        assert!(!req.overwrite);
    }

    #[test]
    fn test_insert_request_add_function() {
        let mut req = InsertRequest::new(ExeSpecifier::new("exe"));
        req.add_function(BSimFunctionDescription::new("exe", "main", 0x1000));
        assert_eq!(req.functions.len(), 1);
    }

    #[test]
    fn test_insert_request_set_overwrite() {
        let mut req = InsertRequest::new(ExeSpecifier::new("exe"));
        req.set_overwrite(true);
        assert!(req.overwrite);
    }

    #[test]
    fn test_insert_request_save_xml() {
        let mut req = InsertRequest::new(ExeSpecifier::new("test.exe"));
        req.add_function(BSimFunctionDescription::new("test.exe", "main", 0x1000));
        req.set_overwrite(true);
        let mut xml = String::new();
        req.save_xml(&mut xml);
        assert!(xml.contains("<insert>"));
        assert!(xml.contains("test.exe"));
        assert!(xml.contains("main"));
    }

    #[test]
    fn test_insert_request_clone() {
        let req = InsertRequest::new(ExeSpecifier::new("exe"));
        let cloned = req.clone();
        assert_eq!(cloned.exe_specifier.exe_name, "exe");
    }

    #[test]
    fn test_insert_request_serialization() {
        let req = InsertRequest::new(ExeSpecifier::new("exe"));
        let json = serde_json::to_string(&req).unwrap();
        let back: InsertRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.exe_specifier.exe_name, "exe");
    }

    #[test]
    fn test_insert_request_debug() {
        let req = InsertRequest::new(ExeSpecifier::new("test"));
        let dbg = format!("{:?}", req);
        assert!(dbg.contains("test"));
    }
}
