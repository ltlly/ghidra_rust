//! InsertOptionalValues -- optional key/value pairs for function insertion.
//!
//! Ports `ghidra.features.bsim.query.protocol.InsertOptionalValues`.
//! Allows inserting optional key/value pairs into an optional table alongside
//! function descriptions.

pub use super::core::InsertOptionalValues;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_optional_values_new() {
        let vals = InsertOptionalValues::new();
        assert!(vals.is_empty());
        assert!(vals.tags.is_empty());
        assert!(vals.signatures.is_empty());
        assert!(vals.metadata.is_empty());
    }

    #[test]
    fn test_insert_optional_values_add_tag() {
        let mut vals = InsertOptionalValues::new();
        vals.add_tag("important");
        assert!(!vals.is_empty());
        assert_eq!(vals.tags.len(), 1);
        assert_eq!(vals.tags[0], "important");
    }

    #[test]
    fn test_insert_optional_values_add_metadata() {
        let mut vals = InsertOptionalValues::new();
        vals.add_metadata("key1", "value1");
        assert!(!vals.is_empty());
        assert_eq!(vals.metadata.get("key1").unwrap(), "value1");
    }

    #[test]
    fn test_insert_optional_values_save_xml() {
        let mut vals = InsertOptionalValues::new();
        vals.add_tag("tag1");
        vals.add_metadata("k", "v");
        let mut xml = String::new();
        vals.save_xml(&mut xml);
        assert!(xml.contains("<optional>"));
        assert!(xml.contains("tag1"));
        assert!(xml.contains("k"));
    }

    #[test]
    fn test_insert_optional_values_save_xml_empty() {
        let vals = InsertOptionalValues::new();
        let mut xml = String::new();
        vals.save_xml(&mut xml);
        assert!(xml.is_empty());
    }

    #[test]
    fn test_insert_optional_values_clone() {
        let mut vals = InsertOptionalValues::new();
        vals.add_tag("t");
        vals.add_metadata("k", "v");
        let cloned = vals.clone();
        assert_eq!(cloned.tags.len(), 1);
        assert_eq!(cloned.metadata.len(), 1);
    }

    #[test]
    fn test_insert_optional_values_serialization() {
        let mut vals = InsertOptionalValues::new();
        vals.add_tag("tag1");
        vals.add_metadata("key", "val");
        let json = serde_json::to_string(&vals).unwrap();
        let back: InsertOptionalValues = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tags.len(), 1);
        assert_eq!(back.metadata.get("key").unwrap(), "val");
    }

    #[test]
    fn test_insert_optional_values_default() {
        let vals = InsertOptionalValues::default();
        assert!(vals.is_empty());
    }
}
