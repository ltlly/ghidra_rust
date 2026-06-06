//! QueryResponseRecord -- base response record from BSim queries.
//!
//! Ports `ghidra.features.bsim.query.protocol.QueryResponseRecord`.

pub use super::core::QueryResponseRecord;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_response_record_new() {
        let record = QueryResponseRecord::new("test_query");
        assert_eq!(record.name, "test_query");
        assert!(!record.has_error());
        assert!(record.error_message.is_none());
    }

    #[test]
    fn test_query_response_record_error() {
        let mut record = QueryResponseRecord::new("query");
        assert!(!record.has_error());
        record.set_error("connection failed");
        assert!(record.has_error());
        assert_eq!(record.error_message, Some("connection failed".to_string()));
    }

    #[test]
    fn test_query_response_record_clone() {
        let mut record = QueryResponseRecord::new("q1");
        record.set_error("err");
        let cloned = record.clone();
        assert_eq!(cloned.name, "q1");
        assert!(cloned.has_error());
    }

    #[test]
    fn test_query_response_record_debug() {
        let record = QueryResponseRecord::new("debug_test");
        let debug = format!("{:?}", record);
        assert!(debug.contains("debug_test"));
    }

    #[test]
    fn test_query_response_record_merge_noop() {
        let mut record = QueryResponseRecord::new("q1");
        let sub = QueryResponseRecord::new("q2");
        record.merge_from_sub_response(&sub);
        // Default implementation is a no-op
        assert_eq!(record.name, "q1");
    }

    #[test]
    fn test_query_response_record_success() {
        let record = QueryResponseRecord::new("success_query");
        assert!(!record.has_error());
        assert!(record.error_message.is_none());
    }
}
