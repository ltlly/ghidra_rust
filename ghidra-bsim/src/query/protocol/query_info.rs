//! QueryInfo -- request database information from a BSim server.
//!
//! Ports `ghidra.features.bsim.query.protocol.QueryInfo`.
//!
//! This protocol message is sent to the server to request the
//! `DatabaseInformation` object for a specific BSim database.  It carries no
//! additional payload; the server responds with a `ResponseInfo` message
//! containing the database metadata (name, description, creation date,
//! function count, etc.).

pub use super::core::QueryInfo;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_info_new() {
        let qi = QueryInfo::new();
        // QueryInfo is a unit struct; just verify construction succeeds.
        let _ = qi;
    }

    #[test]
    fn test_query_info_default() {
        let qi = QueryInfo::default();
        let _ = qi;
    }

    #[test]
    fn test_query_info_clone() {
        let qi = QueryInfo::new();
        let cloned = qi.clone();
        // Both should be identical (unit struct).
        assert_eq!(format!("{:?}", qi), format!("{:?}", cloned));
    }

    #[test]
    fn test_query_info_debug() {
        let qi = QueryInfo::new();
        let debug_str = format!("{:?}", qi);
        assert!(debug_str.contains("QueryInfo"));
    }

    #[test]
    fn test_query_info_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<QueryInfo>();
    }
}
