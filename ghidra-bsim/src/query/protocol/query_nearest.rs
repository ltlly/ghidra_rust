//! QueryNearest -- query for nearest matches within the database.
//!
//! Ports `ghidra.features.bsim.query.protocol.QueryNearest`.
//! Queries nearest matches to a set of functions, with configurable similarity
//! and significance thresholds, result limits, and optional filters.

pub use super::core::QueryNearest;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::protocol::core::{BSimFilter, FilterType};

    #[test]
    fn test_query_nearest_new() {
        let q = QueryNearest::new();
        assert!((q.threshold - 0.7).abs() < f64::EPSILON);
        assert!((q.significance_threshold - 0.0).abs() < f64::EPSILON);
        assert_eq!(q.max_results, 100);
        assert_eq!(q.vector_max, 0);
        assert!(q.fill_categories);
        assert!(q.filter.is_none());
    }

    #[test]
    fn test_query_nearest_default() {
        let q = QueryNearest::default();
        assert!((q.threshold - QueryNearest::DEFAULT_SIMILARITY_THRESHOLD).abs() < f64::EPSILON);
    }

    #[test]
    fn test_query_nearest_constants() {
        assert!((QueryNearest::DEFAULT_SIMILARITY_THRESHOLD - 0.7).abs() < f64::EPSILON);
        assert!((QueryNearest::DEFAULT_SIGNIFICANCE_THRESHOLD - 0.0).abs() < f64::EPSILON);
        assert_eq!(QueryNearest::DEFAULT_MAX_MATCHES, 100);
    }

    #[test]
    fn test_query_nearest_local_staging_copy() {
        let mut q = QueryNearest::new();
        q.threshold = 0.9;
        q.significance_threshold = 2.5;
        q.max_results = 50;
        q.vector_max = 10;
        q.fill_categories = false;
        let mut filter = BSimFilter::new();
        filter.add_atom(FilterType::ExeNameMatch, "exe");
        q.filter = Some(filter);

        let copy = q.local_staging_copy();
        assert!((copy.threshold - 0.9).abs() < f64::EPSILON);
        assert!((copy.significance_threshold - 2.5).abs() < f64::EPSILON);
        assert_eq!(copy.max_results, 50);
        assert_eq!(copy.vector_max, 10);
        assert!(!copy.fill_categories);
        assert!(copy.filter.is_some());
    }

    #[test]
    fn test_query_nearest_save_xml() {
        let q = QueryNearest::new();
        let mut xml = String::new();
        q.save_xml(&mut xml);
        assert!(xml.contains("querynearest"));
        assert!(xml.contains("simthresh"));
        assert!(xml.contains("0.7"));
        assert!(xml.contains("max"));
    }

    #[test]
    fn test_query_nearest_save_xml_with_filter() {
        let mut q = QueryNearest::new();
        let mut filter = BSimFilter::new();
        filter.add_atom(FilterType::ExeNameMatch, "exe");
        q.filter = Some(filter);
        let mut xml = String::new();
        q.save_xml(&mut xml);
        assert!(xml.contains("bsimfilter"));
    }

    #[test]
    fn test_query_nearest_save_xml_no_categories() {
        let mut q = QueryNearest::new();
        q.fill_categories = false;
        let mut xml = String::new();
        q.save_xml(&mut xml);
        assert!(xml.contains("categories"));
        assert!(xml.contains("false"));
    }

    #[test]
    fn test_query_nearest_clone() {
        let mut q = QueryNearest::new();
        q.threshold = 0.85;
        let cloned = q.clone();
        assert!((cloned.threshold - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn test_query_nearest_debug() {
        let q = QueryNearest::new();
        let dbg = format!("{:?}", q);
        assert!(dbg.contains("QueryNearest"));
    }
}
