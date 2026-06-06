//! QueryCluster -- query for function clusters.
//!
//! Ports `ghidra.features.bsim.query.protocol.QueryCluster`.

pub use super::core::QueryCluster;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_cluster_new() {
        let qc = QueryCluster::new(0.8);
        assert!((qc.threshold - 0.8).abs() < f64::EPSILON);
        assert_eq!(qc.max_cluster_size, 1000);
    }

    #[test]
    fn test_query_cluster_custom_max() {
        let mut qc = QueryCluster::new(0.5);
        qc.max_cluster_size = 500;
        assert_eq!(qc.max_cluster_size, 500);
    }

    #[test]
    fn test_query_cluster_clone() {
        let qc = QueryCluster::new(0.9);
        let cloned = qc.clone();
        assert!((cloned.threshold - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_query_cluster_debug() {
        let qc = QueryCluster::new(0.7);
        let debug = format!("{:?}", qc);
        assert!(debug.contains("0.7"));
    }

    #[test]
    fn test_query_cluster_zero_threshold() {
        let qc = QueryCluster::new(0.0);
        assert!((qc.threshold).abs() < f64::EPSILON);
    }

    #[test]
    fn test_query_cluster_full_threshold() {
        let qc = QueryCluster::new(1.0);
        assert!((qc.threshold - 1.0).abs() < f64::EPSILON);
    }
}
