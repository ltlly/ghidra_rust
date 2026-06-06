//! StagingManager -- abstract manager for splitting large queries into stages.
//!
//! Ports `ghidra.features.bsim.query.protocol.StagingManager`.

pub use super::core::StagingManager;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_staging_manager_basic() {
        let mut sm = StagingManager::new(10);
        assert!(sm.initialize(25));
        assert_eq!(sm.total_size(), 3); // ceil(25/10) = 3
        assert_eq!(sm.current_range(), (0, 10));

        assert!(sm.next_stage());
        assert_eq!(sm.current_range(), (10, 20));

        assert!(sm.next_stage());
        assert_eq!(sm.current_range(), (20, 25));

        assert!(!sm.next_stage()); // no more stages
        assert!(sm.is_complete());
    }

    #[test]
    fn test_staging_manager_progress() {
        let mut sm = StagingManager::new(10);
        sm.initialize(20);
        assert!((sm.progress() - 0.0).abs() < f64::EPSILON);
        sm.next_stage();
        assert!((sm.progress() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_staging_manager_empty() {
        let mut sm = StagingManager::new(10);
        assert!(!sm.initialize(0));
        assert_eq!(sm.total_size(), 0);
    }

    #[test]
    fn test_staging_manager_exact_batch() {
        let mut sm = StagingManager::new(10);
        assert!(sm.initialize(10));
        assert_eq!(sm.total_size(), 1);
        assert_eq!(sm.current_range(), (0, 10));
        assert!(!sm.next_stage());
    }

    #[test]
    fn test_staging_manager_single_item() {
        let mut sm = StagingManager::new(10);
        assert!(sm.initialize(1));
        assert_eq!(sm.total_size(), 1);
        assert_eq!(sm.current_range(), (0, 1));
        assert!(!sm.next_stage());
    }

    #[test]
    fn test_staging_manager_queries_made() {
        let mut sm = StagingManager::new(10);
        sm.initialize(25);
        assert_eq!(sm.queries_made(), 0);
        sm.next_stage();
        assert_eq!(sm.queries_made(), 1);
        sm.next_stage();
        assert_eq!(sm.queries_made(), 2);
    }

    #[test]
    fn test_staging_manager_batch_size() {
        let sm = StagingManager::new(50);
        assert_eq!(sm.batch_size(), 50);
    }

    #[test]
    fn test_staging_manager_xml_save() {
        let mut sm = StagingManager::new(10);
        sm.initialize(20);
        let mut xml = String::new();
        sm.save_xml(&mut xml);
        assert!(xml.contains("staging"));
        assert!(xml.contains("10")); // batch size
    }
}
