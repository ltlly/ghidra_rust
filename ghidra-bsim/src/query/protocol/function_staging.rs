//! FunctionStaging -- staging manager for batch function queries.
//!
//! Ports `ghidra.features.bsim.query.protocol.FunctionStaging`.

pub use super::core::FunctionStagingManager as FunctionStaging;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_staging_new() {
        let fs = FunctionStaging::new(100);
        assert_eq!(fs.stage_size, 100);
        assert_eq!(fs.total, 0);
    }

    #[test]
    fn test_function_staging_initialize() {
        let mut fs = FunctionStaging::new(10);
        let has_data = fs.initialize(25);
        assert!(has_data);
        assert_eq!(fs.total, 25);
        assert_eq!(fs.stage_start(), 0);
        assert_eq!(fs.stage_end(), 10);
    }

    #[test]
    fn test_function_staging_advance() {
        let mut fs = FunctionStaging::new(10);
        fs.initialize(25);

        assert!(fs.next_stage());
        assert_eq!(fs.stage_start(), 10);
        assert_eq!(fs.stage_end(), 20);

        assert!(fs.next_stage());
        assert_eq!(fs.stage_start(), 20);
        assert_eq!(fs.stage_end(), 25);

        assert!(!fs.next_stage());
        assert!(fs.is_complete());
    }

    #[test]
    fn test_function_staging_empty() {
        let mut fs = FunctionStaging::new(10);
        let has_data = fs.initialize(0);
        assert!(!has_data);
        assert!(fs.is_complete());
    }

    #[test]
    fn test_function_staging_progress() {
        let mut fs = FunctionStaging::new(10);
        fs.initialize(30);
        assert!((fs.progress() - 10.0 / 30.0).abs() < 1e-10);

        fs.next_stage();
        assert!((fs.progress() - 20.0 / 30.0).abs() < 1e-10);
    }

    #[test]
    fn test_function_staging_single_batch() {
        let mut fs = FunctionStaging::new(100);
        fs.initialize(5);
        assert_eq!(fs.stage_start(), 0);
        assert_eq!(fs.stage_end(), 5);
        assert!(!fs.next_stage());
    }

    #[test]
    fn test_function_staging_clone() {
        let fs = FunctionStaging::new(10);
        let cloned = fs.clone();
        assert_eq!(cloned.stage_size, 10);
    }
}
