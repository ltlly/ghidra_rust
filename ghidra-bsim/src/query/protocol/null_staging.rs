//! NullStaging -- a no-op staging manager that passes everything through.
//!
//! Ports `ghidra.features.bsim.query.protocol.NullStaging`.

pub use super::core::NullStaging;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_staging_new() {
        let ns = NullStaging::new();
        assert_eq!(ns.total_size(), 1);
        assert_eq!(ns.queries_made(), 1);
    }

    #[test]
    fn test_null_staging_single_stage() {
        let mut ns = NullStaging::new();
        assert!(ns.initialize());
        assert!(!ns.next_stage());
    }

    #[test]
    fn test_null_staging_default() {
        let ns = NullStaging;
        assert_eq!(ns.total_size(), 1);
    }

    #[test]
    fn test_null_staging_is_single_stage() {
        let mut ns = NullStaging::new();
        ns.initialize();
        // NullStaging always represents a single stage
        assert!(!ns.next_stage());
    }
}
