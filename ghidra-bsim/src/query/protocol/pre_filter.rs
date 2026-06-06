//! PreFilter -- predicate-based filtering before BSim queries.
//!
//! Ports `ghidra.features.bsim.query.protocol.PreFilter`.

pub use super::core::PreFilter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pre_filter_default_accepts() {
        let filter = PreFilter::new();
        assert!(filter.accepts("main", 100, false, false));
        assert!(filter.accepts("small", 1, false, false));
    }

    #[test]
    fn test_pre_filter_min_size() {
        let filter = PreFilter::new().with_min_size(10);
        assert!(!filter.accepts("tiny", 5, false, false));
        assert!(filter.accepts("medium", 50, false, false));
    }

    #[test]
    fn test_pre_filter_max_size() {
        let filter = PreFilter::new().with_max_size(100);
        assert!(filter.accepts("small", 50, false, false));
        assert!(!filter.accepts("huge", 200, false, false));
    }

    #[test]
    fn test_pre_filter_size_range() {
        let filter = PreFilter::new().with_min_size(10).with_max_size(100);
        assert!(!filter.accepts("tiny", 5, false, false));
        assert!(filter.accepts("medium", 50, false, false));
        assert!(!filter.accepts("huge", 200, false, false));
    }

    #[test]
    fn test_pre_filter_library() {
        let filter_no_lib = PreFilter::new().with_include_library(false);
        assert!(!filter_no_lib.accepts("printf", 100, true, false));
        assert!(filter_no_lib.accepts("main", 100, false, false));

        let filter_lib = PreFilter::new().with_include_library(true);
        assert!(filter_lib.accepts("printf", 100, true, false));
    }

    #[test]
    fn test_pre_filter_thunks() {
        let filter_no_thunk = PreFilter::new().with_include_thunks(false);
        assert!(!filter_no_thunk.accepts("thunk_func", 100, false, true));

        let filter_thunk = PreFilter::new().with_include_thunks(true);
        assert!(filter_thunk.accepts("thunk_func", 100, false, true));
    }

    #[test]
    fn test_pre_filter_include_pattern() {
        let mut filter = PreFilter::new();
        filter.add_include_pattern("init");
        assert!(filter.accepts("__init_module", 100, false, false));
        assert!(!filter.accepts("main", 100, false, false));
    }

    #[test]
    fn test_pre_filter_exclude_pattern() {
        let mut filter = PreFilter::new();
        filter.add_exclude_pattern("debug");
        assert!(filter.accepts("main", 100, false, false));
        assert!(!filter.accepts("debug_print", 100, false, false));
    }

    #[test]
    fn test_pre_filter_combined() {
        let mut filter = PreFilter::new()
            .with_min_size(10)
            .with_include_library(false);
        filter.add_exclude_pattern("test_");
        // Passes all criteria
        assert!(filter.accepts("process_data", 50, false, false));
        // Fails size
        assert!(!filter.accepts("process_data", 5, false, false));
        // Fails library
        assert!(!filter.accepts("process_data", 50, true, false));
        // Fails exclude
        assert!(!filter.accepts("test_data", 50, false, false));
    }

    #[test]
    fn test_pre_filter_clear() {
        let mut filter = PreFilter::new().with_min_size(100);
        filter.add_include_pattern("main");
        assert!(!filter.accepts("other", 50, false, false));

        filter.clear();
        assert!(filter.accepts("other", 50, false, false));
    }

    #[test]
    fn test_pre_filter_multiple_include_patterns() {
        let mut filter = PreFilter::new();
        filter.add_include_pattern("init");
        filter.add_include_pattern("main");
        // Must match at least one
        assert!(filter.accepts("__init", 100, false, false));
        assert!(filter.accepts("main_loop", 100, false, false));
        assert!(!filter.accepts("process", 100, false, false));
    }

    #[test]
    fn test_pre_filter_multiple_exclude_patterns() {
        let mut filter = PreFilter::new();
        filter.add_exclude_pattern("debug");
        filter.add_exclude_pattern("test");
        assert!(filter.accepts("main", 100, false, false));
        assert!(!filter.accepts("debug_print", 100, false, false));
        assert!(!filter.accepts("test_func", 100, false, false));
    }
}
