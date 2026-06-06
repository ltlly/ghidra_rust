//! Port of `RecursiveFindPathsAlgorithm`.
use std::collections::HashMap;
/// Struct porting `RecursiveFindPathsAlgorithm`.
#[derive(Debug, Clone)]
pub struct RecursiveFindPathsAlgorithm {
    /// java_stack_depth_limit.
    pub java_stack_depth_limit: i32,
}

impl RecursiveFindPathsAlgorithm {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for RecursiveFindPathsAlgorithm {
    fn default() -> Self {
        Self {
            java_stack_depth_limit: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_recursive_find_paths_algorithm_new() { let _ = RecursiveFindPathsAlgorithm::new(); }
}
