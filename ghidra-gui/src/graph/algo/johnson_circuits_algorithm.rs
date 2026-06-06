//! Port of `JohnsonCircuitsAlgorithm`.
use std::collections::HashMap;
/// Struct porting `JohnsonCircuitsAlgorithm`.
#[derive(Debug, Clone)]
pub struct JohnsonCircuitsAlgorithm {
    /// java_stack_depth_limit.
    pub java_stack_depth_limit: i32,
}

impl JohnsonCircuitsAlgorithm {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for JohnsonCircuitsAlgorithm {
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
    fn test_johnson_circuits_algorithm_new() { let _ = JohnsonCircuitsAlgorithm::new(); }
}
