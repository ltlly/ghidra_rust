//! Port of `ExecutableScorer`.
use std::collections::HashMap;
/// Struct porting `ExecutableScorer`.
#[derive(Debug, Clone)]
pub struct ExecutableScorer {
    /// func_a.
    pub func_a: String,
    /// func_b.
    pub func_b: String,
    /// similarity.
    pub similarity: f64,
    /// significance.
    pub significance: f64,
    /// executable_set.
    pub executable_set: String,
    /// sim_threshold.
    pub sim_threshold: f64,
}

impl ExecutableScorer {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ExecutableScorer {
    fn default() -> Self {
        Self {
            func_a: String::new(),
            func_b: String::new(),
            similarity: 0,
            significance: 0,
            executable_set: String::new(),
            sim_threshold: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_executable_scorer_new() { let _ = ExecutableScorer::new(); }
}
