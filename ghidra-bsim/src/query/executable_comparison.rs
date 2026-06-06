//! Port of `ExecutableComparison`.
use std::collections::HashMap;
/// Struct porting `ExecutableComparison`.
#[derive(Debug, Clone)]
pub struct ExecutableComparison {
    /// value.
    pub value: i32,
}

impl ExecutableComparison {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ExecutableComparison {
    fn default() -> Self {
        Self {
            value: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_executable_comparison_new() { let _ = ExecutableComparison::new(); }
}
