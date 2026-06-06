//! Port of `ExecutableScorerSingle`.
use std::collections::HashMap;
/// Struct porting `ExecutableScorerSingle`.
#[derive(Debug, Clone)]
pub struct ExecutableScorerSingle {
    _phantom: std::marker::PhantomData<()>,
}
impl ExecutableScorerSingle {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ExecutableScorerSingle {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_executable_scorer_single_new() { let _ = ExecutableScorerSingle::new(); }
}
