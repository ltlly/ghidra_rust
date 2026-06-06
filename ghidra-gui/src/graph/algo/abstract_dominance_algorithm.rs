//! Port of `AbstractDominanceAlgorithm`.
use std::collections::HashMap;
/// Struct porting `AbstractDominanceAlgorithm`.
#[derive(Debug, Clone)]
pub struct AbstractDominanceAlgorithm {
    _phantom: std::marker::PhantomData<()>,
}
impl AbstractDominanceAlgorithm {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for AbstractDominanceAlgorithm {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_abstract_dominance_algorithm_new() { let _ = AbstractDominanceAlgorithm::new(); }
}
