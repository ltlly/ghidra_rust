//! Port of `ChkDominanceAlgorithm`.
use std::collections::HashMap;
/// Struct porting `ChkDominanceAlgorithm`.
#[derive(Debug, Clone)]
pub struct ChkDominanceAlgorithm {
    _phantom: std::marker::PhantomData<()>,
}
impl ChkDominanceAlgorithm {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ChkDominanceAlgorithm {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_chk_dominance_algorithm_new() { let _ = ChkDominanceAlgorithm::new(); }
}
