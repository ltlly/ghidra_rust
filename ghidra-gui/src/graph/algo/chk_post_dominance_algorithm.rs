//! Port of `ChkPostDominanceAlgorithm`.
use std::collections::HashMap;
/// Struct porting `ChkPostDominanceAlgorithm`.
#[derive(Debug, Clone)]
pub struct ChkPostDominanceAlgorithm {
    _phantom: std::marker::PhantomData<()>,
}
impl ChkPostDominanceAlgorithm {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ChkPostDominanceAlgorithm {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_chk_post_dominance_algorithm_new() { let _ = ChkPostDominanceAlgorithm::new(); }
}
