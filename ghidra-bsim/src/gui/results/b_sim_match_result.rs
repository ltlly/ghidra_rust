//! Port of `BSimMatchResult`.
use std::collections::HashMap;
/// Struct porting `BSimMatchResult`.
#[derive(Debug, Clone)]
pub struct BSimMatchResult {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimMatchResult {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimMatchResult {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_match_result_new() { let _ = BSimMatchResult::new(); }
}
