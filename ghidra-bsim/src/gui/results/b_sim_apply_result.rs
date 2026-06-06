//! Port of `BSimApplyResult`.
use std::collections::HashMap;
/// Struct porting `BSimApplyResult`.
#[derive(Debug, Clone)]
pub struct BSimApplyResult {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimApplyResult {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimApplyResult {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_apply_result_new() { let _ = BSimApplyResult::new(); }
}
