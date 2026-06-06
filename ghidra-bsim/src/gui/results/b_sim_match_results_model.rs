//! Port of `BSimMatchResultsModel`.
use std::collections::HashMap;
/// Struct porting `BSimMatchResultsModel`.
#[derive(Debug, Clone)]
pub struct BSimMatchResultsModel {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimMatchResultsModel {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimMatchResultsModel {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_match_results_model_new() { let _ = BSimMatchResultsModel::new(); }
}
