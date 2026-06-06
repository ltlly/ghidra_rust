//! Port of `BSimApplyResultsTableModel`.
use std::collections::HashMap;
/// Struct porting `BSimApplyResultsTableModel`.
#[derive(Debug, Clone)]
pub struct BSimApplyResultsTableModel {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimApplyResultsTableModel {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimApplyResultsTableModel {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_apply_results_table_model_new() { let _ = BSimApplyResultsTableModel::new(); }
}
