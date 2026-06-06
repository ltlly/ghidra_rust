//! Port of `BSimApplyResultsDisplayDialog`.
use std::collections::HashMap;
/// Struct porting `BSimApplyResultsDisplayDialog`.
#[derive(Debug, Clone)]
pub struct BSimApplyResultsDisplayDialog {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimApplyResultsDisplayDialog {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimApplyResultsDisplayDialog {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_apply_results_display_dialog_new() { let _ = BSimApplyResultsDisplayDialog::new(); }
}
