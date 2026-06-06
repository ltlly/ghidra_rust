//! Port of `BSimOverviewModel`.
use std::collections::HashMap;
/// Struct porting `BSimOverviewModel`.
#[derive(Debug, Clone)]
pub struct BSimOverviewModel {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimOverviewModel {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimOverviewModel {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_overview_model_new() { let _ = BSimOverviewModel::new(); }
}
