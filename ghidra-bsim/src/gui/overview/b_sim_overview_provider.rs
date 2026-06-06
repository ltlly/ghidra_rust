//! Port of `BSimOverviewProvider`.
use std::collections::HashMap;
/// Struct porting `BSimOverviewProvider`.
#[derive(Debug, Clone)]
pub struct BSimOverviewProvider {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimOverviewProvider {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimOverviewProvider {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_overview_provider_new() { let _ = BSimOverviewProvider::new(); }
}
