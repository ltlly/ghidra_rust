//! Port of `BSimSearchResultsProvider`.
use std::collections::HashMap;
/// Struct porting `BSimSearchResultsProvider`.
#[derive(Debug, Clone)]
pub struct BSimSearchResultsProvider {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimSearchResultsProvider {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimSearchResultsProvider {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_search_results_provider_new() { let _ = BSimSearchResultsProvider::new(); }
}
