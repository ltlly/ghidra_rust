//! Port of `BSimOverviewRowObject`.
use std::collections::HashMap;
/// Struct porting `BSimOverviewRowObject`.
#[derive(Debug, Clone)]
pub struct BSimOverviewRowObject {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimOverviewRowObject {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimOverviewRowObject {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_overview_row_object_new() { let _ = BSimOverviewRowObject::new(); }
}
