//! Port of `BSimOverviewRowObjectToAddressTableRowMapper`.
use std::collections::HashMap;
/// Struct porting `BSimOverviewRowObjectToAddressTableRowMapper`.
#[derive(Debug, Clone)]
pub struct BSimOverviewRowObjectToAddressTableRowMapper {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimOverviewRowObjectToAddressTableRowMapper {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimOverviewRowObjectToAddressTableRowMapper {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_overview_row_object_to_address_table_row_mapper_new() { let _ = BSimOverviewRowObjectToAddressTableRowMapper::new(); }
}
