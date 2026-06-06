//! Port of `BSimResultRowObjectToAddressTableRowMapper`.
use std::collections::HashMap;
/// Struct porting `BSimResultRowObjectToAddressTableRowMapper`.
#[derive(Debug, Clone)]
pub struct BSimResultRowObjectToAddressTableRowMapper {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimResultRowObjectToAddressTableRowMapper {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimResultRowObjectToAddressTableRowMapper {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_result_row_object_to_address_table_row_mapper_new() { let _ = BSimResultRowObjectToAddressTableRowMapper::new(); }
}
