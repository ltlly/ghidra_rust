//! Port of `BSimSqlClause`.
use std::collections::HashMap;
/// Struct porting `BSimSqlClause`.
#[derive(Debug, Clone)]
pub struct BSimSqlClause {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimSqlClause {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimSqlClause {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_sql_clause_new() { let _ = BSimSqlClause::new(); }
}
