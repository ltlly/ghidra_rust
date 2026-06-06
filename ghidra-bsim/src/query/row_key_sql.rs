//! Port of `RowKeySQL`.
use std::collections::HashMap;
/// Struct porting `RowKeySQL`.
#[derive(Debug, Clone)]
pub struct RowKeySQL {
    _phantom: std::marker::PhantomData<()>,
}
impl RowKeySQL {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RowKeySQL {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_row_key_sql_new() { let _ = RowKeySQL::new(); }
}
