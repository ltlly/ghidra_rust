//! Port of `WeightTable`.
use std::collections::HashMap;
/// Struct porting `WeightTable`.
#[derive(Debug, Clone)]
pub struct WeightTable {
    _phantom: std::marker::PhantomData<()>,
}
impl WeightTable {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for WeightTable {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_weight_table_new() { let _ = WeightTable::new(); }
}
