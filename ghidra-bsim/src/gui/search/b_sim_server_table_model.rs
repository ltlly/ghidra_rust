//! Port of `BSimServerTableModel`.
use std::collections::HashMap;
/// Struct porting `BSimServerTableModel`.
#[derive(Debug, Clone)]
pub struct BSimServerTableModel {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimServerTableModel {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimServerTableModel {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_server_table_model_new() { let _ = BSimServerTableModel::new(); }
}
