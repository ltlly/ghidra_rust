//! Port of `RowKeyElastic`.
use std::collections::HashMap;
/// Struct porting `RowKeyElastic`.
#[derive(Debug, Clone)]
pub struct RowKeyElastic {
    _phantom: std::marker::PhantomData<()>,
}
impl RowKeyElastic {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RowKeyElastic {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_row_key_elastic_new() { let _ = RowKeyElastic::new(); }
}
