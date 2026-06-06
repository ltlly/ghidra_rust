//! Port of `RowKey`.
use std::collections::HashMap;
/// Struct porting `RowKey`.
#[derive(Debug, Clone)]
pub struct RowKey {
    _phantom: std::marker::PhantomData<()>,
}
impl RowKey {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RowKey {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_row_key_new() { let _ = RowKey::new(); }
}
