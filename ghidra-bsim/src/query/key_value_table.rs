//! Port of `KeyValueTable`.
use std::collections::HashMap;
/// Struct porting `KeyValueTable`.
#[derive(Debug, Clone)]
pub struct KeyValueTable {
    _phantom: std::marker::PhantomData<()>,
}
impl KeyValueTable {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for KeyValueTable {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_key_value_table_new() { let _ = KeyValueTable::new(); }
}
