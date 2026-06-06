//! Port of `OptionalTable`.
use std::collections::HashMap;
/// Struct porting `OptionalTable`.
#[derive(Debug, Clone)]
pub struct OptionalTable {
    _phantom: std::marker::PhantomData<()>,
}
impl OptionalTable {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for OptionalTable {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_optional_table_new() { let _ = OptionalTable::new(); }
}
