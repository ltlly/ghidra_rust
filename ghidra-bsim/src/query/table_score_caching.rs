//! Port of `TableScoreCaching`.
use std::collections::HashMap;
/// Struct porting `TableScoreCaching`.
#[derive(Debug, Clone)]
pub struct TableScoreCaching {
    _phantom: std::marker::PhantomData<()>,
}
impl TableScoreCaching {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for TableScoreCaching {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_table_score_caching_new() { let _ = TableScoreCaching::new(); }
}
