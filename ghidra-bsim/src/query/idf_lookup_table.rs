//! Port of `IdfLookupTable`.
use std::collections::HashMap;
/// Struct porting `IdfLookupTable`.
#[derive(Debug, Clone)]
pub struct IdfLookupTable {
    _phantom: std::marker::PhantomData<()>,
}
impl IdfLookupTable {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for IdfLookupTable {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_idf_lookup_table_new() { let _ = IdfLookupTable::new(); }
}
