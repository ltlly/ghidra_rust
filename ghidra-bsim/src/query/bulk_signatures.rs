//! Port of `BulkSignatures`.
use std::collections::HashMap;
/// Struct porting `BulkSignatures`.
#[derive(Debug, Clone)]
pub struct BulkSignatures {
    _phantom: std::marker::PhantomData<()>,
}
impl BulkSignatures {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BulkSignatures {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_bulk_signatures_new() { let _ = BulkSignatures::new(); }
}
