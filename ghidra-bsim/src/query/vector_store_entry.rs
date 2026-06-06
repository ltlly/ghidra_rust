//! Port of `VectorStoreEntry`.
use std::collections::HashMap;
/// Struct porting `VectorStoreEntry`.
#[derive(Debug, Clone)]
pub struct VectorStoreEntry {
    _phantom: std::marker::PhantomData<()>,
}
impl VectorStoreEntry {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VectorStoreEntry {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vector_store_entry_new() { let _ = VectorStoreEntry::new(); }
}
