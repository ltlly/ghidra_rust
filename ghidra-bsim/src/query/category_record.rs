//! Port of `CategoryRecord`.
use std::collections::HashMap;
/// Struct porting `CategoryRecord`.
#[derive(Debug, Clone)]
pub struct CategoryRecord {
    _phantom: std::marker::PhantomData<()>,
}
impl CategoryRecord {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for CategoryRecord {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_category_record_new() { let _ = CategoryRecord::new(); }
}
