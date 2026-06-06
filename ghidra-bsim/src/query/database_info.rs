//! Port of `DatabaseInfo`.
use std::collections::HashMap;
/// Struct porting `DatabaseInfo`.
#[derive(Debug, Clone)]
pub struct DatabaseInfo {
    _phantom: std::marker::PhantomData<()>,
}
impl DatabaseInfo {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DatabaseInfo {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_database_info_new() { let _ = DatabaseInfo::new(); }
}
