//! Port of `QueryDatabaseException`.
use std::collections::HashMap;
/// Struct porting `QueryDatabaseException`.
#[derive(Debug, Clone)]
pub struct QueryDatabaseException {
    _phantom: std::marker::PhantomData<()>,
}
impl QueryDatabaseException {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for QueryDatabaseException {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_query_database_exception_new() { let _ = QueryDatabaseException::new(); }
}
