//! Port of `CancelledSQLException`.
use std::collections::HashMap;
/// Struct porting `CancelledSQLException`.
#[derive(Debug, Clone)]
pub struct CancelledSQLException {
    _phantom: std::marker::PhantomData<()>,
}
impl CancelledSQLException {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for CancelledSQLException {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_cancelled_sql_exception_new() { let _ = CancelledSQLException::new(); }
}
