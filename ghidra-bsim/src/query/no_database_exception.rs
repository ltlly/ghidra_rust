//! Port of `NoDatabaseException`.
use std::collections::HashMap;
/// Struct porting `NoDatabaseException`.
#[derive(Debug, Clone)]
pub struct NoDatabaseException {
    _phantom: std::marker::PhantomData<()>,
}
impl NoDatabaseException {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for NoDatabaseException {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_no_database_exception_new() { let _ = NoDatabaseException::new(); }
}
