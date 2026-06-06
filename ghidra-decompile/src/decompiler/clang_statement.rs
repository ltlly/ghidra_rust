//! Port of `ClangStatement`.
use std::collections::HashMap;
/// Struct porting `ClangStatement`.
#[derive(Debug, Clone)]
pub struct ClangStatement {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangStatement {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangStatement {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_statement_new() { let _ = ClangStatement::new(); }
}
