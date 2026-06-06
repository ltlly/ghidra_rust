//! Port of `ClangVariableDecl`.
use std::collections::HashMap;
/// Struct porting `ClangVariableDecl`.
#[derive(Debug, Clone)]
pub struct ClangVariableDecl {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangVariableDecl {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangVariableDecl {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_variable_decl_new() { let _ = ClangVariableDecl::new(); }
}
