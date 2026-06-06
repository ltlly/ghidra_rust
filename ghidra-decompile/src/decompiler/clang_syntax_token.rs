//! Port of `ClangSyntaxToken`.
use std::collections::HashMap;
/// Struct porting `ClangSyntaxToken`.
#[derive(Debug, Clone)]
pub struct ClangSyntaxToken {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangSyntaxToken {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangSyntaxToken {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_syntax_token_new() { let _ = ClangSyntaxToken::new(); }
}
