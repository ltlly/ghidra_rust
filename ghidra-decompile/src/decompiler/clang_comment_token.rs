//! Port of `ClangCommentToken`.
use std::collections::HashMap;
/// Struct porting `ClangCommentToken`.
#[derive(Debug, Clone)]
pub struct ClangCommentToken {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangCommentToken {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangCommentToken {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_comment_token_new() { let _ = ClangCommentToken::new(); }
}
