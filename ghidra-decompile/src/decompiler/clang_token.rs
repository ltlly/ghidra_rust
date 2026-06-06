//! Port of `ClangToken`.
use std::collections::HashMap;
/// Struct porting `ClangToken`.
#[derive(Debug, Clone)]
pub struct ClangToken {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangToken {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangToken {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_token_new() { let _ = ClangToken::new(); }
}
