//! Port of `ClangTypeToken`.
use std::collections::HashMap;
/// Struct porting `ClangTypeToken`.
#[derive(Debug, Clone)]
pub struct ClangTypeToken {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangTypeToken {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangTypeToken {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_type_token_new() { let _ = ClangTypeToken::new(); }
}
