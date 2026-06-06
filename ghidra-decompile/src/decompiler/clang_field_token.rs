//! Port of `ClangFieldToken`.
use std::collections::HashMap;
/// Struct porting `ClangFieldToken`.
#[derive(Debug, Clone)]
pub struct ClangFieldToken {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangFieldToken {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangFieldToken {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_field_token_new() { let _ = ClangFieldToken::new(); }
}
