//! Port of `ClangVariableToken`.
use std::collections::HashMap;
/// Struct porting `ClangVariableToken`.
#[derive(Debug, Clone)]
pub struct ClangVariableToken {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangVariableToken {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangVariableToken {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_variable_token_new() { let _ = ClangVariableToken::new(); }
}
