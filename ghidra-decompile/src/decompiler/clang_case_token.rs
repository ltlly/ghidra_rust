//! Port of `ClangCaseToken`.
use std::collections::HashMap;
/// Struct porting `ClangCaseToken`.
#[derive(Debug, Clone)]
pub struct ClangCaseToken {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangCaseToken {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangCaseToken {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_case_token_new() { let _ = ClangCaseToken::new(); }
}
