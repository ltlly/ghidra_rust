//! Port of `ClangFuncNameToken`.
use std::collections::HashMap;
/// Struct porting `ClangFuncNameToken`.
#[derive(Debug, Clone)]
pub struct ClangFuncNameToken {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangFuncNameToken {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangFuncNameToken {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_func_name_token_new() { let _ = ClangFuncNameToken::new(); }
}
