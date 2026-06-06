//! Port of `ClangOpToken`.
use std::collections::HashMap;
/// Struct porting `ClangOpToken`.
#[derive(Debug, Clone)]
pub struct ClangOpToken {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangOpToken {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangOpToken {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_op_token_new() { let _ = ClangOpToken::new(); }
}
