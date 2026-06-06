//! Port of `ClangLabelToken`.
use std::collections::HashMap;
/// Struct porting `ClangLabelToken`.
#[derive(Debug, Clone)]
pub struct ClangLabelToken {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangLabelToken {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangLabelToken {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_label_token_new() { let _ = ClangLabelToken::new(); }
}
