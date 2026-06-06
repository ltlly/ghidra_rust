//! Port of `ClangTokenGroup`.
use std::collections::HashMap;
/// Struct porting `ClangTokenGroup`.
#[derive(Debug, Clone)]
pub struct ClangTokenGroup {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangTokenGroup {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangTokenGroup {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_token_group_new() { let _ = ClangTokenGroup::new(); }
}
