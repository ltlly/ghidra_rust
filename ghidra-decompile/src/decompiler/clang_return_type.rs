//! Port of `ClangReturnType`.
use std::collections::HashMap;
/// Struct porting `ClangReturnType`.
#[derive(Debug, Clone)]
pub struct ClangReturnType {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangReturnType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangReturnType {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_return_type_new() { let _ = ClangReturnType::new(); }
}
