//! Port of `ClangBitFieldToken`.
use std::collections::HashMap;
/// Struct porting `ClangBitFieldToken`.
#[derive(Debug, Clone)]
pub struct ClangBitFieldToken {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangBitFieldToken {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangBitFieldToken {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_bit_field_token_new() { let _ = ClangBitFieldToken::new(); }
}
