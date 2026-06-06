//! Port of `ClangTextField`.
use std::collections::HashMap;
/// Struct porting `ClangTextField`.
#[derive(Debug, Clone)]
pub struct ClangTextField {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangTextField {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangTextField {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_text_field_new() { let _ = ClangTextField::new(); }
}
