//! Port of `ClangFunction`.
use std::collections::HashMap;
/// Struct porting `ClangFunction`.
#[derive(Debug, Clone)]
pub struct ClangFunction {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangFunction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangFunction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_function_new() { let _ = ClangFunction::new(); }
}
