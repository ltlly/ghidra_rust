//! Port of `ClangFieldElement`.
use std::collections::HashMap;
/// Struct porting `ClangFieldElement`.
#[derive(Debug, Clone)]
pub struct ClangFieldElement {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangFieldElement {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangFieldElement {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_field_element_new() { let _ = ClangFieldElement::new(); }
}
