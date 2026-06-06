//! Port of `ClangLayoutController`.
use std::collections::HashMap;
/// Struct porting `ClangLayoutController`.
#[derive(Debug, Clone)]
pub struct ClangLayoutController {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangLayoutController {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangLayoutController {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_layout_controller_new() { let _ = ClangLayoutController::new(); }
}
