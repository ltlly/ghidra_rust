//! Port of `NullClangHighlightController`.
use std::collections::HashMap;
/// Struct porting `NullClangHighlightController`.
#[derive(Debug, Clone)]
pub struct NullClangHighlightController {
    _phantom: std::marker::PhantomData<()>,
}
impl NullClangHighlightController {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for NullClangHighlightController {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_null_clang_highlight_controller_new() { let _ = NullClangHighlightController::new(); }
}
