//! Port of `ClangHighlightController`.
use std::collections::HashMap;
/// Struct porting `ClangHighlightController`.
#[derive(Debug, Clone)]
pub struct ClangHighlightController {
    /// DEFAULT_HIGHLIGHT_COLOR
    pub default_highlight_color: String,
    /// defaultParenColor
    pub default_paren_color: String,
}
impl ClangHighlightController {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangHighlightController {
    fn default() -> Self {
        Self {
            default_highlight_color: String::new(),
            default_paren_color: String::new()
        }


}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_highlight_controller_new() { let _ = ClangHighlightController::new(); }
}
