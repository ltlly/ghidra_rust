//! Port of `TokenHighlightColors`.
use std::collections::HashMap;
/// Struct porting `TokenHighlightColors`.
#[derive(Debug, Clone)]
pub struct TokenHighlightColors {
    _phantom: std::marker::PhantomData<()>,
}
impl TokenHighlightColors {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for TokenHighlightColors {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_token_highlight_colors_new() { let _ = TokenHighlightColors::new(); }
}
