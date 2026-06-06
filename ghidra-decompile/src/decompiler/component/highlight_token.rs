//! Port of `HighlightToken`.
use std::collections::HashMap;
/// Struct porting `HighlightToken`.
#[derive(Debug, Clone)]
pub struct HighlightToken {
    _phantom: std::marker::PhantomData<()>,
}
impl HighlightToken {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for HighlightToken {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_highlight_token_new() { let _ = HighlightToken::new(); }
}
