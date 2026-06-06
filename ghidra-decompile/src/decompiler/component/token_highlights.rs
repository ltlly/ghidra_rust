//! Port of `TokenHighlights`.
use std::collections::HashMap;
/// Struct porting `TokenHighlights`.
#[derive(Debug, Clone)]
pub struct TokenHighlights {
    _phantom: std::marker::PhantomData<()>,
}
impl TokenHighlights {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for TokenHighlights {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_token_highlights_new() { let _ = TokenHighlights::new(); }
}
