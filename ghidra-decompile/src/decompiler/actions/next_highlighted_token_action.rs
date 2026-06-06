//! Port of `NextHighlightedTokenAction`.
use std::collections::HashMap;
/// Struct porting `NextHighlightedTokenAction`.
#[derive(Debug, Clone)]
pub struct NextHighlightedTokenAction {
    _phantom: std::marker::PhantomData<()>,
}
impl NextHighlightedTokenAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for NextHighlightedTokenAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_next_highlighted_token_action_new() { let _ = NextHighlightedTokenAction::new(); }
}
