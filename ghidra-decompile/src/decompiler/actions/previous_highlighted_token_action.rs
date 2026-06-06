//! Port of `PreviousHighlightedTokenAction`.
use std::collections::HashMap;
/// Struct porting `PreviousHighlightedTokenAction`.
#[derive(Debug, Clone)]
pub struct PreviousHighlightedTokenAction {
    _phantom: std::marker::PhantomData<()>,
}
impl PreviousHighlightedTokenAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PreviousHighlightedTokenAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_previous_highlighted_token_action_new() { let _ = PreviousHighlightedTokenAction::new(); }
}
