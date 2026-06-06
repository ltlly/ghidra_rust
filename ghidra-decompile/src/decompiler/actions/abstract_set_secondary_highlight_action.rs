//! Port of `AbstractSetSecondaryHighlightAction`.
use std::collections::HashMap;
/// Struct porting `AbstractSetSecondaryHighlightAction`.
#[derive(Debug, Clone)]
pub struct AbstractSetSecondaryHighlightAction {
    _phantom: std::marker::PhantomData<()>,
}
impl AbstractSetSecondaryHighlightAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for AbstractSetSecondaryHighlightAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_abstract_set_secondary_highlight_action_new() { let _ = AbstractSetSecondaryHighlightAction::new(); }
}
