//! Port of `RemoveSecondaryHighlightAction`.
use std::collections::HashMap;
/// Struct porting `RemoveSecondaryHighlightAction`.
#[derive(Debug, Clone)]
pub struct RemoveSecondaryHighlightAction {
    /// NAME
    pub name: String,
}
impl RemoveSecondaryHighlightAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RemoveSecondaryHighlightAction {
    fn default() -> Self {
        Self {
            name: String::new()
        }

}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_remove_secondary_highlight_action_new() { let _ = RemoveSecondaryHighlightAction::new(); }
}
