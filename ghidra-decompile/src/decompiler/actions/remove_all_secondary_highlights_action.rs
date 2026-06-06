//! Port of `RemoveAllSecondaryHighlightsAction`.
use std::collections::HashMap;
/// Struct porting `RemoveAllSecondaryHighlightsAction`.
#[derive(Debug, Clone)]
pub struct RemoveAllSecondaryHighlightsAction {
    /// NAME
    pub name: String,
}
impl RemoveAllSecondaryHighlightsAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RemoveAllSecondaryHighlightsAction {
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
    fn test_remove_all_secondary_highlights_action_new() { let _ = RemoveAllSecondaryHighlightsAction::new(); }
}
