//! Port of `SetSecondaryHighlightAction`.
use std::collections::HashMap;
/// Struct porting `SetSecondaryHighlightAction`.
#[derive(Debug, Clone)]
pub struct SetSecondaryHighlightAction {
    /// NAME
    pub name: String,
}
impl SetSecondaryHighlightAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for SetSecondaryHighlightAction {
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
    fn test_set_secondary_highlight_action_new() { let _ = SetSecondaryHighlightAction::new(); }
}
