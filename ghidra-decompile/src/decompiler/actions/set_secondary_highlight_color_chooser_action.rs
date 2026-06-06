//! Port of `SetSecondaryHighlightColorChooserAction`.
use std::collections::HashMap;
/// Struct porting `SetSecondaryHighlightColorChooserAction`.
#[derive(Debug, Clone)]
pub struct SetSecondaryHighlightColorChooserAction {
    /// NAME
    pub name: String,
}
impl SetSecondaryHighlightColorChooserAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for SetSecondaryHighlightColorChooserAction {
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
    fn test_set_secondary_highlight_color_chooser_action_new() { let _ = SetSecondaryHighlightColorChooserAction::new(); }
}
