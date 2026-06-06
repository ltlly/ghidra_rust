//! Port of `MultiChoiceSelectionDialog`.
use std::collections::HashMap;
/// Struct porting `MultiChoiceSelectionDialog`.
#[derive(Debug, Clone)]
pub struct MultiChoiceSelectionDialog {
    _phantom: std::marker::PhantomData<()>,
}
impl MultiChoiceSelectionDialog {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MultiChoiceSelectionDialog {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_multi_choice_selection_dialog_new() { let _ = MultiChoiceSelectionDialog::new(); }
}
