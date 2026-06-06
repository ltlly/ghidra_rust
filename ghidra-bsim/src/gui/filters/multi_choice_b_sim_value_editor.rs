//! Port of `MultiChoiceBSimValueEditor`.
use std::collections::HashMap;
/// Struct porting `MultiChoiceBSimValueEditor`.
#[derive(Debug, Clone)]
pub struct MultiChoiceBSimValueEditor {
    _phantom: std::marker::PhantomData<()>,
}
impl MultiChoiceBSimValueEditor {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MultiChoiceBSimValueEditor {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_multi_choice_b_sim_value_editor_new() { let _ = MultiChoiceBSimValueEditor::new(); }
}
