//! Port of `BooleanBSimValueEditor`.
use std::collections::HashMap;
/// Struct porting `BooleanBSimValueEditor`.
#[derive(Debug, Clone)]
pub struct BooleanBSimValueEditor {
    _phantom: std::marker::PhantomData<()>,
}
impl BooleanBSimValueEditor {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BooleanBSimValueEditor {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_boolean_b_sim_value_editor_new() { let _ = BooleanBSimValueEditor::new(); }
}
