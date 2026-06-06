//! Port of `StringBSimValueEditor`.
use std::collections::HashMap;
/// Struct porting `StringBSimValueEditor`.
#[derive(Debug, Clone)]
pub struct StringBSimValueEditor {
    _phantom: std::marker::PhantomData<()>,
}
impl StringBSimValueEditor {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for StringBSimValueEditor {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_string_b_sim_value_editor_new() { let _ = StringBSimValueEditor::new(); }
}
