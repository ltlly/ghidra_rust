//! Port of `NoRegisteredEditorPropertyEditor`.
use std::collections::HashMap;
/// Struct porting `NoRegisteredEditorPropertyEditor`.
#[derive(Debug, Clone)]
pub struct NoRegisteredEditorPropertyEditor {
    _phantom: std::marker::PhantomData<()>,
}
impl NoRegisteredEditorPropertyEditor {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for NoRegisteredEditorPropertyEditor {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_no_registered_editor_property_editor_new() { let _ = NoRegisteredEditorPropertyEditor::new(); }
}
