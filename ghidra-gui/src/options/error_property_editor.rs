//! Port of `ErrorPropertyEditor`.
use std::collections::HashMap;
/// Struct porting `ErrorPropertyEditor`.
#[derive(Debug, Clone)]
pub struct ErrorPropertyEditor {
    _phantom: std::marker::PhantomData<()>,
}
impl ErrorPropertyEditor {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ErrorPropertyEditor {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_error_property_editor_new() { let _ = ErrorPropertyEditor::new(); }
}
