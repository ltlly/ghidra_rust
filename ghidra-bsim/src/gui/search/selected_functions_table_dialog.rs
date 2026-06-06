//! Port of `SelectedFunctionsTableDialog`.
use std::collections::HashMap;
/// Struct porting `SelectedFunctionsTableDialog`.
#[derive(Debug, Clone)]
pub struct SelectedFunctionsTableDialog {
    _phantom: std::marker::PhantomData<()>,
}
impl SelectedFunctionsTableDialog {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for SelectedFunctionsTableDialog {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_selected_functions_table_dialog_new() { let _ = SelectedFunctionsTableDialog::new(); }
}
