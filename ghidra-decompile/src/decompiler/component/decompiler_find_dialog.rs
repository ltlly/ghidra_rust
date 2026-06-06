//! Port of `DecompilerFindDialog`.
use std::collections::HashMap;
/// Struct porting `DecompilerFindDialog`.
#[derive(Debug, Clone)]
pub struct DecompilerFindDialog {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerFindDialog {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerFindDialog {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_find_dialog_new() { let _ = DecompilerFindDialog::new(); }
}
