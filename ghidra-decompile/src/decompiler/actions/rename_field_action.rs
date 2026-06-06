//! Port of `RenameFieldAction`.
use std::collections::HashMap;
/// Struct porting `RenameFieldAction`.
#[derive(Debug, Clone)]
pub struct RenameFieldAction {
    _phantom: std::marker::PhantomData<()>,
}
impl RenameFieldAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RenameFieldAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rename_field_action_new() { let _ = RenameFieldAction::new(); }
}
