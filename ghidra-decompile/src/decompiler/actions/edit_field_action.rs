//! Port of `EditFieldAction`.
use std::collections::HashMap;
/// Struct porting `EditFieldAction`.
#[derive(Debug, Clone)]
pub struct EditFieldAction {
    _phantom: std::marker::PhantomData<()>,
}
impl EditFieldAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for EditFieldAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_edit_field_action_new() { let _ = EditFieldAction::new(); }
}
