//! Port of `EditDataTypeAction`.
use std::collections::HashMap;
/// Struct porting `EditDataTypeAction`.
#[derive(Debug, Clone)]
pub struct EditDataTypeAction {
    _phantom: std::marker::PhantomData<()>,
}
impl EditDataTypeAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for EditDataTypeAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_edit_data_type_action_new() { let _ = EditDataTypeAction::new(); }
}
