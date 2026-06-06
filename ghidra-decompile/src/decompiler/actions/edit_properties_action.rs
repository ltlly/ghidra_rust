//! Port of `EditPropertiesAction`.
use std::collections::HashMap;
/// Struct porting `EditPropertiesAction`.
#[derive(Debug, Clone)]
pub struct EditPropertiesAction {
    _phantom: std::marker::PhantomData<()>,
}
impl EditPropertiesAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for EditPropertiesAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_edit_properties_action_new() { let _ = EditPropertiesAction::new(); }
}
