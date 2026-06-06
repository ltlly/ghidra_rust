//! Port of `EditPrototypeOverrideAction`.
use std::collections::HashMap;
/// Struct porting `EditPrototypeOverrideAction`.
#[derive(Debug, Clone)]
pub struct EditPrototypeOverrideAction {
    _phantom: std::marker::PhantomData<()>,
}
impl EditPrototypeOverrideAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for EditPrototypeOverrideAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_edit_prototype_override_action_new() { let _ = EditPrototypeOverrideAction::new(); }
}
