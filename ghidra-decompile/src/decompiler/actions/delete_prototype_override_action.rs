//! Port of `DeletePrototypeOverrideAction`.
use std::collections::HashMap;
/// Struct porting `DeletePrototypeOverrideAction`.
#[derive(Debug, Clone)]
pub struct DeletePrototypeOverrideAction {
    _phantom: std::marker::PhantomData<()>,
}
impl DeletePrototypeOverrideAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DeletePrototypeOverrideAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_delete_prototype_override_action_new() { let _ = DeletePrototypeOverrideAction::new(); }
}
