//! Port of `OverridePrototypeAction`.
use std::collections::HashMap;
/// Struct porting `OverridePrototypeAction`.
#[derive(Debug, Clone)]
pub struct OverridePrototypeAction {
    _phantom: std::marker::PhantomData<()>,
}
impl OverridePrototypeAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for OverridePrototypeAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_override_prototype_action_new() { let _ = OverridePrototypeAction::new(); }
}
