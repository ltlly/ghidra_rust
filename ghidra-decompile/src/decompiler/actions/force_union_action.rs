//! Port of `ForceUnionAction`.
use std::collections::HashMap;
/// Struct porting `ForceUnionAction`.
#[derive(Debug, Clone)]
pub struct ForceUnionAction {
    _phantom: std::marker::PhantomData<()>,
}
impl ForceUnionAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ForceUnionAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_force_union_action_new() { let _ = ForceUnionAction::new(); }
}
