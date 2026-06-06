//! Port of `SpecifyCPrototypeAction`.
use std::collections::HashMap;
/// Struct porting `SpecifyCPrototypeAction`.
#[derive(Debug, Clone)]
pub struct SpecifyCPrototypeAction {
    _phantom: std::marker::PhantomData<()>,
}
impl SpecifyCPrototypeAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for SpecifyCPrototypeAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_specify_c_prototype_action_new() { let _ = SpecifyCPrototypeAction::new(); }
}
