//! Port of `SetEquateAction`.
use std::collections::HashMap;
/// Struct porting `SetEquateAction`.
#[derive(Debug, Clone)]
pub struct SetEquateAction {
    _phantom: std::marker::PhantomData<()>,
}
impl SetEquateAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for SetEquateAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_set_equate_action_new() { let _ = SetEquateAction::new(); }
}
