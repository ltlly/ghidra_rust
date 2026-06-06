//! Port of `RemoveEquateAction`.
use std::collections::HashMap;
/// Struct porting `RemoveEquateAction`.
#[derive(Debug, Clone)]
pub struct RemoveEquateAction {
    _phantom: std::marker::PhantomData<()>,
}
impl RemoveEquateAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RemoveEquateAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_remove_equate_action_new() { let _ = RemoveEquateAction::new(); }
}
