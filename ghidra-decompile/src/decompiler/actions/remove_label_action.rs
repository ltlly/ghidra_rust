//! Port of `RemoveLabelAction`.
use std::collections::HashMap;
/// Struct porting `RemoveLabelAction`.
#[derive(Debug, Clone)]
pub struct RemoveLabelAction {
    _phantom: std::marker::PhantomData<()>,
}
impl RemoveLabelAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RemoveLabelAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_remove_label_action_new() { let _ = RemoveLabelAction::new(); }
}
