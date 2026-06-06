//! Port of `RenameLabelAction`.
use std::collections::HashMap;
/// Struct porting `RenameLabelAction`.
#[derive(Debug, Clone)]
pub struct RenameLabelAction {
    _phantom: std::marker::PhantomData<()>,
}
impl RenameLabelAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RenameLabelAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rename_label_action_new() { let _ = RenameLabelAction::new(); }
}
